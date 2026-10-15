//! Thin, safe wrappers over the libc calls tacitty needs.
//!
//! This is the ONLY module in the crate allowed to contain `unsafe`. Every
//! block carries a SAFETY comment. Everything else in the crate is built on
//! the safe API exported here.
#![allow(unsafe_code)]

use std::ffi::c_int;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

fn cvt(r: c_int) -> io::Result<c_int> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

// ---------------------------------------------------------------------------
// Identity / process hardening
// ---------------------------------------------------------------------------

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn getpid() -> i32 {
    // SAFETY: getpid has no preconditions and cannot fail.
    unsafe { libc::getpid() }
}

/// Result of [`harden_process`].
#[derive(Debug, Clone, Copy)]
pub struct HardenReport {
    pub dumpable_off: bool,
    pub core_limit_zero: bool,
}

/// The process's core-dump limit from before [`harden_process`] lowered
/// it, so children (the user's shell) can be given it back.
static ORIGINAL_CORE_LIMIT: std::sync::OnceLock<libc::rlimit> = std::sync::OnceLock::new();

/// Disable core dumps and ptrace-attachability (`PR_SET_DUMPABLE=0`, soft
/// `RLIMIT_CORE=0`). Best effort; the report says what succeeded. Only the
/// soft limit is lowered, so [`spawn_on_pty`] can restore the original
/// limit for the user's shell instead of disabling core dumps for every
/// program they run. Safe to call more than once.
pub fn harden_process() -> HardenReport {
    // SAFETY: prctl with PR_SET_DUMPABLE takes plain integer arguments.
    let dumpable_off = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `cur` is a valid rlimit for getrlimit to fill in.
    let core_limit_zero = if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut cur) } == 0 {
        let original = *ORIGINAL_CORE_LIMIT.get_or_init(|| cur);
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `lim` is a valid, initialised rlimit that outlives the call.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 }
    } else {
        false
    };
    HardenReport {
        dumpable_off,
        core_limit_zero,
    }
}

/// Best-effort `mlock` of a memory range. Returns whether it succeeded
/// (it fails harmlessly when `RLIMIT_MEMLOCK` is exhausted).
pub fn mlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: mlock only reads the address range for bookkeeping; it never
    // dereferences it, and an invalid range simply yields an error.
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Current soft `RLIMIT_MEMLOCK` in bytes (`None` = unlimited/unknown).
pub fn memlock_limit() -> Option<u64> {
    let mut lim = MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit writes a full rlimit into the provided pointer.
    let r = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, lim.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    // SAFETY: initialised by the successful call above.
    let lim = unsafe { lim.assume_init() };
    if lim.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(lim.rlim_cur)
    }
}

pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask cannot fail.
    unsafe { libc::umask(mask as libc::mode_t) as u32 }
}

/// Fill `buf` from the kernel CSPRNG.
///
/// Uses the raw syscall rather than libc's `getrandom()` wrapper: in the
/// static musl release builds that wrapper resolved to a null pointer and
/// crashed, and older glibc versions don't have it at all.
pub fn getrandom(buf: &mut [u8]) -> io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        // SAFETY: the pointer/length pair describes the unwritten tail of `buf`.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
                0 as libc::c_uint,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
}

pub fn kill(pid: i32, sig: c_int) -> io::Result<()> {
    // SAFETY: kill takes plain integers.
    cvt(unsafe { libc::kill(pid, sig) }).map(|_| ())
}

/// Non-blocking `flock(LOCK_EX)`. Returns `Ok(false)` if someone else holds it.
pub fn try_flock_exclusive(fd: RawFd) -> io::Result<bool> {
    // SAFETY: flock takes a plain fd and flag.
    let r = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        Ok(true)
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(false)
        } else {
            Err(e)
        }
    }
}

/// UID of the peer of a connected Unix socket (`SO_PEERCRED`).
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred`/`len` describe a correctly sized buffer for SO_PEERCRED.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    cvt(r)?;
    // SAFETY: initialised by the successful getsockopt above.
    Ok(unsafe { cred.assume_init() }.uid)
}

// ---------------------------------------------------------------------------
// File descriptor I/O
// ---------------------------------------------------------------------------

pub fn isatty(fd: RawFd) -> bool {
    // SAFETY: isatty takes a plain fd.
    unsafe { libc::isatty(fd) == 1 }
}

/// Single `read(2)` (no EINTR retry, so signals can interrupt the caller).
pub fn read_once(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf is a valid writable slice.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// `read(2)` that retries on EINTR.
pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match read_once(fd, buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Write the whole buffer, retrying on EINTR and waiting out EAGAIN.
pub fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: buf is a valid readable slice.
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let mut p = [libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    }];
                    let _ = poll(&mut p, 100);
                    continue;
                }
                _ => return Err(e),
            }
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// `poll(2)`; EINTR is reported as "0 fds ready".
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    // SAFETY: fds is a valid mutable slice of pollfd.
    let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(r as usize)
}

pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_GETFD/F_SETFD take plain integers.
    unsafe {
        let flags = cvt(libc::fcntl(fd, libc::F_GETFD))?;
        cvt(libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
    }
    Ok(())
}

/// Create a close-on-exec, non-blocking pipe: `(read_end, write_end)`.
pub fn pipe_nonblock() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for the two descriptors pipe2 writes.
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
    // SAFETY: pipe2 just returned two fresh descriptors that we now own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

// ---------------------------------------------------------------------------
// termios / pty
// ---------------------------------------------------------------------------

pub fn tcgetattr(fd: RawFd) -> io::Result<libc::termios> {
    let mut t = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr fully initialises the struct on success.
    cvt(unsafe { libc::tcgetattr(fd, t.as_mut_ptr()) })?;
    // SAFETY: initialised by the successful call above.
    Ok(unsafe { t.assume_init() })
}

pub fn tcsetattr(fd: RawFd, action: c_int, t: &libc::termios) -> io::Result<()> {
    // SAFETY: `t` is a valid termios reference.
    cvt(unsafe { libc::tcsetattr(fd, action, t) }).map(|_| ())
}

pub fn make_raw(t: &mut libc::termios) {
    // SAFETY: cfmakeraw only mutates the struct it is given.
    unsafe { libc::cfmakeraw(t) }
}

pub fn get_winsize(fd: RawFd) -> io::Result<libc::winsize> {
    let mut ws = MaybeUninit::<libc::winsize>::uninit();
    // SAFETY: TIOCGWINSZ writes a winsize into the pointer.
    cvt(unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, ws.as_mut_ptr()) })?;
    // SAFETY: initialised by the successful ioctl above.
    Ok(unsafe { ws.assume_init() })
}

pub fn set_winsize(fd: RawFd, ws: &libc::winsize) -> io::Result<()> {
    // SAFETY: TIOCSWINSZ reads a winsize from the pointer.
    cvt(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, ws as *const libc::winsize) }).map(|_| ())
}

/// Foreground process group of the terminal behind `fd`
/// (for a pty master: the group on the slave side).
pub fn tcgetpgrp(fd: RawFd) -> io::Result<i32> {
    // SAFETY: tcgetpgrp takes a plain fd.
    cvt(unsafe { libc::tcgetpgrp(fd) })
}

pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Open a pty pair (both ends close-on-exec), optionally seeding the slave's
/// termios and window size.
pub fn open_pty(termios: Option<&libc::termios>, ws: Option<&libc::winsize>) -> io::Result<Pty> {
    let (mut m, mut s) = (-1 as c_int, -1 as c_int);
    let tp = termios.map_or(std::ptr::null(), |t| t as *const libc::termios);
    let wp = ws.map_or(std::ptr::null(), |w| w as *const libc::winsize);
    // SAFETY: m/s are valid out-pointers; tp/wp are null or point to valid
    // structs that outlive the call (openpty only reads them).
    let r = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            tp as *mut libc::termios,
            wp as *mut libc::winsize,
        )
    };
    cvt(r)?;
    // SAFETY: openpty returned two fresh descriptors that we now own.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    set_cloexec(master.as_raw_fd())?;
    set_cloexec(slave.as_raw_fd())?;
    Ok(Pty { master, slave })
}

/// Spawn `cmd` with the pty slave as its stdin/stdout/stderr and controlling
/// terminal, in a new session.
pub fn spawn_on_pty(cmd: &mut Command, slave: OwnedFd) -> io::Result<Child> {
    cmd.stdin(Stdio::from(slave.try_clone()?));
    cmd.stdout(Stdio::from(slave.try_clone()?));
    cmd.stderr(Stdio::from(slave));
    let restore_core = ORIGINAL_CORE_LIMIT.get().copied();
    // SAFETY: the closure runs between fork and exec and only calls
    // async-signal-safe functions (setsid, ioctl, setrlimit).
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            // Give the user's shell back the core-dump limit it would have
            // had without tacitty (best effort).
            if let Some(lim) = restore_core {
                libc::setrlimit(libc::RLIMIT_CORE, &lim);
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Spawn a fully detached background process (new session, null stdio).
pub fn spawn_detached(cmd: &mut Command) -> io::Result<Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe setsid() runs between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static SIGNAL_PIPE_W: AtomicI32 = AtomicI32::new(-1);

/// Set by [`flag_handler`] when a termination signal arrives.
pub static SIGNAL_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn pipe_handler(sig: c_int) {
    // SAFETY (whole fn): async-signal-safe: only touches errno, an atomic and
    // write(2) with a one-byte stack buffer.
    unsafe {
        let errno = libc::__errno_location();
        let saved = *errno;
        let fd = SIGNAL_PIPE_W.load(Ordering::Relaxed);
        if fd >= 0 {
            let b = sig as u8;
            libc::write(fd, &b as *const u8 as *const libc::c_void, 1);
        }
        *errno = saved;
    }
}

extern "C" fn flag_handler(_sig: c_int) {
    SIGNAL_FLAG.store(true, Ordering::SeqCst);
}

fn install(
    sig: c_int,
    handler: extern "C" fn(c_int),
    restart: bool,
) -> io::Result<libc::sigaction> {
    // SAFETY: we build a fully zeroed sigaction, then fill in the handler,
    // an empty mask and flags before passing it to sigaction.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        let mut old: libc::sigaction = std::mem::zeroed();
        cvt(libc::sigaction(sig, &sa, &mut old))?;
        Ok(old)
    }
}

/// Route the given signals into a self-pipe (one byte = the signal number).
pub fn install_signal_pipe(sigs: &[c_int], write_fd: RawFd) -> io::Result<()> {
    SIGNAL_PIPE_W.store(write_fd, Ordering::SeqCst);
    for &s in sigs {
        install(s, pipe_handler, true)?;
    }
    Ok(())
}

/// Install a handler that sets [`SIGNAL_FLAG`] permanently (agent shutdown).
pub fn install_flag_handler(sigs: &[c_int]) -> io::Result<()> {
    for &s in sigs {
        install(s, flag_handler, false)?;
    }
    Ok(())
}

pub fn ignore_sigpipe() {
    // SAFETY: SIG_IGN is a valid disposition for SIGPIPE.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Restore the default SIGPIPE action (quietly terminate, no core dump),
/// so `tacitty ls | head -1` simply stops when `head` exits instead of
/// failing on a broken pipe.
pub fn default_sigpipe() {
    // SAFETY: SIG_DFL is a valid disposition for SIGPIPE.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// While alive, INT/TERM/HUP set [`SIGNAL_FLAG`] (and interrupt blocking
/// reads with EINTR) instead of killing the process, so callers can restore
/// terminal state. Previous dispositions are restored on drop.
pub struct SignalGuard {
    old: Vec<(c_int, libc::sigaction)>,
}

impl SignalGuard {
    pub fn new() -> io::Result<Self> {
        SIGNAL_FLAG.store(false, Ordering::SeqCst);
        let mut old = Vec::new();
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            old.push((s, install(s, flag_handler, false)?));
        }
        Ok(SignalGuard { old })
    }

    pub fn triggered(&self) -> bool {
        SIGNAL_FLAG.load(Ordering::SeqCst)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (s, sa) in &self.old {
            // SAFETY: restoring a sigaction previously returned by the kernel.
            unsafe {
                libc::sigaction(*s, sa, std::ptr::null_mut());
            }
        }
    }
}
