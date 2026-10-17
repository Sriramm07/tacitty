//! Shared test harness: an isolated HOME/XDG env plus a helper to spawn
//! `tacitty` under a real pty via `rexpect`.

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

use rexpect::session::{spawn_command, PtySession};

pub struct Env {
    pub home: PathBuf,
    pub runtime: PathBuf,
    pub bin: PathBuf,
}

fn bin_path() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_tacitty"))
}

impl Env {
    /// A fresh, isolated HOME/XDG_RUNTIME_DIR under a unique temp dir, so
    /// tests never share a vault or a running agent with each other.
    pub fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap().keep();
        let home = dir.join("home");
        let runtime = dir.join("run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        Env {
            home,
            runtime,
            bin: bin_path(),
        }
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args);
        cmd.env("HOME", &self.home);
        cmd.env("XDG_RUNTIME_DIR", &self.runtime);
        cmd.env("TACITTY_TEST_WORK_FACTOR", "8");
        cmd.env_remove("TACITTY_ACTIVE");
        // Keep everything inside the test's own HOME: never the
        // developer's real config, vault or shell rc files.
        for var in [
            "ZDOTDIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "NO_TACITTY",
            "TACITTY_RELEASES_URL",
        ] {
            cmd.env_remove(var);
        }
        cmd
    }

    pub fn spawn(&self, args: &[&str], timeout_ms: u64) -> PtySession {
        spawn_command(self.command(args), Some(timeout_ms)).expect("spawn tacitty")
    }

    /// Spawn `tacitty shell` with a fixed size, fast bash, and a plain
    /// prompt so tests don't depend on the ambient PS1.
    pub fn spawn_shell(&self, timeout_ms: u64) -> PtySession {
        let mut cmd = self.command(&["shell"]);
        cmd.env("SHELL", "/bin/bash");
        cmd.env("PS1", "TESTPROMPT$ ");
        let mut p = spawn_command(cmd, Some(timeout_ms)).expect("spawn tacitty shell");
        if let Ok(f) = p.process().get_file_handle() {
            let ws = libc::winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let _ = tacitty::sys::set_winsize(f.as_raw_fd(), &ws);
        }
        p.send_line("PS1='TESTPROMPT$ '").ok();
        p.exp_string("TESTPROMPT$ ").expect("initial prompt");
        p
    }
}

/// Best-effort teardown: this test's agent process (if any is running
/// under its own private runtime dir) is killed. Every test should hold
/// onto its `Env` in a variable bound with `let _env = ...` (not `let _ =
/// ...`) for its whole body and let this `Drop` impl run at scope exit, so
/// dozens of test runs don't leave a pile of idle agent daemons behind —
/// on a heavily loaded/low-core machine that pile is enough to introduce
/// real scheduling-latency flakiness into otherwise-deterministic tests.
impl Drop for Env {
    fn drop(&mut self) {
        let sock = self.runtime.join("tacitty").join("agent-2.sock");
        if let Ok(mut c) = tacitty::agent::Client::connect(&sock) {
            let _ = c.lock();
        }
        // Client has no explicit "shut down the agent" RPC by design (see
        // spec §8.2 — its protocol is GET/LIST/LOCK/STATUS/UNLOCK only), so
        // ask the kernel which process is listening on this test's socket
        // (SO_PEERCRED, or LOCAL_PEERPID on macOS) and signal it directly.
        // /proc/<pid>/environ can't be
        // used for this: the agent marks itself non-dumpable, which makes
        // its environ unreadable even to the same user. This is test-only
        // cleanup, not something `tacitty` itself needs at runtime.
        if let Some(pid) = agent_pid(&sock) {
            let _ = tacitty::sys::kill(pid, libc::SIGKILL);
        }
        let _ = std::fs::remove_dir_all(self.home.parent().unwrap_or(&self.home));
    }
}

/// PID of the process serving the Unix socket at `sock`, if one is.
#[cfg(target_os = "linux")]
fn agent_pid(sock: &std::path::Path) -> Option<i32> {
    let stream = std::os::unix::net::UnixStream::connect(sock).ok()?;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred`/`len` describe a correctly sized buffer for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

/// PID of the process serving the Unix socket at `sock`, if one is.
#[cfg(target_os = "macos")]
fn agent_pid(sock: &std::path::Path) -> Option<i32> {
    let stream = std::os::unix::net::UnixStream::connect(sock).ok()?;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid`/`len` describe a correctly sized buffer for LOCAL_PEERPID.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut libc::pid_t as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid)
}

pub fn init_vault(env: &Env, passphrase: &str) {
    let mut p = env.spawn(&["init"], 10_000);
    p.exp_string("New master passphrase:").unwrap();
    p.send_line(passphrase).unwrap();
    p.exp_string("Confirm master passphrase:").unwrap();
    p.send_line(passphrase).unwrap();
    let rest = p.exp_eof().unwrap();
    let status = p.process().wait();
    assert!(
        matches!(status, Ok(rexpect::process::wait::WaitStatus::Exited(_, 0))),
        "`tacitty init` did not exit 0: status={status:?} output={rest:?}"
    );
}

pub fn add_alias(env: &Env, alias: &str, secret: &str, passphrase: &str) {
    let mut p = env.spawn(&["add", alias], 10_000);
    p.exp_string("Secret:").unwrap();
    p.send_line(secret).unwrap();
    p.exp_string("Confirm secret:").unwrap();
    p.send_line(secret).unwrap();
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(passphrase).unwrap();
    p.exp_eof().unwrap();
}

pub fn unlock_agent(env: &Env, passphrase: &str) {
    let mut p = env.spawn(&["unlock"], 10_000);
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(passphrase).unwrap();
    p.exp_eof().unwrap();
}
