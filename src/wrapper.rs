//! The `tacitty shell` PTY wrapper: spawns `$SHELL` (or a given command) on
//! a pty, proxies bytes in both directions, and drives the input state
//! machine to intercept `@alias` at secret prompts (spec §5, §6, §7).

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Command;
use std::time::{Duration, Instant};

use regex::Regex;
use secrecy::SecretString;

use crate::config::Config;
use crate::detect::{self, AltScreenTracker};
use crate::remote::{self, LineTracker};
use crate::resolver::{ResolveOutcome, Resolver};
use crate::secret::SecretBuf;
use crate::statemachine::{self, Action, StateMachine};
use crate::sys;

/// How the current input line's secret-prompt status was determined.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineMode {
    None,
    Local,
    RemoteConfirm,
    RemoteAuto,
}

impl LineMode {
    fn is_secret(self) -> bool {
        self != LineMode::None
    }

    fn is_remote(self) -> bool {
        matches!(self, LineMode::RemoteAuto | LineMode::RemoteConfirm)
    }
}

/// What the terminal looked like when an `@alias` capture started. Checked
/// again right before the secret is sent: if the prompt has gone away in
/// the meantime (Ctrl-C, a timeout, the program exiting), the secret must
/// not be sent to whatever is reading the terminal now.
#[derive(Clone, Copy)]
struct CaptureCtx {
    mode: LineMode,
    pgid: Option<i32>,
    output_seq: u64,
}

/// RAII guard: puts `fd` into raw mode and restores the original termios
/// (and the xterm title, if we changed it) when dropped — including on
/// early return, panic unwind, or the signal-triggered break out of the
/// main loop.
struct TermGuard {
    fd: RawFd,
    saved: libc::termios,
}

impl TermGuard {
    fn new(fd: RawFd) -> io::Result<Self> {
        let saved = sys::tcgetattr(fd)?;
        let mut raw = saved;
        sys::make_raw(&mut raw);
        sys::tcsetattr(fd, libc::TCSANOW, &raw)?;
        Ok(TermGuard { fd, saved })
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = sys::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
    }
}

fn write_stdout(bytes: &[u8]) {
    let _ = sys::write_all_fd(1, bytes);
}

fn ring_local_bell() {
    write_stdout(b"\x07");
}

fn set_title(text: &str) {
    write_stdout(b"\x1b[22;0t"); // push title
    write_stdout(format!("\x1b]0;{text}\x07").as_bytes());
}

fn restore_title() {
    write_stdout(b"\x1b[23;0t"); // pop title
}

/// Read one line (up to and including Enter) from local stdin with no echo
/// (the caller's terminal is already raw). Used only for the master
/// passphrase prompt and the remote-fallback confirmation key. Blocking.
fn read_line_noecho(max_len: usize) -> io::Result<SecretBuf> {
    let mut buf = SecretBuf::new();
    let mut byte = [0u8; 1];
    loop {
        let n = sys::read_fd(0, &mut byte)?;
        if n == 0 {
            break;
        }
        match byte[0] {
            b'\r' | b'\n' => break,
            0x7f | 0x08 => {
                buf.pop();
            }
            0x03 | 0x04 => {
                buf.clear();
                break;
            }
            b if buf.len() < max_len => buf.push(b),
            _ => {}
        }
    }
    Ok(buf)
}

fn prompt_passphrase_and_unlock(resolver: &mut Resolver) -> Result<bool, String> {
    write_stdout(b"\r\ntacitty: enter master passphrase to unlock vault: ");
    let pass_bytes = read_line_noecho(4096).map_err(|e| e.to_string())?;
    write_stdout(b"\x1b[2K\r"); // best-effort erase of the local prompt line
    if pass_bytes.is_empty() {
        return Ok(false);
    }
    let pass = SecretString::from(String::from_utf8_lossy(pass_bytes.as_slice()).into_owned());
    resolver.unlock(&pass).map(|_| true)
}

fn confirm_locally(alias: &str) -> bool {
    write_stdout(format!("\r\ntacitty: send secret for @{alias}? [y/N] ").as_bytes());
    let ans = read_line_noecho(8).unwrap_or_else(|_| SecretBuf::new());
    write_stdout(b"\x1b[2K\r");
    matches!(ans.as_slice().first(), Some(b'y') | Some(b'Y'))
}

/// Decide, for the first input byte of a new line, whether this line should
/// be treated as a secret prompt, and by which detection path.
///
/// The local check has an inherent race: a program (e.g. bash's `read -s`)
/// may print its prompt text fractionally before or after it actually
/// flips the pty's termios to no-echo/canonical, and our very first input
/// byte can land in that gap. A false *positive* here is harmless (nothing
/// happens unless the user also types the trigger character), but a false
/// *negative* would mean a real secret gets echoed and forwarded literally
/// — so immediately after fresh output (i.e. right after a prompt could
/// plausibly have just been printed) we retry briefly before committing to
/// an initial "not secret" reading, biasing the race toward the safe
/// outcome. Once a line is well underway (no output in the last moment)
/// there is nothing left to race against, so ordinary typing pays none of
/// this cost.
fn classify_line(
    master_fd: RawFd,
    alt_active: bool,
    suppressed: bool,
    just_settled: bool,
    cfg: &Config,
    prompt_re: &Regex,
    line_tracker: &LineTracker,
) -> LineMode {
    if alt_active {
        return LineMode::None;
    }
    if !suppressed {
        if detect::read_secret_mode(master_fd) {
            return LineMode::Local;
        }
        if just_settled {
            const RETRIES: u32 = 8;
            const DELAY: Duration = Duration::from_millis(1);
            for _ in 0..RETRIES {
                std::thread::sleep(DELAY);
                if detect::read_secret_mode(master_fd) {
                    return LineMode::Local;
                }
            }
        }
    }
    if matches!(cfg.remote.mode, crate::config::RemoteMode::Off) {
        return LineMode::None;
    }
    // A real interactive ssh/mosh/docker -t/kubectl -t client turns local
    // echo off. If it's still on (`ssh host 'sudo -S ...'`, `ssh -T`,
    // `kubectl exec -i` without -t), the local terminal itself would print
    // the secret, so never treat the line as a password prompt.
    match sys::tcgetattr(master_fd) {
        Ok(t) if t.c_lflag & libc::ECHO == 0 => {}
        _ => return LineMode::None,
    }
    let Ok(pgid) = sys::tcgetpgrp(master_fd) else {
        return LineMode::None;
    };
    let Some(comm) = remote::proc_comm(pgid) else {
        return LineMode::None;
    };
    if !remote::is_allowlisted(&comm, &cfg.remote.processes) {
        return LineMode::None;
    }
    if !remote::looks_like_prompt(prompt_re, &line_tracker.current_line()) {
        return LineMode::None;
    }
    match cfg.remote.mode {
        crate::config::RemoteMode::Auto => LineMode::RemoteAuto,
        _ => LineMode::RemoteConfirm,
    }
}

/// Is the line `ctx` was captured on still the same password prompt? Every
/// check here must pass, or the secret is not sent:
/// - no output from the child since the capture started (and none waiting
///   to be read): a prompt that times out or exits prints something;
/// - the same foreground process group is reading the terminal;
/// - the terminal is still in password mode, of the same kind.
fn capture_still_valid(
    master_fd: RawFd,
    ctx: &CaptureCtx,
    output_seq: u64,
    cfg: &Config,
    prompt_re: &Regex,
    alt: &AltScreenTracker,
    line_tracker: &LineTracker,
) -> bool {
    if output_seq != ctx.output_seq {
        return false;
    }
    let mut pfd = [libc::pollfd {
        fd: master_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    if !matches!(sys::poll(&mut pfd, 0), Ok(0)) {
        return false;
    }
    if sys::tcgetpgrp(master_fd).ok() != ctx.pgid {
        return false;
    }
    let now = classify_line(
        master_fd,
        alt.is_active(),
        false,
        false,
        cfg,
        prompt_re,
        line_tracker,
    );
    match ctx.mode {
        LineMode::Local => now == LineMode::Local,
        LineMode::RemoteAuto | LineMode::RemoteConfirm => now.is_remote(),
        LineMode::None => false,
    }
}

fn report_not_sent() {
    ring_local_bell();
    write_stdout(b"\r\ntacitty: the password prompt changed, so nothing was sent\r\n");
}

pub struct RunOptions {
    pub command: Option<Vec<String>>,
}

/// Run `tacitty shell`: spawn the shell (or `options.command`) on a pty and
/// proxy until it exits, intercepting alias triggers along the way. Returns
/// the child's exit code (or 128+signal, matching normal shell convention).
pub fn run(cfg: Config, options: RunOptions) -> anyhow::Result<i32> {
    if std::env::var_os("TACITTY_ACTIVE").is_some() {
        eprintln!("tacitty: already active in this shell, not nesting");
        let shell = shell_command(&options);
        let err = exec_replace(shell);
        anyhow::bail!("exec failed: {err}");
    }

    if !sys::isatty(0) {
        anyhow::bail!("tacitty shell must be run from an interactive terminal");
    }

    let local_ws = sys::get_winsize(0).ok();
    let pty = sys::open_pty(None, local_ws.as_ref())?;
    let master_fd = pty.master.as_raw_fd();

    let (sig_r, sig_w) = sys::pipe_nonblock()?;
    sys::install_signal_pipe(
        &[
            libc::SIGWINCH,
            libc::SIGCHLD,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGHUP,
        ],
        sig_w.as_raw_fd(),
    )?;

    let term_guard = TermGuard::new(0)?;
    sys::harden_process();

    let mut cmd = build_command(&options);
    cmd.env("TACITTY_ACTIVE", "1");
    let mut child = sys::spawn_on_pty(&mut cmd, pty.slave)?;
    let child_pid = child.id() as i32;

    let mut sm = StateMachine::new(cfg.trigger_byte());
    let mut alt = AltScreenTracker::new();
    let mut line_tracker = LineTracker::new();
    let mut resolver = Resolver::new(cfg.clone())?;
    let mut cached_mode: Option<LineMode> = None;
    let mut suppressed = false;
    let mut title_shown = false;
    let mut last_output_at = Instant::now() - Duration::from_secs(1);
    let mut output_seq: u64 = 0;
    let mut capture: Option<CaptureCtx> = None;
    // Compiled once per session (it's validated when the config loads).
    let prompt_re = cfg.prompt_regex();

    let exit_code: i32;

    'outer: loop {
        let mut fds = [
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sig_r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if sys::poll(&mut fds, -1)? == 0 {
            continue;
        }

        // --- signals -------------------------------------------------
        if fds[2].revents & libc::POLLIN != 0 {
            let mut sigbuf = [0u8; 64];
            let mut winch = false;
            let mut chld = false;
            let mut term = false;
            let mut term_sig = 0i32;
            loop {
                match sys::read_once(sig_r.as_raw_fd(), &mut sigbuf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for &s in &sigbuf[..n] {
                            match s as i32 {
                                libc::SIGWINCH => winch = true,
                                libc::SIGCHLD => chld = true,
                                s @ (libc::SIGTERM | libc::SIGINT | libc::SIGHUP) => {
                                    term = true;
                                    term_sig = s;
                                }
                                _ => {}
                            }
                        }
                        if n < sigbuf.len() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            if winch {
                if let Ok(ws) = sys::get_winsize(0) {
                    let _ = sys::set_winsize(master_fd, &ws);
                    let _ = sys::kill(child_pid, libc::SIGWINCH);
                }
            }
            if chld {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        exit_code = exit_code_of(status);
                        break 'outer;
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            }
            if term {
                let _ = sys::kill(child_pid, libc::SIGHUP);
                exit_code = 128 + term_sig;
                break 'outer;
            }
        }

        // --- child output ---------------------------------------------
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut buf = [0u8; 4096];
            match sys::read_once(master_fd, &mut buf) {
                Ok(0) => {
                    exit_code = wait_for_exit(&mut child);
                    break 'outer;
                }
                Ok(n) => {
                    write_stdout(&buf[..n]);
                    alt.feed(&buf[..n]);
                    line_tracker.feed(&buf[..n]);
                    suppressed = false;
                    last_output_at = Instant::now();
                    output_seq = output_seq.wrapping_add(1);
                    // New output can mean a new prompt (or no prompt any
                    // more): decide afresh on the next keystroke. A capture
                    // in progress keeps its decision, and is re-checked
                    // (and refused, since output arrived) before sending.
                    if !sm.is_capturing() {
                        cached_mode = None;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                    exit_code = wait_for_exit(&mut child);
                    break 'outer;
                }
                Err(_) => {
                    exit_code = wait_for_exit(&mut child);
                    break 'outer;
                }
            }
        }

        // --- local input -------------------------------------------------
        if fds[0].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 256];
            match sys::read_once(0, &mut buf) {
                Ok(0) => { /* local stdin EOF; keep proxying child output */ }
                Ok(n) => {
                    for &b in &buf[..n] {
                        handle_input_byte(
                            b,
                            master_fd,
                            &cfg,
                            &prompt_re,
                            &mut sm,
                            &mut resolver,
                            &alt,
                            &line_tracker,
                            &mut cached_mode,
                            &mut suppressed,
                            &mut title_shown,
                            last_output_at,
                            output_seq,
                            &mut capture,
                        );
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
    }

    drop(term_guard);
    if title_shown {
        restore_title();
    }
    Ok(exit_code)
}

#[allow(clippy::too_many_arguments)]
fn handle_input_byte(
    b: u8,
    master_fd: RawFd,
    cfg: &Config,
    prompt_re: &Regex,
    sm: &mut StateMachine,
    resolver: &mut Resolver,
    alt: &AltScreenTracker,
    line_tracker: &LineTracker,
    cached_mode: &mut Option<LineMode>,
    suppressed: &mut bool,
    title_shown: &mut bool,
    last_output_at: Instant,
    output_seq: u64,
    capture: &mut Option<CaptureCtx>,
) {
    // Whether this line is a password prompt only matters when the trigger
    // is typed at the very start of a line (the only place a capture can
    // begin), so the check runs only then, not on every keystroke.
    let mode = if b == cfg.trigger_byte() && sm.at_line_start() {
        *cached_mode.get_or_insert_with(|| {
            let just_settled = last_output_at.elapsed() < Duration::from_millis(150);
            classify_line(
                master_fd,
                alt.is_active(),
                *suppressed,
                just_settled,
                cfg,
                prompt_re,
                line_tracker,
            )
        })
    } else {
        LineMode::None
    };
    let secret_mode = mode.is_secret();

    let was_capturing = sm.is_capturing();
    let action = sm.process(b, secret_mode);
    if !was_capturing && sm.is_capturing() {
        *capture = Some(CaptureCtx {
            mode,
            pgid: sys::tcgetpgrp(master_fd).ok(),
            output_seq,
        });
    }

    if cfg.title_indicator {
        if !was_capturing && sm.is_capturing() {
            set_title("tacitty: secret prompt");
            *title_shown = true;
        } else if was_capturing && !sm.is_capturing() && *title_shown {
            restore_title();
            *title_shown = false;
        }
    }

    match action {
        Action::Consumed => {}
        Action::Forward(byte) => {
            let _ = sys::write_all_fd(master_fd, &[byte]);
            // Enter ends the line. Ctrl-C / Ctrl-D / Ctrl-Z usually end the
            // program reading it (or the prompt), so the next keystroke
            // must be classified afresh, not trusted from before.
            if matches!(byte, b'\r' | b'\n' | 0x03 | 0x04 | 0x1a) {
                // A password typed by hand: the terminal can stay in
                // password mode for a moment after Enter, so don't treat
                // the next line as a prompt until the program responds.
                if detect::read_secret_mode(master_fd) {
                    *suppressed = true;
                }
                *cached_mode = None;
            }
        }
        Action::ForwardBytes(buf) => {
            let _ = sys::write_all_fd(master_fd, buf.as_slice());
        }
        Action::TooLong => {
            ring_local_bell();
            *cached_mode = None;
        }
        Action::ResolveAlias { alias, enter_byte } => {
            // A capture only ever starts on a password-prompt line.
            *suppressed = true;
            *cached_mode = None;
            let Some(ctx) = capture.take() else {
                ring_local_bell();
                return;
            };
            let still_valid = || {
                capture_still_valid(
                    master_fd,
                    &ctx,
                    output_seq,
                    cfg,
                    prompt_re,
                    alt,
                    line_tracker,
                )
            };

            if ctx.mode == LineMode::RemoteConfirm && !confirm_locally(&alias) {
                ring_local_bell();
                return;
            }

            deliver(master_fd, cfg, resolver, &alias, enter_byte, &still_valid);
        }
    }
    if !sm.is_capturing() {
        *capture = None;
    }
}

/// Look up `alias` and send it, but only if `still_valid()` holds at the
/// moment of sending (checked after any unlock or confirmation, which can
/// take a while).
fn deliver(
    master_fd: RawFd,
    cfg: &Config,
    resolver: &mut Resolver,
    alias: &str,
    enter_byte: u8,
    still_valid: &dyn Fn() -> bool,
) {
    match resolver.resolve(alias) {
        ResolveOutcome::Found(secret) => {
            if !still_valid() {
                report_not_sent();
                return;
            }
            let line = statemachine::resolved_line(secret.as_slice());
            let _ = sys::write_all_fd(master_fd, line.as_slice());
        }
        ResolveOutcome::Locked => match prompt_passphrase_and_unlock(resolver) {
            Ok(true) => deliver(master_fd, cfg, resolver, alias, enter_byte, still_valid),
            Ok(false) => ring_local_bell(),
            Err(_) => ring_local_bell(),
        },
        ResolveOutcome::NotFound => match cfg.on_miss {
            crate::config::OnMiss::Bell => ring_local_bell(),
            crate::config::OnMiss::Literal => {
                if !still_valid() {
                    report_not_sent();
                    return;
                }
                let line = statemachine::literal_line(cfg.trigger_byte(), alias, enter_byte);
                let _ = sys::write_all_fd(master_fd, line.as_slice());
            }
        },
        ResolveOutcome::Error(_) => ring_local_bell(),
    }
}

fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

fn wait_for_exit(child: &mut std::process::Child) -> i32 {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return exit_code_of(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return 0,
        }
    }
}

fn build_command(options: &RunOptions) -> Command {
    shell_command(options)
}

fn shell_command(options: &RunOptions) -> Command {
    if let Some(argv) = &options.command {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        Command::new(shell)
    }
}

fn exec_replace(mut cmd: Command) -> io::Error {
    use std::os::unix::process::CommandExt;
    // This replaces tacitty with the user's shell, which should get its
    // normal core-dump limit back.
    sys::restore_core_limit();
    cmd.exec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RemoteMode;

    #[test]
    fn line_mode_is_secret() {
        assert!(!LineMode::None.is_secret());
        assert!(LineMode::Local.is_secret());
        assert!(LineMode::RemoteAuto.is_secret());
        assert!(LineMode::RemoteConfirm.is_secret());
    }

    #[test]
    fn classify_line_alt_screen_always_none() {
        let cfg = Config::default();
        let lt = LineTracker::new();
        // master_fd -1 would error on tcgetattr, which is fine: alt_active
        // short-circuits before it's used.
        let mode = classify_line(-1, true, false, false, &cfg, &cfg.prompt_regex(), &lt);
        assert!(matches!(mode, LineMode::None));
    }

    #[test]
    fn classify_line_remote_off_short_circuits() {
        let mut cfg = Config::default();
        cfg.remote.mode = RemoteMode::Off;
        let lt = LineTracker::new();
        let mode = classify_line(-1, false, false, false, &cfg, &cfg.prompt_regex(), &lt);
        assert!(matches!(mode, LineMode::None));
    }
}
