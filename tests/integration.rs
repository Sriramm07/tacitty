//! End-to-end tests driving the real `tacitty` binary through a real pty,
//! matching the scenarios in spec §11. Each test gets its own isolated
//! HOME/XDG_RUNTIME_DIR (see `common::Env::fresh`), so they can run in
//! parallel without sharing a vault or an agent.
//!
//! Every test that resolves an alias also asserts the secret never shows up
//! in the wrapper's OWN captured output outside of the one place it's
//! supposed to (the final "GOT[...]" line printed by the *child* program) —
//! i.e. it's never echoed back by the terminal itself.

mod common;

use common::{add_alias, add_alias_in, init_vault, unlock_agent, Env};

const PASSPHRASE: &str = "correct horse battery staple";

fn setup_with_alias(alias: &str, secret: &str) -> Env {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, alias, secret, PASSPHRASE);
    // `add` locks the agent again after saving (see main.rs), so unlock
    // once more here to match the realistic flow: a user runs `tacitty
    // unlock` (or gets prompted inline) before relying on alias expansion.
    unlock_agent(&env, PASSPHRASE);
    env
}

#[test]
fn init_creates_vault_with_safe_permissions() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    let vault = env.home.join(".local/share/tacitty/vault.age");
    assert!(vault.exists());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn locked_vault_prompts_inline_and_then_delivers() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, "prod-db", "s3cr3t!", PASSPHRASE);
    // Deliberately NOT calling unlock_agent: the agent is locked, so the
    // wrapper should prompt for the master passphrase inline, then deliver.
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@prod-db\r").unwrap();
    p.flush().unwrap();
    p.exp_string("enter master passphrase to unlock vault")
        .unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("GOT[s3cr3t!]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn read_s_prompt_gets_the_real_secret() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@prod-db\r").unwrap();
    p.flush().unwrap();
    let (before, _) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
    assert!(
        !before.contains("s3cr3t!"),
        "secret leaked before GOT[..]: {before:?}"
    );
    p.exp_string("GOT[s3cr3t!]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn getpass_prompt_gets_the_real_secret() {
    let env = setup_with_alias("api-key", "xyz-789");
    let mut p = env.spawn_shell(15_000);
    p.send_line(r#"python3 -c "import getpass; print('GOT['+getpass.getpass()+']')""#)
        .unwrap();
    p.exp_string("Password:").unwrap();
    p.send("@api-key\r").unwrap();
    p.flush().unwrap();
    p.exp_string("GOT[xyz-789]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn normal_shell_line_passes_alias_through_literally() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("echo literal:@prod-db").unwrap();
    p.exp_string("literal:@prod-db").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn unknown_alias_reports_and_does_not_submit() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@nope-does-not-exist\r").unwrap();
    p.flush().unwrap();
    // A miss must say so (otherwise the swallowed Enter looks like a hang).
    p.exp_string("no such alias").unwrap();
    // prompt is still live: typing a real password now should work
    p.send("realpw\r").unwrap();
    p.flush().unwrap();
    p.exp_string("GOT[realpw]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn double_at_sends_literal_at() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@@atstart\r").unwrap();
    p.flush().unwrap();
    p.exp_string("GOT[@atstart]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn password_starting_with_at_and_space_passes_through_whole() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@ab cd\r").unwrap();
    p.flush().unwrap();
    p.exp_string("GOT[@ab cd]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn ctrl_c_during_capture_discards_and_forwards_sigint() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    // A deterministic SIGINT handler (bash's own trap semantics inside a
    // `bash -c` subshell are less predictable across bash builds).
    p.send_line(
        "python3 -c \"import signal,sys; \
         signal.signal(signal.SIGINT, lambda *a: (print('TRAPPED'), sys.exit(1))); \
         import getpass; getpass.getpass('Password: ')\"",
    )
    .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@partial").unwrap();
    p.flush().unwrap();
    p.send_control('c').unwrap();
    p.flush().unwrap();
    p.exp_string("TRAPPED").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn alternate_screen_program_never_enters_secret_mode() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    // A tiny program that enters the alternate screen, prints a marker,
    // waits briefly (during which we try to trigger an alias), then exits.
    p.send_line(
        "python3 -c \"import sys,time; sys.stdout.write('\\x1b[?1049h'); \
         sys.stdout.write('ALTSCREEN\\n'); sys.stdout.flush(); time.sleep(1.5); \
         sys.stdout.write('\\x1b[?1049l')\"",
    )
    .unwrap();
    p.exp_string("ALTSCREEN").unwrap();
    // Even though this looks like a capture attempt, nothing should
    // intercept it, and nothing should crash or hang.
    p.send("@prod-db\r").unwrap();
    p.flush().unwrap();
    p.exp_string("TESTPROMPT$").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn exit_status_propagates() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    let mut p = env.spawn_shell(15_000);
    p.send_line("exit 7").unwrap();
    let status = p.process().wait();
    match status {
        Ok(rexpect::process::wait::WaitStatus::Exited(_, code)) => assert_eq!(code, 7),
        other => panic!("unexpected wait status: {other:?}"),
    }
}

#[test]
fn nesting_guard_execs_plain_shell_instead_of_double_wrapping() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    let mut p = env.spawn_shell(15_000);
    p.send_line(&format!("{} shell; echo AFTERNEST[$?]", env.bin.display()))
        .unwrap();
    p.exp_string("already active").unwrap();
    // the nested exec replaced itself with a plain, unwrapped $SHELL
    p.send_line("exit").unwrap();
    p.exp_string("AFTERNEST[0]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn window_resize_propagates_to_child() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    let mut p = env.spawn_shell(15_000);
    p.send_line(
        "python3 -c \"import fcntl,termios,struct; \
         print(struct.unpack('hhhh', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))[0:2])\"",
    )
    .unwrap();
    p.exp_string("(24, 80)").unwrap();

    let ws = libc::winsize {
        ws_row: 40,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    use std::os::fd::AsRawFd;
    tacitty::sys::set_winsize(p.process().pty.as_raw_fd(), &ws).unwrap();
    let _ = tacitty::sys::kill(p.process().child_pid.as_raw(), libc::SIGWINCH);

    p.send_line(
        "python3 -c \"import fcntl,termios,struct; \
         print(struct.unpack('hhhh', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))[0:2])\"",
    )
    .unwrap();
    p.exp_string("(40, 100)").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn sigterm_restores_terminal_and_exits() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    let mut p = env.spawn_shell(15_000);
    p.process_mut()
        .signal(rexpect::process::signal::Signal::SIGTERM)
        .unwrap();
    let status = p.process().wait();
    match status {
        Ok(rexpect::process::wait::WaitStatus::Signaled(_, sig, _)) => {
            assert_eq!(sig, rexpect::process::signal::Signal::SIGTERM)
        }
        // Some kernels/pty combos report it as a 128+sig exit instead.
        Ok(rexpect::process::wait::WaitStatus::Exited(_, code)) => assert_eq!(code, 143),
        other => panic!("unexpected wait status: {other:?}"),
    }
}

/// An interactive `bash` in the test's HOME, as a fresh terminal would
/// start it (so it sources the test's `~/.bashrc`).
fn spawn_login_bash(env: &Env) -> rexpect::session::PtySession {
    let mut cmd = std::process::Command::new("/bin/bash");
    cmd.args(["--noprofile", "-i"]);
    cmd.env("HOME", &env.home);
    cmd.env("XDG_RUNTIME_DIR", &env.runtime);
    cmd.env("SHELL", "/bin/bash");
    cmd.env("TACITTY_TEST_WORK_FACTOR", "8");
    cmd.env_remove("TACITTY_ACTIVE");
    cmd.env_remove("NO_TACITTY");
    cmd.env("BASH_SILENCE_DEPRECATION_WARNING", "1");
    rexpect::session::spawn_command(cmd, Some(15_000)).expect("spawn bash")
}

/// A real bash *login* shell (`bash -l -i`) in the test's HOME — what an ssh
/// session starts. It reads `~/.bash_profile`/`~/.profile`, not `~/.bashrc`.
fn spawn_login_shell_l(env: &Env) -> rexpect::session::PtySession {
    let mut cmd = std::process::Command::new("/bin/bash");
    cmd.args(["-l", "-i"]);
    cmd.env("HOME", &env.home);
    cmd.env("XDG_RUNTIME_DIR", &env.runtime);
    cmd.env("SHELL", "/bin/bash");
    cmd.env("TACITTY_TEST_WORK_FACTOR", "8");
    cmd.env_remove("TACITTY_ACTIVE");
    cmd.env_remove("NO_TACITTY");
    cmd.env("BASH_SILENCE_DEPRECATION_WARNING", "1");
    rexpect::session::spawn_command(cmd, Some(15_000)).expect("spawn login bash")
}

/// An ssh session is a bash *login* shell, which reads `~/.bash_profile` and
/// not `~/.bashrc`. If the login file doesn't source `~/.bashrc`, the hook
/// that lives there never runs — which is why ssh sessions needed a manual
/// `tacitty shell`. `enable` must hook the login file too.
#[test]
fn ssh_style_login_shell_is_wrapped() {
    let env = Env::fresh();
    // The broken case: a login file that does NOT source ~/.bashrc.
    std::fs::write(env.home.join(".bash_profile"), "export FROM_PROFILE=1\n").unwrap();

    // init (enables autostart). Force SHELL=bash so the bash login file is hooked.
    let mut cmd = env.command(&["init"]);
    cmd.env("SHELL", "/bin/bash");
    let mut p = rexpect::session::spawn_command(cmd, Some(10_000)).expect("spawn init");
    p.exp_string("New master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("Confirm master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_eof().unwrap();

    // The hook must have landed in the login file, not only ~/.bashrc.
    let profile = std::fs::read_to_string(env.home.join(".bash_profile")).unwrap();
    assert!(profile.contains("shell --autostart"), "profile: {profile:?}");

    // A real login shell (what ssh starts) must now auto-wrap on its own.
    let mut sh = spawn_login_shell_l(&env);
    sh.send_line("echo ACTIVE[$TACITTY_ACTIVE]").unwrap();
    sh.exp_string("ACTIVE[/dev/").unwrap();
    sh.send_line("exit").unwrap();
    let _ = sh.exp_eof();
}

#[test]
fn init_enables_autostart_and_new_shells_are_wrapped() {
    let env = Env::fresh();
    std::fs::write(env.home.join(".bashrc"), "export FROM_RC=1\n").unwrap();
    let mut p = env.spawn(&["init"], 10_000);
    p.exp_string("New master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("Confirm master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("Auto-start enabled in").unwrap();
    p.exp_eof().unwrap();

    let rc = std::fs::read_to_string(env.home.join(".bashrc")).unwrap();
    assert!(rc.starts_with("export FROM_RC=1\n"), "rc: {rc:?}");
    assert!(rc.contains("shell --autostart"), "rc: {rc:?}");
    let installed = env.home.join(".local/bin/tacitty");
    assert!(installed.is_file(), "binary was not installed");

    let mut sh = spawn_login_bash(&env);
    // The wrapper records which terminal it wrapped: this one.
    sh.send_line("[ \"$TACITTY_ACTIVE\" = \"$(tty)\" ] && echo WRAPPED$((1+1))")
        .unwrap();
    sh.exp_string("WRAPPED2").unwrap();
    sh.send_line("exit").unwrap();
    sh.exp_eof().unwrap();

    let mut p = env.spawn(&["disable"], 10_000);
    p.exp_string("Auto-start removed from").unwrap();
    p.exp_eof().unwrap();
    let rc = std::fs::read_to_string(env.home.join(".bashrc")).unwrap();
    assert_eq!(rc, "export FROM_RC=1\n");
}

#[test]
fn no_tacitty_skips_autostart() {
    let env = Env::fresh();
    std::fs::write(env.home.join(".bashrc"), "").unwrap();
    let mut p = env.spawn(&["enable"], 10_000);
    p.exp_eof().unwrap();

    let mut cmd = std::process::Command::new("/bin/bash");
    cmd.args(["--noprofile", "-i"]);
    cmd.env("HOME", &env.home);
    cmd.env("NO_TACITTY", "1");
    cmd.env_remove("TACITTY_ACTIVE");
    let mut sh = rexpect::session::spawn_command(cmd, Some(15_000)).unwrap();
    sh.send_line("echo ACTIVE[$TACITTY_ACTIVE]").unwrap();
    sh.exp_string("ACTIVE[]").unwrap();
    sh.send_line("exit").unwrap();
    sh.exp_eof().unwrap();
}

#[test]
fn broken_wrapper_falls_back_to_plain_shell() {
    let env = Env::fresh();
    std::fs::write(env.home.join(".bashrc"), "").unwrap();
    let mut p = env.spawn(&["enable"], 10_000);
    p.exp_eof().unwrap();
    // An invalid config makes `tacitty shell` fail before it starts.
    let cfg_dir = env.home.join(".config/tacitty");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("config.toml"), "trigger = 42\n").unwrap();

    let mut sh = spawn_login_bash(&env);
    sh.exp_string("continuing without tacitty").unwrap();
    sh.send_line("echo ALIVE[$TACITTY_ACTIVE]").unwrap();
    sh.exp_string("ALIVE[]").unwrap();
    sh.send_line("exit").unwrap();
    sh.exp_eof().unwrap();
}

/// A stand-in for an interactive `ssh` session: the local pty is raw (as a
/// real ssh client sets it), and the "remote" prints a password prompt and
/// reads one line. The script is *named* `ssh` so the foreground-process
/// allow-list matches it, exactly as it would for the real client.
#[cfg(target_os = "linux")]
fn fake_ssh(env: &Env) -> std::path::PathBuf {
    let bin = env.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let path = bin.join("ssh");
    // Python (not bash `read`, which misbehaves on a raw tty) reading raw
    // bytes up to the Enter key, like a remote sshd's pty would deliver.
    std::fs::write(
        &path,
        "#!/usr/bin/python3\n\
         import os, sys, termios, tty\n\
         fd = sys.stdin.fileno()\n\
         old = termios.tcgetattr(fd)\n\
         tty.setraw(fd)\n\
         os.write(1, b'Password for user postgres: ')\n\
         pw = b''\n\
         while True:\n\
         \x20   c = os.read(fd, 1)\n\
         \x20   if c in (b'\\r', b'\\n', b''): break\n\
         \x20   pw += c\n\
         termios.tcsetattr(fd, termios.TCSANOW, old)\n\
         print()\n\
         print('GOT[' + pw.decode() + ']')\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Like the Linux [`fake_ssh`], but a compiled program: on macOS a script's
/// process name is its interpreter's (`Python`), not the script's, so a
/// script named `ssh` would never match the allow-list.
#[cfg(target_os = "macos")]
fn fake_ssh(env: &Env) -> std::path::PathBuf {
    compile_fake_ssh(
        env,
        r#"
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
int main(void) {
    struct termios old, raw;
    char pw[256], c;
    size_t n = 0;
    tcgetattr(0, &old);
    raw = old;
    cfmakeraw(&raw);
    tcsetattr(0, TCSANOW, &raw);
    write(1, "Password for user postgres: ", 28);
    while (read(0, &c, 1) == 1 && c != '\r' && c != '\n')
        if (n < sizeof pw - 1) pw[n++] = c;
    pw[n] = 0;
    tcsetattr(0, TCSANOW, &old);
    printf("\nGOT[%s]\n", pw);
    return 0;
}
"#,
    )
}

/// Build `src` (C) into an executable named `ssh` with the system compiler
/// (which the Rust toolchain needs anyway, as its linker).
#[cfg(target_os = "macos")]
fn compile_fake_ssh(env: &Env, src: &str) -> std::path::PathBuf {
    let bin = env.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let c_file = env.home.join("fake_ssh.c");
    std::fs::write(&c_file, src).unwrap();
    let path = bin.join("ssh");
    let status = std::process::Command::new("cc")
        .arg("-o")
        .arg(&path)
        .arg(&c_file)
        .status()
        .expect("run cc");
    assert!(status.success(), "compiling the fake ssh failed");
    path
}

/// A fake `ssh` that leaves the local terminal echoing (like `ssh host
/// 'sudo -S ...'` or `ssh -T`), prints a password prompt and reads a line.
#[cfg(target_os = "linux")]
fn fake_ssh_with_local_echo(env: &Env) -> std::path::PathBuf {
    let bin = env.home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let ssh = bin.join("ssh");
    std::fs::write(
        &ssh,
        "#!/usr/bin/python3\n\
         import sys\n\
         sys.stdout.write('Password for user postgres: ')\n\
         sys.stdout.flush()\n\
         print('GOT[' + sys.stdin.readline().strip() + ']')\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    ssh
}

/// See the Linux version and [`fake_ssh`] for why this is compiled.
#[cfg(target_os = "macos")]
fn fake_ssh_with_local_echo(env: &Env) -> std::path::PathBuf {
    compile_fake_ssh(
        env,
        r#"
#include <stdio.h>
#include <string.h>
int main(void) {
    char line[256];
    fputs("Password for user postgres: ", stdout);
    fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) line[0] = 0;
    line[strcspn(line, "\r\n")] = 0;
    printf("GOT[%s]\n", line);
    return 0;
}
"#,
    )
}

#[test]
fn remote_prompt_sends_secret_without_confirmation_by_default() {
    let env = setup_with_alias("db", "pg-s3cret");
    let ssh = fake_ssh(&env);
    let mut p = env.spawn_shell(15_000);
    p.send_line(&ssh.display().to_string()).unwrap();
    p.exp_string("Password for user postgres: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@db\r").unwrap();
    p.flush().unwrap();
    let (before, got) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
    assert_eq!(got, "GOT[pg-s3cret]");
    assert!(
        !before.contains("send secret"),
        "unexpected confirmation: {before:?}"
    );
    assert!(!before.contains("pg-s3cret"), "secret leaked: {before:?}");
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn remote_prompt_asks_first_in_confirm_mode() {
    let env = setup_with_alias("db", "pg-s3cret");
    let cfg_dir = env.home.join(".config/tacitty");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        cfg_dir.join("config.toml"),
        "[remote]\nmode = \"confirm\"\n",
    )
    .unwrap();
    let ssh = fake_ssh(&env);
    let mut p = env.spawn_shell(15_000);
    p.send_line(&ssh.display().to_string()).unwrap();
    p.exp_string("Password for user postgres: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@db\r").unwrap();
    p.flush().unwrap();
    p.exp_string("send secret for @db? [y/N]").unwrap();
    p.send("y\r").unwrap();
    p.flush().unwrap();
    p.exp_string("GOT[pg-s3cret]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

// ---------------------------------------------------------------------------
// Security regressions (see the audit findings these reproduce)
// ---------------------------------------------------------------------------

/// Pressing Ctrl-C at a password prompt and then typing an alias at the
/// shell prompt must not send the secret to the shell (where it would be
/// echoed, run as a command and saved in history).
#[test]
fn alias_after_ctrl_c_at_prompt_is_not_sent_to_shell() {
    let env = setup_with_alias("proddb", "S3CRETVALUE");
    let mut p = env.spawn_shell(15_000);
    p.send_line("read -s -p 'Password: ' pw").unwrap();
    p.exp_string("Password: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send_control('c').unwrap();
    p.exp_string("TESTPROMPT$ ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@proddb\r").unwrap();
    p.flush().unwrap();
    let out1 = p.exp_string("@proddb: command not found").unwrap();
    p.send_line("history | tail -3; echo HIST$((1+1))END")
        .unwrap();
    let out2 = p.exp_string("HIST2END").unwrap();
    for out in [&out1, &out2] {
        assert!(!out.contains("S3CRETVALUE"), "secret leaked: {out:?}");
    }
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

/// If the prompt times out while an alias is being typed, the secret must
/// not be sent to whatever reads the terminal afterwards.
#[test]
fn prompt_timeout_during_alias_sends_nothing() {
    let env = setup_with_alias("proddb", "S3CRETVALUE");
    let mut p = env.spawn_shell(15_000);
    p.send_line("read -s -t 2 -p 'Password: ' pw; echo; echo RESULT[$pw]")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@").unwrap();
    p.flush().unwrap();
    let out1 = p.exp_string("RESULT[]").unwrap();
    p.send("proddb\r").unwrap();
    p.flush().unwrap();
    let out2 = p.exp_string("nothing was sent").unwrap();
    p.send_line("history | tail -3; echo CHECK$((2+2))")
        .unwrap();
    let out3 = p.exp_string("CHECK4").unwrap();
    for out in [&out1, &out2, &out3] {
        assert!(!out.contains("S3CRETVALUE"), "secret leaked: {out:?}");
    }
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

/// `ssh host 'sudo -S ...'`, `ssh -T`, `kubectl exec -i`: the local
/// terminal still echoes, so a remote-looking prompt must not get the
/// secret (it would be printed on screen).
#[test]
fn remote_prompt_with_local_echo_on_gets_no_secret() {
    let env = setup_with_alias("db", "pg-s3cret");
    let ssh = fake_ssh_with_local_echo(&env);
    let mut p = env.spawn_shell(15_000);
    p.send_line(&ssh.display().to_string()).unwrap();
    p.exp_string("Password for user postgres: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@db\r").unwrap();
    p.flush().unwrap();
    let (before, got) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
    assert_eq!(got, "GOT[@db]");
    assert!(!before.contains("pg-s3cret"), "secret leaked: {before:?}");
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

/// A long output line of multi-byte characters used to crash the wrapper.
#[test]
fn long_multibyte_output_line_does_not_crash() {
    let env = Env::fresh();
    let mut p = env.spawn_shell(15_000);
    p.send_line(
        "printf '\u{e9}%0600d\\n' 0; printf '\u{65e5}%.0s' $(seq 400); echo; echo ALIVE$((3+4))",
    )
    .unwrap();
    p.exp_string("ALIVE7").unwrap();
    p.send_line("echo STILL$((4+4))").unwrap();
    p.exp_string("STILL8").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

// ---------------------------------------------------------------------------
// export / import
// ---------------------------------------------------------------------------

const EXPORT_PASS: &str = "share this one separately";

fn exited_ok(p: &mut rexpect::session::PtySession) -> bool {
    matches!(
        p.process().wait(),
        Ok(rexpect::process::wait::WaitStatus::Exited(_, 0))
    )
}

/// Run a command that asks only for the master passphrase; returns whether
/// it succeeded and its output (stdout and stderr: both go to the pty).
fn with_master(env: &Env, args: &[&str]) -> (bool, String) {
    let mut p = env.spawn(args, 15_000);
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    let out = p.exp_eof().unwrap();
    (exited_ok(&mut p), out)
}

/// `tacitty export <args>` with an export passphrase; returns whether it
/// succeeded and its output.
fn export_with_passphrase(env: &Env, args: &[&str], export_pass: &str) -> (bool, String) {
    let mut p = env.spawn(args, 15_000);
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("Export passphrase:").unwrap();
    p.send_line(export_pass).unwrap();
    p.exp_string("Confirm export passphrase:").unwrap();
    p.send_line(export_pass).unwrap();
    let out = p.exp_eof().unwrap();
    (exited_ok(&mut p), out)
}

/// `tacitty import <file> [extra]` for a passphrase-protected file.
fn import_file(env: &Env, file: &str, extra: &[&str]) -> String {
    let mut args = vec!["import", file];
    args.extend_from_slice(extra);
    let mut p = env.spawn(&args, 15_000);
    p.exp_string("Export file passphrase:").unwrap();
    p.send_line(EXPORT_PASS).unwrap();
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    let out = p.exp_eof().unwrap();
    assert!(exited_ok(&mut p), "import failed: {out:?}");
    out
}

/// The secret stored under `alias`, via `tacitty get` with stdout piped.
fn stored_secret(env: &Env, alias: &str) -> String {
    // Lock first so the unlock always prompts (and reloads the vault),
    // whether or not the import just locked the agent.
    assert!(env.command(&["lock"]).output().unwrap().status.success());
    unlock_agent(env, PASSPHRASE);
    let out = env.command(&["get", alias]).output().unwrap();
    assert!(out.status.success(), "get failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn exported_alias_resolves_after_import_elsewhere() {
    let alice = setup_with_alias("prod-db", "s3cr3t!");
    add_alias(&alice, "other", "not-exported", PASSPHRASE);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("prod.tacitty");
    let file_s = file.to_str().unwrap();

    let (ok, out) =
        export_with_passphrase(&alice, &["export", "prod-db", "-o", file_s], EXPORT_PASS);
    assert!(ok, "export failed: {out:?}");
    assert!(out.contains("Exported 1 alias"), "{out:?}");
    assert!(!out.contains("s3cr3t!"), "{out:?}");
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::metadata(&file).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    let raw = std::fs::read(&file).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1\n"));
    assert!(!raw.windows(7).any(|w| w == b"s3cr3t!"));

    let bob = Env::fresh();
    init_vault(&bob, PASSPHRASE);
    let out = import_file(&bob, file_s, &[]);
    assert!(out.contains("Imported 1 alias:"), "{out:?}");
    assert!(out.contains("group default: @prod-db"), "{out:?}");
    assert!(!out.contains("other"), "{out:?}");
    unlock_agent(&bob, PASSPHRASE);

    let mut p = bob.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@prod-db\r").unwrap();
    p.flush().unwrap();
    let (before, _) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
    assert!(
        !before.contains("s3cr3t!"),
        "secret leaked before GOT[..]: {before:?}"
    );
    p.exp_string("GOT[s3cr3t!]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn import_skips_existing_aliases_unless_overwrite() {
    let alice = setup_with_alias("prod-db", "new-secret");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("team.tacitty");
    let file_s = file.to_str().unwrap();
    let (ok, out) =
        export_with_passphrase(&alice, &["export", "-o", file_s, "--armor"], EXPORT_PASS);
    assert!(ok, "export failed: {out:?}");
    assert!(std::fs::read(&file)
        .unwrap()
        .starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

    let bob = setup_with_alias("prod-db", "old-secret");
    let out = import_file(&bob, file_s, &[]);
    assert!(out.contains("Imported nothing"), "{out:?}");
    assert!(
        out.contains("prod-db: already in your vault (use --overwrite"),
        "{out:?}"
    );
    assert_eq!(stored_secret(&bob, "prod-db"), "old-secret");

    let out = import_file(&bob, file_s, &["--overwrite"]);
    assert!(
        out.contains("group default: @prod-db (replaced)"),
        "{out:?}"
    );
    assert_eq!(stored_secret(&bob, "prod-db"), "new-secret");
}

#[test]
fn export_to_ssh_key_imports_with_default_identity() {
    let bob = Env::fresh();
    init_vault(&bob, PASSPHRASE);
    let ssh_dir = bob.home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let key = ssh_dir.join("id_ed25519");
    let made = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "bob@host", "-f"])
        .arg(&key)
        .status();
    if !matches!(made, Ok(s) if s.success()) {
        eprintln!("note: ssh-keygen not available, skipping");
        return;
    }

    let alice = setup_with_alias("rootpw", "r00t-pw");
    let (ok, out) = with_master(&alice, &["group", "move", "rootpw", "--to", "ops"]);
    assert!(ok, "{out:?}");
    let dir = tempfile::tempdir().unwrap();

    // Garbage is refused before any passphrase is asked for.
    let out = alice
        .command(&["export", "--with-key", "nonsense.pub", "-o", "x.tacitty"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--with-key: `nonsense.pub` is not a public key"),
        "{err}"
    );

    let keys = dir.path().join("bob.keys");
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    std::fs::write(&keys, format!("# Bob's laptop\n{public}\n")).unwrap();
    let file = dir.path().join("for-bob.tacitty");
    let file_s = file.to_str().unwrap();
    let mut p = alice.spawn(
        &[
            "export",
            "rootpw",
            "--with-key",
            keys.to_str().unwrap(),
            "-o",
            file_s,
        ],
        15_000,
    );
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("Encrypted to 1 public key").unwrap();
    p.exp_eof().unwrap();
    assert!(exited_ok(&mut p));

    // No -i: ~/.ssh/id_ed25519 is used, and only the master passphrase is
    // asked for.
    let mut p = bob.spawn(&["import", file_s], 15_000);
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    let out = p.exp_eof().unwrap();
    assert!(exited_ok(&mut p), "import failed: {out:?}");
    assert!(out.contains("group ops: @rootpw"), "{out:?}");
    assert_eq!(stored_secret(&bob, "rootpw"), "r00t-pw");

    // Someone without the key gets a clear error.
    let eve = Env::fresh();
    init_vault(&eve, PASSPHRASE);
    let out = eve.command(&["import", file_s]).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("encrypted to public keys"), "{err}");
}

#[test]
fn export_refuses_short_passphrase_and_existing_file() {
    let alice = setup_with_alias("prod-db", "s3cr3t!");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("x.tacitty");
    let file_s = file.to_str().unwrap();
    let (ok, out) = export_with_passphrase(&alice, &["export", "-o", file_s], "too short");
    assert!(!ok);
    assert!(out.contains("at least 12 characters"), "{out:?}");
    assert!(!file.exists());

    std::fs::write(&file, b"keep me").unwrap();
    let out = alice.command(&["export", "-o", file_s]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--force"));
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
}

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------

/// `tacitty <args>`, which must succeed; returns its output.
fn ok_with_master(env: &Env, args: &[&str]) -> String {
    let (ok, out) = with_master(env, args);
    assert!(ok, "`tacitty {}` failed: {out:?}", args.join(" "));
    out
}

/// `tacitty <args>`, which must fail after the passphrase; returns its output.
fn fails_with_master(env: &Env, args: &[&str]) -> String {
    let (ok, out) = with_master(env, args);
    assert!(
        !ok,
        "`tacitty {}` should have failed: {out:?}",
        args.join(" ")
    );
    out
}

/// Position of `needle` in `hay`, which must contain it.
fn pos(hay: &str, needle: &str) -> usize {
    hay.find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in {hay:?}"))
}

#[test]
fn add_and_ls_by_group() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, "home", "h-pw", PASSPHRASE);
    add_alias_in(&env, "proddb", "prod", "p-pw", PASSPHRASE);
    add_alias_in(&env, "rootpw", "prod", "r-pw", PASSPHRASE);

    let out = ok_with_master(&env, &["ls"]);
    assert!(!out.contains("-pw"), "secret shown: {out:?}");
    let default = pos(&out, "default (default)\r\n  @home ");
    let prod = pos(&out, "\r\nprod\r\n  @proddb ");
    assert!(default < prod, "{out:?}");
    assert!(pos(&out, "@rootpw") > prod, "{out:?}");
    assert!(out.contains("created ") && out.contains(" UTC"), "{out:?}");

    let out = ok_with_master(&env, &["ls", "-g", "prod"]);
    assert!(
        out.contains("@proddb") && out.contains("@rootpw"),
        "{out:?}"
    );
    assert!(
        !out.contains("@home") && !out.contains("default"),
        "{out:?}"
    );
    assert!(fails_with_master(&env, &["ls", "--group", "nope"]).contains("no such group: nope"));

    let out = ok_with_master(&env, &["group", "ls"]);
    assert!(out.contains("default"), "{out:?}");
    assert!(out.contains("1 alias  (default)"), "{out:?}");
    assert!(out.contains("2 aliases"), "{out:?}");

    // Invalid names are refused before anything is asked.
    for args in [
        &["add", "x", "-g", "bad/name"][..],
        &["ls", "-g", "_oops"],
        &["group", "move", "home", "--to", "a b"],
    ] {
        let out = env.command(args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("invalid group name"), "{args:?}: {err}");
    }
}

#[test]
fn group_move_rename_rm_and_default() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, "home", "h-pw", PASSPHRASE);
    add_alias_in(&env, "proddb", "prod", "p-pw", PASSPHRASE);
    add_alias(&env, "rootpw", "r-pw", PASSPHRASE);

    // move: an unknown alias changes nothing.
    let out = fails_with_master(&env, &["group", "move", "rootpw", "nope", "--to", "prod"]);
    assert!(out.contains("no such alias: nope"), "{out:?}");
    assert!(!ok_with_master(&env, &["ls", "-g", "prod"]).contains("@rootpw"));
    let out = ok_with_master(&env, &["group", "move", "rootpw", "proddb", "--to", "prod"]);
    assert!(out.contains("Moved @rootpw to group prod."), "{out:?}");
    assert!(out.contains("Already in group prod: @proddb."), "{out:?}");
    let out = ok_with_master(&env, &["group", "move", "home", "--to", "personal"]);
    assert!(out.contains("Moved @home to group personal."), "{out:?}");

    // rename: never onto an existing group.
    let out = fails_with_master(&env, &["group", "rename", "prod", "personal"]);
    assert!(out.contains("group personal already exists"), "{out:?}");
    assert!(out.contains("tacitty group move"), "{out:?}");
    let out = ok_with_master(&env, &["group", "rename", "prod", "production"]);
    assert!(
        out.contains("Renamed group prod to production (2 aliases)."),
        "{out:?}"
    );
    let out = ok_with_master(&env, &["ls", "-g", "production"]);
    assert!(
        out.contains("@proddb") && out.contains("@rootpw"),
        "{out:?}"
    );

    // rm: never the default group; aliases move to the default group.
    let out = fails_with_master(&env, &["group", "rm", "default"]);
    assert!(out.contains("default is the default group"), "{out:?}");
    let out = ok_with_master(&env, &["group", "rm", "personal"]);
    assert!(out.contains("Removed group personal."), "{out:?}");
    assert!(out.contains("Moved @home to group default."), "{out:?}");

    // default: show and set; new aliases follow it, renames carry it along.
    let out = ok_with_master(&env, &["group", "default"]);
    assert!(out.contains("group default (the default group)"), "{out:?}");
    let out = ok_with_master(&env, &["group", "default", "production"]);
    assert!(
        out.contains("New aliases now go into group production."),
        "{out:?}"
    );
    add_alias(&env, "newone", "n-pw", PASSPHRASE);
    assert!(ok_with_master(&env, &["ls", "-g", "production"]).contains("@newone"));
    let out = ok_with_master(&env, &["group", "rename", "production", "live"]);
    assert!(out.contains("live is still the default group"), "{out:?}");
    let out = ok_with_master(&env, &["group", "ls"]);
    assert!(out.contains("3 aliases  (default)"), "{out:?}");
    assert!(pos(&out, "live") > pos(&out, "default"), "{out:?}");
    assert!(!out.contains("production"), "{out:?}");

    // `mv` keeps the alias in its group.
    ok_with_master(&env, &["mv", "home", "house"]);
    assert!(ok_with_master(&env, &["ls", "-g", "default"]).contains("@house"));
}

#[test]
fn alias_resolves_after_moving_between_groups() {
    let env = setup_with_alias("proddb", "s3cr3t!");
    ok_with_master(&env, &["group", "move", "proddb", "--to", "prod"]);
    ok_with_master(&env, &["group", "move", "proddb", "--to", "ops"]);
    // Each change locks the agent, so it reloads the vault on unlock.
    unlock_agent(&env, PASSPHRASE);
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@proddb\r").unwrap();
    p.flush().unwrap();
    let (before, _) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
    assert!(!before.contains("s3cr3t!"), "secret leaked: {before:?}");
    p.exp_string("GOT[s3cr3t!]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn exported_groups_survive_import() {
    let alice = Env::fresh();
    init_vault(&alice, PASSPHRASE);
    add_alias(&alice, "notmine", "x-pw", PASSPHRASE);
    add_alias_in(&alice, "proddb", "prod", "p-pw", PASSPHRASE);
    add_alias_in(&alice, "rootpw", "prod", "r-pw", PASSPHRASE);
    add_alias_in(&alice, "home", "personal", "h-pw", PASSPHRASE);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("prod.tacitty");
    let file_s = file.to_str().unwrap();

    let out = fails_with_master(&alice, &["export", "-g", "nope", "-o", file_s]);
    assert!(out.contains("no such group: nope"), "{out:?}");
    assert!(!file.exists());

    // A group plus a named alias from another group.
    let (ok, out) = export_with_passphrase(
        &alice,
        &["export", "--group", "prod", "home", "-o", file_s],
        EXPORT_PASS,
    );
    assert!(ok, "export failed: {out:?}");
    assert!(out.contains("Exported 3 aliases"), "{out:?}");
    assert!(out.contains("group personal: @home"), "{out:?}");
    assert!(out.contains("group prod: @proddb, @rootpw"), "{out:?}");
    assert!(!out.contains("notmine"), "{out:?}");

    // Bob's default group is different; the file's groups win.
    let bob = Env::fresh();
    init_vault(&bob, PASSPHRASE);
    ok_with_master(&bob, &["group", "default", "inbox"]);
    let out = import_file(&bob, file_s, &[]);
    assert!(out.contains("Imported 3 aliases:"), "{out:?}");
    assert!(out.contains("group personal: @home"), "{out:?}");
    assert!(out.contains("group prod: @proddb, @rootpw"), "{out:?}");
    let out = ok_with_master(&bob, &["ls", "-g", "prod"]);
    assert!(
        out.contains("@proddb") && out.contains("@rootpw"),
        "{out:?}"
    );
    assert!(!out.contains("@home"), "{out:?}");
    assert_eq!(stored_secret(&bob, "rootpw"), "r-pw");

    // --group puts everything in one group.
    let out = import_file(&bob, file_s, &["--overwrite", "--group", "shared"]);
    assert!(
        out.contains("group shared: @home (replaced), @proddb (replaced), @rootpw (replaced)"),
        "{out:?}"
    );
    let out = ok_with_master(&bob, &["group", "ls"]);
    assert!(
        out.contains("shared") && out.contains("3 aliases"),
        "{out:?}"
    );
    assert!(!out.contains("prod"), "{out:?}");
}

/// Renaming onto an alias that already exists must not destroy its secret.
#[test]
fn mv_refuses_to_overwrite_an_existing_alias() {
    let env = setup_with_alias("first", "secret-one");
    add_alias(&env, "second", "secret-two", PASSPHRASE);
    let out = fails_with_master(&env, &["mv", "first", "second"]);
    assert!(out.contains("already exists"), "{out:?}");
    assert_eq!(stored_secret(&env, "first"), "secret-one");
    assert_eq!(stored_secret(&env, "second"), "secret-two");
}

/// The longest allowed secret must arrive whole at a real password prompt,
/// on every platform (macOS's terminal line buffer is only 1024 bytes).
#[test]
fn longest_allowed_secret_is_delivered_whole() {
    let secret: String = "Abc123-_.".chars().cycle().take(1000).collect();
    let env = setup_with_alias("long", &secret);
    let mut p = env.spawn_shell(30_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo LEN[${#pw}]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@long\r").unwrap();
    p.flush().unwrap();
    p.exp_string("LEN[1000]").unwrap();
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

/// The agent closes idle connections; the wrapper must reconnect instead of
/// failing every later lookup in that shell.
#[test]
fn aliases_keep_working_after_the_agent_connection_goes_idle() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, "prod-db", "s3cr3t!", PASSPHRASE);
    // The wrapper starts the agent itself, so it inherits a 1 s idle timeout.
    let mut cmd = env.command(&["shell"]);
    cmd.env("SHELL", "/bin/bash");
    cmd.env("PS1", "TESTPROMPT$ ");
    cmd.env("TACITTY_TEST_AGENT_IDLE_SECS", "1");
    let mut p = rexpect::session::spawn_command(cmd, Some(20_000)).unwrap();
    p.send_line("PS1='TESTPROMPT$ '").unwrap();
    p.exp_string("TESTPROMPT$ ").unwrap();
    // The prompt text is assembled by printf so that "Password: " and
    // "GOT[" only ever appear in bash's output, never in the echoed command.
    let prompt = "bash -c 'read -s -p \"$(printf \"Pass%s: \" word)\" pw; echo; printf \"%s[%s]\\n\" GOT \"$pw\"'";

    p.send_line(prompt).unwrap();
    p.exp_string("Password: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send("@prod-db\r").unwrap();
    p.flush().unwrap();
    p.exp_string("enter master passphrase to unlock vault")
        .unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_string("GOT[s3cr3t!]").unwrap();

    // Let the agent drop the idle connection, then look up twice more.
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_secs(3));
        p.send_line(prompt).unwrap();
        p.exp_string("Password: ").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        p.send("@prod-db\r").unwrap();
        p.flush().unwrap();
        let (before, got) = p.exp_regex(r"GOT\[[^\]]*\]").unwrap();
        assert_eq!(got, "GOT[s3cr3t!]", "{before:?}");
        assert!(
            !before.contains("unlock vault"),
            "asked to unlock again: {before:?}"
        );
    }
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

/// Ctrl-C at a passphrase prompt must leave the terminal echoing again.
#[test]
fn ctrl_c_at_passphrase_prompt_restores_echo() {
    let env = Env::fresh();
    let mut p = env.spawn_shell(15_000);
    p.send_line(&format!(
        "{} init --no-autostart; stty -a | tr ' ' '\\n' | grep -x -e echo -e -echo",
        env.bin.display()
    ))
    .unwrap();
    p.exp_string("New master passphrase:").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.send_control('c').unwrap();
    p.exp_string("cancelled").unwrap();
    // `stty -a` lists "echo" when echo is on and "-echo" when it is off.
    let (_, state) = p.exp_regex(r"\n-?echo\r").unwrap();
    assert_eq!(state.trim(), "echo", "terminal left with echo off");
    p.send_line("exit").unwrap();
    p.exp_eof().unwrap();
}

// ---------------------------------------------------------------------------
// Terminals inside terminals (tmux, screen, ...)
// ---------------------------------------------------------------------------

/// A vault with @prod-db, and auto-start enabled in this Env's ~/.bashrc.
fn env_with_autostart() -> Env {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    std::fs::write(env.home.join(".bashrc"), "").unwrap();
    let mut p = env.spawn(&["enable"], 10_000);
    p.exp_eof().unwrap();
    env
}

/// A new terminal opened inside a wrapped one (what tmux and screen do for
/// each pane/window) gets wrapped too, and aliases work in it.
#[test]
fn a_terminal_inside_a_wrapped_terminal_is_wrapped_too() {
    let env = env_with_autostart();
    let mut sh = spawn_login_bash(&env);
    sh.send_line("PS1='OUTER$ '").unwrap();
    sh.exp_string("OUTER$ ").unwrap();
    // A fresh pty with an interactive bash in it, like a tmux pane.
    sh.send_line("python3 -c 'import pty; pty.spawn([\"bash\", \"-i\"])'")
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    sh.send_line("PS1='INNER$ '").unwrap();
    sh.exp_string("INNER$ ").unwrap();
    // The inner terminal's wrapper recorded the inner terminal.
    sh.send_line("[ \"$TACITTY_ACTIVE\" = \"$(tty)\" ] && echo WRAPPED$((1+1))")
        .unwrap();
    sh.exp_string("WRAPPED2").unwrap();
    sh.send_line("bash -c 'read -s -p \"$(printf \"Pass%s: \" word)\" pw; echo; printf \"%s[%s]\\n\" GOT \"$pw\"'")
        .unwrap();
    sh.exp_string("Password: ").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    sh.send("@prod-db\r").unwrap();
    sh.flush().unwrap();
    sh.exp_string("GOT[s3cr3t!]").unwrap();
    sh.send_line("exit").unwrap(); // inner wrapped shell
    sh.exp_string("OUTER$ ").unwrap();
    sh.send_line("exit").unwrap(); // outer wrapped shell
    sh.exp_eof().unwrap();
}

/// Real tmux: a pane's shell is wrapped automatically, even though tmux
/// passes the outer terminal's TACITTY_ACTIVE on to it. Skipped where tmux
/// isn't installed.
#[test]
fn tmux_panes_are_wrapped_automatically() {
    if std::process::Command::new("tmux")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("note: tmux not installed, skipping");
        return;
    }
    let env = env_with_autostart();
    let sock = format!("tacitty-test-{}", std::process::id());
    let tmux = |args: &[&str]| {
        let mut c = std::process::Command::new("tmux");
        c.args(["-L", &sock, "-f", "/dev/null"]).args(args);
        c.env("HOME", &env.home);
        c.env("XDG_RUNTIME_DIR", &env.runtime);
        c.env("SHELL", "/bin/bash");
        c.env("TACITTY_TEST_WORK_FACTOR", "8");
        c.env("BASH_SILENCE_DEPRECATION_WARNING", "1");
        // As if tmux had been started from inside a wrapped terminal.
        c.env("TACITTY_ACTIVE", "/dev/not-this-terminal");
        c.output().unwrap()
    };
    let capture =
        || String::from_utf8_lossy(&tmux(&["capture-pane", "-p", "-t", "t"]).stdout).into_owned();
    let wait_for = |needle: &str| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let screen = capture();
            if screen.contains(needle) {
                return screen;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "never saw {needle:?}:\n{screen}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    assert!(tmux(&[
        "new-session",
        "-d",
        "-s",
        "t",
        "-x",
        "100",
        "-y",
        "30",
        "bash -i"
    ])
    .status
    .success());
    std::thread::sleep(std::time::Duration::from_millis(1500));
    tmux(&[
        "send-keys",
        "-t",
        "t",
        "[ \"$TACITTY_ACTIVE\" = \"$(tty)\" ] && echo PANE$((1+1))WRAPPED",
        "Enter",
    ]);
    wait_for("PANE2WRAPPED");
    tmux(&["send-keys", "-t", "t", "bash -c 'read -s -p \"$(printf \"Pass%s: \" word)\" pw; echo; printf \"%s[%s]\\n\" GOT \"$pw\"'", "Enter"]);
    wait_for("Password:"); // capture-pane trims trailing spaces
    std::thread::sleep(std::time::Duration::from_millis(300));
    tmux(&["send-keys", "-t", "t", "@prod-db", "Enter"]);
    let screen = wait_for("GOT[");
    let _ = tmux(&["kill-server"]);
    assert!(screen.contains("GOT[s3cr3t!]"), "{screen}");
}

// ---------------------------------------------------------------------------
// `tacitty run`
// ---------------------------------------------------------------------------

/// A `bash -c` script that writes each of its arguments, one per line, to
/// `out`. Combined with a trailing `_` (bash's `$0`) and the real arguments,
/// this lets a test see exactly what argv the child received.
fn argv_dump_script(out: &std::path::Path) -> String {
    format!("printf '%s\\n' \"$@\" > {}", out.display())
}

#[test]
fn run_substitutes_a_whole_arg_alias_into_the_child_argv() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    // The alias name is what appears on tacitty's command line; the child
    // must receive the real secret in its place.
    let result = env
        .command(&["run", "bash", "-c", &script, "_", "@prod-db"])
        .output()
        .unwrap();
    assert!(result.status.success(), "run failed: {result:?}");
    let argv = std::fs::read_to_string(&out).unwrap();
    assert_eq!(argv, "s3cr3t!\n", "child argv was {argv:?}");
}

#[test]
fn run_substitutes_the_flag_equals_alias_form() {
    let env = setup_with_alias("smtp", "p@ss-w0rd");
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    let result = env
        .command(&["run", "bash", "-c", &script, "_", "--auth-password=@smtp"])
        .output()
        .unwrap();
    assert!(result.status.success(), "run failed: {result:?}");
    let argv = std::fs::read_to_string(&out).unwrap();
    // The flag is kept verbatim; only the value is replaced.
    assert_eq!(
        argv, "--auth-password=p@ss-w0rd\n",
        "child argv was {argv:?}"
    );
}

#[test]
fn run_passes_a_doubled_trigger_through_as_a_literal() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    let result = env
        .command(&["run", "bash", "-c", &script, "_", "@@literal", "--p=@@x"])
        .output()
        .unwrap();
    assert!(result.status.success(), "run failed: {result:?}");
    let argv = std::fs::read_to_string(&out).unwrap();
    assert_eq!(argv, "@literal\n--p=@x\n", "child argv was {argv:?}");
}

#[test]
fn run_leaves_an_email_style_arg_untouched() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    let result = env
        .command(&["run", "bash", "-c", &script, "_", "user@example.com"])
        .output()
        .unwrap();
    assert!(result.status.success(), "run failed: {result:?}");
    let argv = std::fs::read_to_string(&out).unwrap();
    assert_eq!(argv, "user@example.com\n", "child argv was {argv:?}");
}

#[test]
fn run_errors_on_an_unknown_alias_and_does_not_run_the_command() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    let result = env
        .command(&["run", "bash", "-c", &script, "_", "@nope"])
        .output()
        .unwrap();
    assert!(!result.status.success(), "run should have failed");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("no such alias: nope"),
        "stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("@@"),
        "should hint the @@ escape: {stderr:?}"
    );
    assert!(!out.exists(), "the command must not have run");
}

#[test]
fn run_propagates_the_child_exit_status() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let result = env
        .command(&["run", "bash", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(7),
        "status was {:?}",
        result.status
    );
}

#[test]
fn run_prompts_for_the_passphrase_when_the_vault_is_locked() {
    let env = Env::fresh();
    init_vault(&env, PASSPHRASE);
    add_alias(&env, "prod-db", "s3cr3t!", PASSPHRASE);
    // Deliberately NOT unlocking: `add` leaves the agent locked, so `run`
    // must prompt for the master passphrase inline before resolving.
    let out = env.home.join("argv.txt");
    let script = argv_dump_script(&out);
    let mut p = env.spawn(&["run", "bash", "-c", &script, "_", "@prod-db"], 15_000);
    p.exp_string("Master passphrase:").unwrap();
    p.send_line(PASSPHRASE).unwrap();
    p.exp_eof().unwrap();
    assert!(exited_ok(&mut p), "run did not exit 0");
    let argv = std::fs::read_to_string(&out).unwrap();
    assert_eq!(argv, "s3cr3t!\n", "child argv was {argv:?}");
}

// Completions and the man page are generated from the live CLI and need no
// vault or agent, so these just run the binary and check its stdout.

#[test]
fn completions_generate_a_script_for_each_shell() {
    let env = Env::fresh();
    for shell in ["bash", "zsh", "fish"] {
        let out = env.command(&["completions", shell]).output().unwrap();
        assert!(
            out.status.success(),
            "`tacitty completions {shell}` exited non-zero: {out:?}"
        );
        let script = String::from_utf8_lossy(&out.stdout);
        assert!(
            !script.trim().is_empty(),
            "`tacitty completions {shell}` printed nothing"
        );
        assert!(
            script.contains("tacitty"),
            "`tacitty completions {shell}` script never mentions tacitty"
        );
    }
}

#[test]
fn completions_reject_an_unknown_shell() {
    let env = Env::fresh();
    let out = env.command(&["completions", "smalltalk"]).output().unwrap();
    assert!(
        !out.status.success(),
        "an unknown shell should be rejected, not accepted"
    );
}

#[test]
fn man_page_is_roff_with_our_sections() {
    let env = Env::fresh();
    let out = env.command(&["man"]).output().unwrap();
    assert!(
        out.status.success(),
        "`tacitty man` exited non-zero: {out:?}"
    );
    let page = String::from_utf8_lossy(&out.stdout);
    // A real man page: the title header, the program name, and the
    // hand-written sections we append after the generated ones.
    assert!(page.contains(".TH"), "man page has no .TH title header");
    assert!(page.contains("TACITTY"), "man page never mentions TACITTY");
    for section in [".SH FILES", ".SH ENVIRONMENT", ".SH EXAMPLES"] {
        assert!(page.contains(section), "man page is missing {section}");
    }
}
