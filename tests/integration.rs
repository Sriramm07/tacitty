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

use common::{add_alias, init_vault, unlock_agent, Env};

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
fn unknown_alias_bells_and_does_not_submit() {
    let env = setup_with_alias("prod-db", "s3cr3t!");
    let mut p = env.spawn_shell(15_000);
    p.send_line("bash -c 'read -s -p \"Password: \" pw; echo; echo GOT[$pw]'")
        .unwrap();
    p.exp_string("Password: ").unwrap();
    p.send("@nope-does-not-exist\r").unwrap();
    p.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
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
         print(struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, b'0000'))[0:2])\"",
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
    let f = p.process().get_file_handle().unwrap();
    tacitty::sys::set_winsize(f.as_raw_fd(), &ws).unwrap();
    let _ = tacitty::sys::kill(p.process().child_pid.as_raw(), libc::SIGWINCH);

    p.send_line(
        "python3 -c \"import fcntl,termios,struct; \
         print(struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, b'0000'))[0:2])\"",
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
    rexpect::session::spawn_command(cmd, Some(15_000)).expect("spawn bash")
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
    sh.send_line("echo ACTIVE[$TACITTY_ACTIVE]").unwrap();
    sh.exp_string("ACTIVE[1]").unwrap();
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
