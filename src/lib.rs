// The pty, termios, process-hardening and peer-credential code in `sys` is
// written for these two kernels only.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("tacitty supports Linux and macOS only");

pub mod agent;
pub mod alias;
pub mod autostart;
pub mod backend;
pub mod config;
pub mod detect;
pub mod export;
pub mod logging;
pub mod remote;
pub mod resolver;
pub mod secret;
pub mod statemachine;
pub mod sys;
pub mod update;
pub mod vault;
pub mod wrapper;
