//! Bridges the input state machine to an actual secret source: the agent
//! (for the native backend, so the vault only needs unlocking once) or a
//! stateless backend (pass / secret-service / command) directly.

use secrecy::SecretString;

use crate::agent::{self, AgentError};
use crate::backend::{self, BackendError};
use crate::config::BackendKind;
use crate::config::{self, Config};
use crate::secret::SecretBuf;

pub enum ResolveOutcome {
    Found(SecretBuf),
    NotFound,
    /// Native backend only: the agent's vault is locked.
    Locked,
    Error(String),
}

pub struct Resolver {
    cfg: Config,
    agent_sock: std::path::PathBuf,
    client: Option<agent::Client>,
}

impl Resolver {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        Ok(Resolver {
            cfg,
            agent_sock: config::agent_sock_path()?,
            client: None,
        })
    }

    fn client(&mut self) -> Result<&mut agent::Client, String> {
        if self.client.is_none() {
            let c = agent::connect_or_start(&self.agent_sock).map_err(|e| e.to_string())?;
            self.client = Some(c);
        }
        Ok(self.client.as_mut().unwrap())
    }

    pub fn resolve(&mut self, alias: &str) -> ResolveOutcome {
        match self.cfg.backend {
            BackendKind::Native => {
                let client = match self.client() {
                    Ok(c) => c,
                    Err(e) => return ResolveOutcome::Error(e),
                };
                match client.get(alias) {
                    Ok(buf) => ResolveOutcome::Found(buf),
                    Err(AgentError::Locked) => ResolveOutcome::Locked,
                    Err(AgentError::NotFound(_)) => ResolveOutcome::NotFound,
                    Err(e) => ResolveOutcome::Error(e.to_string()),
                }
            }
            _ => match backend::get_via_config(&self.cfg, alias, None) {
                Ok(buf) => ResolveOutcome::Found(buf),
                Err(BackendError::NotFound(_)) => ResolveOutcome::NotFound,
                Err(e) => ResolveOutcome::Error(e.to_string()),
            },
        }
    }

    pub fn unlock(&mut self, passphrase: &SecretString) -> Result<(), String> {
        let client = self.client()?;
        client.unlock(passphrase).map_err(|e| e.to_string())
    }
}
