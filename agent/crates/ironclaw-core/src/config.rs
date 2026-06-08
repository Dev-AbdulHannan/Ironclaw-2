//! Static agent configuration — read from environment variables with safe defaults.
//! This is the startup config (paths, URLs, intervals).
//! Runtime behavior is controlled by Policy (received from HQ).

use crate::identity::{default_role, validate_role};
use std::path::PathBuf;

/// Full agent startup configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub backend: BackendConfig,
    pub paths: PathsConfig,
    pub buffer: BufferConfig,
    /// Initial role used only at first enrollment. After enrollment the role
    /// is persisted in identity.json and the env var is ignored on subsequent
    /// starts (backend remains the authoritative source).
    pub initial_role: String,
    /// Group/department this agent belongs to (e.g., "hr", "engineering", "finance").
    /// Sent on every heartbeat and registration. Not persisted in identity.json.
    pub group: String,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            backend: BackendConfig::from_env(),
            paths: PathsConfig::from_env(),
            buffer: BufferConfig::from_env(),
            initial_role: load_initial_role(),
            group: load_group(),
        }
    }
}

fn load_initial_role() -> String {
    match std::env::var("IRONCLAW_ROLE") {
        Ok(v) => match validate_role(&v) {
            Ok(()) => v,
            Err(e) => {
                log::warn!(
                    "IRONCLAW_ROLE='{}' invalid ({}). Falling back to '{}'.",
                    v,
                    e,
                    default_role()
                );
                default_role()
            }
        },
        Err(_) => default_role(),
    }
}

fn load_group() -> String {
    std::env::var("IRONCLAW_GROUP").unwrap_or_else(|_| "default".to_string())
}

/// Backend connectivity settings.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// Base URL of the HQ backend (e.g. http://192.168.122.1:8000)
    pub url: String,
    /// Heartbeat interval in seconds (default: 60)
    pub heartbeat_interval_secs: u64,
    /// Max retry attempts for HTTP calls
    pub max_retries: u32,
    /// Base backoff delay in seconds
    pub retry_delay_secs: u64,
    /// HTTP request timeout in seconds
    pub timeout_secs: u64,
}

impl BackendConfig {
    fn from_env() -> Self {
        Self {
            url: std::env::var("IRONCLAW_BACKEND_URL")
                .unwrap_or_else(|_| "http://192.168.100.115:8000".to_string()),
            heartbeat_interval_secs: env_u64("IRONCLAW_HEARTBEAT_INTERVAL", 60),
            max_retries: env_u64("IRONCLAW_MAX_RETRIES", 3) as u32,
            retry_delay_secs: env_u64("IRONCLAW_RETRY_DELAY", 5),
            timeout_secs: env_u64("IRONCLAW_TIMEOUT", 30),
        }
    }

    pub fn register_url(&self) -> String {
        format!("{}/api/v1/agents/register", self.url)
    }

    pub fn heartbeat_url(&self, agent_id: &str) -> String {
        format!("{}/api/v1/agents/{}/heartbeat", self.url, agent_id)
    }

    pub fn policy_url(&self, agent_id: &str, current_version: u64) -> String {
        format!(
            "{}/api/v1/agents/{}/policy?current_version={}",
            self.url, agent_id, current_version
        )
    }

    pub fn events_url(&self, agent_id: &str) -> String {
        format!("{}/api/v1/agents/{}/events", self.url, agent_id)
    }
}

/// File system paths used by the agent.
#[derive(Debug, Clone)]
pub struct PathsConfig {
    /// Path to identity.json
    pub identity_path: PathBuf,
    /// Path to policy.json (persisted active policy)
    pub policy_path: PathBuf,
    /// Directory for disk spool files
    pub spool_dir: PathBuf,
}

impl PathsConfig {
    fn from_env() -> Self {
        let state_dir = std::env::var("IRONCLAW_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_state_dir());

        // Allow individual overrides for backward compatibility
        let identity_path = std::env::var("IRONCLAW_IDENTITY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_dir.join("identity.json"));

        let policy_path = std::env::var("IRONCLAW_POLICY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_dir.join("policy.json"));

        let spool_dir = std::env::var("IRONCLAW_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_dir.join("spool"));

        Self {
            identity_path,
            policy_path,
            spool_dir,
        }
    }
}

fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from("C:\\ProgramData\\Ironclaw");
    #[cfg(not(windows))]
    return PathBuf::from("./ironclaw-state");
}

/// In-memory and on-disk buffer settings.
#[derive(Debug, Clone)]
pub struct BufferConfig {
    /// Max events held in memory before overflow to disk
    pub memory_capacity: usize,
    /// Max events per batch sent to backend
    pub batch_size: usize,
    /// Max seconds before sending a partial batch
    pub batch_timeout_secs: u64,
    /// Disk spool toggle and (future) cap. Currently: > 0 enables disk overflow,
    /// 0 disables. Size limit itself is not yet enforced.
    pub spool_max_mb: u64,
}

impl BufferConfig {
    fn from_env() -> Self {
        Self {
            memory_capacity: env_u64("IRONCLAW_BUFFER_CAPACITY", 10_000) as usize,
            batch_size: env_u64("IRONCLAW_BATCH_SIZE", 500) as usize,
            batch_timeout_secs: env_u64("IRONCLAW_BATCH_TIMEOUT", 5),
            spool_max_mb: env_u64("IRONCLAW_SPOOL_MAX_MB", 512),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
