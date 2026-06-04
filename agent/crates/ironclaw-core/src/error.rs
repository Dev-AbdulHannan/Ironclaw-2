//! Unified error type for the IRONCLAW agent.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Policy hash mismatch: expected {expected}, got {got}")]
    PolicyHashMismatch { expected: String, got: String },

    #[error("Policy validation failed: {0}")]
    PolicyInvalid(String),

    #[error("Identity not found at {0}")]
    IdentityNotFound(String),

    #[error("Backend error ({status}): {body}")]
    Backend { status: u16, body: String },

    #[error("Buffer full: {0}")]
    BufferFull(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

// reqwest is used in transport crate — add a compatible From here via anyhow bridge
pub type Result<T> = std::result::Result<T, Error>;
