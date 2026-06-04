//! Agent identity — keypair, agent_id, backend public key, and persisted policy.
//! Loaded from and saved to identity.json on the local filesystem.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::policy::Policy;

/// The agent's complete identity, persisted to disk after enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Permanent UUID assigned by HQ on registration.
    pub agent_id: String,
    /// Base64-encoded Ed25519 private (signing) key.
    pub private_key_b64: String,
    /// Base64-encoded Ed25519 public key (sent to HQ during registration).
    pub public_key_b64: String,
    /// Base64-encoded Ed25519 public key of the backend (for future verification).
    pub backend_public_key_b64: String,
    /// The policy that was active when this identity was last saved.
    pub policy: Policy,
}

/// A freshly generated Ed25519 keypair (before enrollment).
pub struct GeneratedKeypair {
    pub signing_key: SigningKey,
    pub public_key_b64: String,
}

/// Generate a new Ed25519 keypair using the OS secure random source.
pub fn generate_keypair() -> GeneratedKeypair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let public_key_b64 = BASE64.encode(verifying_key.as_bytes());
    GeneratedKeypair {
        signing_key,
        public_key_b64,
    }
}

/// Load an existing identity from disk. Returns None if the file doesn't exist.
pub fn load_identity(path: &Path) -> crate::Result<Option<Identity>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(path)?;
    let identity: Identity = serde_json::from_str(&data)?;
    Ok(Some(identity))
}

/// Atomically save the identity to disk.
/// Writes to a temp file first, then renames to prevent corruption.
pub fn save_identity(identity: &Identity, path: &Path) -> crate::Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(identity)?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Registration request body sent to POST /api/v1/agents/register.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub os_info: OsInfo,
    pub public_key: String,
    pub os_version: String,
    pub agent_version: String,
}

/// OS metadata included in the registration request.
#[derive(Debug, Serialize)]
pub struct OsInfo {
    pub os: String,
    pub version: String,
    pub arch: String,
}

/// Response from POST /api/v1/agents/register.
#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub backend_public_key: String,
    pub policy: Policy,
}

/// Collect current host OS info.
pub fn collect_os_info() -> OsInfo {
    let _sys = sysinfo::System::new();
    OsInfo {
        os: sysinfo::System::name().unwrap_or_else(|| "Unknown".to_string()),
        version: sysinfo::System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        arch: std::env::consts::ARCH.to_string(),
    }
}
