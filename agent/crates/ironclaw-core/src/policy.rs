//! Policy document — the "post orders" from HQ (§6 of the Engineering Task Brief).
//!
//! This is the exact schema the backend sends. The agent receives it, validates it,
//! and applies it to live behavior. The agent never invents policy fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The complete policy document assigned by HQ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Monotonically increasing version number. Increases on every change at HQ.
    pub version: u64,
    /// SHA-256 fingerprint of the compiled policy ("sha256:<hex>").
    /// Agent must verify this before applying.
    #[serde(default)]
    pub hash: String,
    /// Hard safety rules — invariants can never be disabled in the field.
    pub invariants: PolicyInvariants,
    /// What telemetry to collect.
    pub collection: PolicyCollection,
    /// Network and event rate limits.
    pub rate_limits: PolicyRateLimits,
    /// Lightweight on-site detection filters.
    #[serde(default)]
    pub detection_filters: Vec<DetectionFilter>,
}

impl Policy {
    /// Compute the SHA-256 hash of the policy body (excluding the hash field itself).
    /// Used to verify integrity of received policies.
    pub fn compute_hash(&self) -> String {
        // Serialize without the hash field to compute it
        let mut copy = self.clone();
        copy.hash = String::new();
        let canonical = serde_json::to_string(&copy).unwrap_or_default();
        let digest = Sha256::digest(canonical.as_bytes());
        format!("sha256:{}", hex::encode(digest))
    }

    /// Validate the policy hash. Returns error if hash doesn't match.
    /// If the hash field is empty (backend didn't set it), validation passes — 
    /// this is for backward compatibility with M1 default policies.
    pub fn validate_hash(&self) -> Result<(), String> {
        if self.hash.is_empty() {
            return Ok(());
        }
        let computed = self.compute_hash();
        if computed != self.hash {
            return Err(format!(
                "Policy hash mismatch: received '{}', computed '{}'",
                self.hash, computed
            ));
        }
        Ok(())
    }

    /// Enforce invariants: certain fields can never be disabled, even if the
    /// incoming policy tries to set them to false.
    pub fn enforce_invariants(&mut self) {
        self.invariants.lsass_access.enabled = true;
        self.invariants.unsigned_drivers.enabled = true;
        self.invariants.credential_dumping.enabled = true;
    }

    /// Compute a human-readable diff vs another policy for logging.
    pub fn diff_summary(&self, other: &Policy) -> Vec<String> {
        let mut changes = Vec::new();
        if self.version != other.version {
            changes.push(format!("version: {} → {}", self.version, other.version));
        }
        if self.collection.dll_events_enabled != other.collection.dll_events_enabled {
            changes.push(format!(
                "dll_events_enabled: {} → {}",
                self.collection.dll_events_enabled, other.collection.dll_events_enabled
            ));
        }
        if self.collection.powershell_logging != other.collection.powershell_logging {
            changes.push(format!(
                "powershell_logging: {} → {}",
                self.collection.powershell_logging, other.collection.powershell_logging
            ));
        }
        if self.rate_limits.events_per_second != other.rate_limits.events_per_second {
            changes.push(format!(
                "events_per_second: {} → {}",
                self.rate_limits.events_per_second, other.rate_limits.events_per_second
            ));
        }
        if self.collection.sysmon_events != other.collection.sysmon_events {
            changes.push(format!(
                "sysmon_events: {:?} → {:?}",
                self.collection.sysmon_events, other.collection.sysmon_events
            ));
        }
        changes
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            hash: String::new(),
            invariants: PolicyInvariants::default(),
            collection: PolicyCollection::default(),
            rate_limits: PolicyRateLimits::default(),
            detection_filters: Vec::new(),
        }
    }
}

/// Hard safety rules — the agent enforces these regardless of what the rest of the policy says.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInvariants {
    pub lsass_access: InvariantRule,
    pub unsigned_drivers: InvariantRule,
    pub credential_dumping: InvariantRule,
}

impl Default for PolicyInvariants {
    fn default() -> Self {
        Self {
            lsass_access: InvariantRule { enabled: true },
            unsigned_drivers: InvariantRule { enabled: true },
            credential_dumping: InvariantRule { enabled: true },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantRule {
    pub enabled: bool,
}

/// Telemetry collection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyCollection {
    /// Sysmon event IDs to collect (e.g. [1,3,7,8,10,11,12,13,22,23])
    pub sysmon_events: Vec<u32>,
    /// Windows Security event IDs to collect (e.g. [4624,4625,4672,4688,4720])
    pub security_events: Vec<u32>,
    /// Enable PowerShell script block logging collection
    pub powershell_logging: bool,
    /// Enable DLL load event collection (Sysmon event 7)
    pub dll_events_enabled: bool,
    /// File event collection settings
    pub file_events: FileEventsConfig,
}

impl Default for PolicyCollection {
    fn default() -> Self {
        Self {
            sysmon_events: vec![1, 3, 7, 8, 10, 11, 12, 13, 22, 23],
            security_events: vec![4624, 4625, 4672, 4688, 4720],
            powershell_logging: true,
            dll_events_enabled: false,
            file_events: FileEventsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEventsConfig {
    pub enabled: bool,
    pub path_filters: Vec<String>,
}

impl Default for FileEventsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path_filters: vec!["C:\\Windows\\Temp\\*".to_string()],
        }
    }
}

/// Event rate limits to protect the network and backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRateLimits {
    pub events_per_second: u32,
    pub network_events_per_second: u32,
}

impl Default for PolicyRateLimits {
    fn default() -> Self {
        Self {
            events_per_second: 1000,
            network_events_per_second: 200,
        }
    }
}

/// Lightweight on-site detection filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFilter {
    pub name: String,
    /// Field to match against (e.g. "cmdline")
    #[serde(rename = "match")]
    pub match_field: String,
    /// Pattern to search for
    pub pattern: String,
    /// Action on match ("flag", "block")
    pub action: String,
}

/// Response from the policy fetch endpoint.
#[derive(Debug, Deserialize)]
pub struct PolicyFetchResponse {
    pub status: String,
    pub policy: Option<Policy>,
}

impl PolicyFetchResponse {
    pub fn is_current(&self) -> bool {
        self.status == "current"
    }
}
