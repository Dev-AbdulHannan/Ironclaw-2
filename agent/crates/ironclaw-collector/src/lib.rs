//! IRONCLAW Telemetry Collectors
//!
//! Each collector implements the `Collector` trait. All collectors are driven
//! by the live policy — when policy changes, collectors reconfigure without restart.
//!
//! Windows-only: the agent ships real ETW/EventLog collectors (Sysmon, Security
//! Event Log, PowerShell). Non-Windows builds compile but produce no telemetry.

#[cfg(windows)]
pub mod win_util;
#[cfg(windows)]
pub mod windows_eventlog;
#[cfg(windows)]
pub mod windows_powershell;
#[cfg(windows)]
pub mod windows_sysmon;

use ironclaw_core::{event::Event, policy::Policy};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

/// The `Collector` trait — every telemetry source implements this.
#[async_trait::async_trait]
pub trait Collector: Send + Sync {
    /// Human-readable name of this collector.
    fn name(&self) -> &str;

    /// Run the collector. Sends events to `tx`. Runs until the policy watch
    /// signals shutdown or an unrecoverable error occurs.
    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()>;
}

/// Build the list of active collectors. The agent is Windows-only at runtime:
/// non-Windows builds return an empty collector set and log a warning so the
/// rest of the agent (heartbeat, shipper, identity) can still be exercised.
pub fn build_collectors() -> Vec<Box<dyn Collector>> {
    #[cfg(windows)]
    {
        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(windows_sysmon::SysmonCollector::new()),
            Box::new(windows_eventlog::SecurityLogCollector::new()),
            Box::new(windows_powershell::PowerShellCollector::new()),
        ];
        collectors
    }

    #[cfg(not(windows))]
    {
        log::warn!(
            "ironclaw-collector: no collectors registered — this build targets a non-Windows \
             platform and the agent only collects telemetry on Windows."
        );
        Vec::new()
    }
}
