//! IRONCLAW Telemetry Collectors
//!
//! Each collector implements the `Collector` trait. All collectors are driven
//! by the live policy — when policy changes, collectors reconfigure without restart.

pub mod simulator;

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

/// Build the list of active collectors based on the current platform.
/// On Windows: real ETW/EventLog collectors + simulator fallback.
/// On Linux/macOS: simulator only (for dev/demo purposes).
pub fn build_collectors() -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = Vec::new();

    #[cfg(windows)]
    {
        collectors.push(Box::new(windows_sysmon::SysmonCollector::new()));
        collectors.push(Box::new(windows_eventlog::SecurityLogCollector::new()));
        collectors.push(Box::new(windows_powershell::PowerShellCollector::new()));
    }

    // Simulator only included on non-Windows platforms.
    // On Windows, we rely entirely on real collectors.
    #[cfg(not(windows))]
    collectors.push(Box::new(simulator::SimulatorCollector::new()));

    collectors
}
