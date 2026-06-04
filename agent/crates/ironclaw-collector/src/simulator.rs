//! Cross-platform event simulator for demo and testing.
//!
//! Generates realistic synthetic events driven by the live policy config.
//! Used on Linux/macOS builds, and supplements real collectors on Windows.
//! Respects the same policy flags as real collectors (dll_events_enabled, etc.).

use crate::Collector;
use ironclaw_core::{
    event::{Event, EventType},
    policy::Policy,
};
use rand::Rng;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

pub struct SimulatorCollector {
    agent_id: std::sync::OnceLock<String>,
}

impl SimulatorCollector {
    pub fn new() -> Self {
        Self {
            agent_id: std::sync::OnceLock::new(),
        }
    }
}

#[async_trait::async_trait]
impl Collector for SimulatorCollector {
    fn name(&self) -> &str {
        "simulator"
    }

    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()> {
        // Retrieve agent_id from the first event or use placeholder
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));
        let agent_id = "simulator-agent";
        loop {
            interval.tick().await;

            let pol = policy.read().await;
            
            let events: Vec<_> = {
                // Create rng here so it's not held across await
                let mut rng = rand::thread_rng();
                let events_per_tick = rng.gen_range(1..=4_usize);

                (0..events_per_tick).filter_map(|_| {
                    generate_event(&pol, agent_id, &mut rng)
                }).collect()
            }; // rng is dropped here

            for ev in events {
                if tx.send(ev).await.is_err() {
                    // Channel closed — agent is shutting down
                    return Ok(());
                }
            }
        }
    }
}

fn generate_event(
    policy: &Policy,
    agent_id: &str,
    rng: &mut impl Rng,
) -> Option<Event> {
    // Choose event type based on policy settings
    let choices = build_choices(policy);
    if choices.is_empty() {
        return None;
    }

    let idx = rng.gen_range(0..choices.len());
    let (event_type, source, event_id, payload) = match choices[idx] {
        EventChoice::ProcessCreate => (
            EventType::Process,
            "sysmon",
            Some(1u32),
            json!({
                "process_name": pick(rng, &["powershell.exe","cmd.exe","notepad.exe","svchost.exe","explorer.exe"]),
                "pid": rng.gen_range(1000..65535u32),
                "ppid": rng.gen_range(100..1000u32),
                "cmdline": pick(rng, &["powershell.exe -NoProfile","cmd.exe /c whoami","notepad.exe C:\\temp\\file.txt"]),
                "user": pick(rng, &["SYSTEM","Administrator","IronClaw\\ahmed"]),
                "hash_sha256": format!("{:064x}", rng.gen::<u64>()),
            }),
        ),
        EventChoice::NetworkConnect => (
            EventType::Network,
            "sysmon",
            Some(3u32),
            json!({
                "process": pick(rng, &["chrome.exe","svchost.exe","powershell.exe"]),
                "dst_ip": format!("{}.{}.{}.{}", rng.gen_range(1..255u8), rng.gen_range(0..255u8), rng.gen_range(0..255u8), rng.gen_range(1..255u8)),
                "dst_port": pick(rng, &[80u16, 443, 8080, 53, 445]),
                "protocol": "tcp",
            }),
        ),
        EventChoice::DnsQuery => (
            EventType::Dns,
            "sysmon",
            Some(22u32),
            json!({
                "process": pick(rng, &["chrome.exe","svchost.exe","powershell.exe"]),
                "query": pick(rng, &["google.com","microsoft.com","windowsupdate.com","github.com"]),
                "result": format!("{}.{}.{}.{}", rng.gen_range(1..255u8), rng.gen_range(0..255u8), rng.gen_range(0..255u8), rng.gen_range(1..255u8)),
            }),
        ),
        EventChoice::AuthEvent => (
            EventType::Auth,
            "security_log",
            Some(*pick(rng, &[4624u32, 4625, 4672, 4688])),
            json!({
                "user": pick(rng, &["Administrator","ahmed","SYSTEM","Guest"]),
                "logon_type": rng.gen_range(2..12u32),
                "source_ip": "192.168.122.1",
                "success": rng.gen_bool(0.9),
            }),
        ),
        EventChoice::PowerShell => (
            EventType::PowerShell,
            "powershell",
            Some(4104u32),
            json!({
                "script_block": pick(rng, &[
                    "Get-Process",
                    "Invoke-WebRequest -Uri http://example.com",
                    "Get-ChildItem C:\\Windows\\Temp",
                    "Set-ExecutionPolicy RemoteSigned",
                ]),
                "path": pick(rng, &["<interactive>","C:\\Scripts\\init.ps1"]),
            }),
        ),
        EventChoice::DllLoad => (
            EventType::DriverLoad,
            "sysmon",
            Some(7u32),
            json!({
                "process": pick(rng, &["lsass.exe","svchost.exe","explorer.exe"]),
                "image_loaded": pick(rng, &["C:\\Windows\\System32\\ntdll.dll","C:\\Windows\\System32\\kernel32.dll"]),
                "signed": rng.gen_bool(0.85),
                "signature": pick(rng, &["Microsoft Corporation","(unsigned)",""]),
            }),
        ),
        EventChoice::FileEvent => (
            EventType::FileSystem,
            "sysmon",
            Some(11u32),
            json!({
                "process": pick(rng, &["explorer.exe","cmd.exe","powershell.exe"]),
                "path": pick(rng, &[
                    "C:\\Windows\\Temp\\tmp_payload.exe",
                    "C:\\Users\\ahmed\\Downloads\\setup.exe",
                    "C:\\Windows\\Temp\\output.txt",
                ]),
                "action": pick(rng, &["created","modified","deleted"]),
            }),
        ),
    };

    Some(Event::new(agent_id, event_type, source, event_id, payload))
}

enum EventChoice {
    ProcessCreate,
    NetworkConnect,
    DnsQuery,
    AuthEvent,
    PowerShell,
    DllLoad,
    FileEvent,
}

fn build_choices(policy: &Policy) -> Vec<EventChoice> {
    let mut choices = Vec::new();

    // Process events always enabled if sysmon_events includes event ID 1
    if policy.collection.sysmon_events.contains(&1) {
        choices.push(EventChoice::ProcessCreate);
    }
    // Network events: sysmon event 3
    if policy.collection.sysmon_events.contains(&3) {
        choices.push(EventChoice::NetworkConnect);
    }
    // DNS events: sysmon event 22
    if policy.collection.sysmon_events.contains(&22) {
        choices.push(EventChoice::DnsQuery);
    }
    // Auth events
    if !policy.collection.security_events.is_empty() {
        choices.push(EventChoice::AuthEvent);
    }
    // PowerShell
    if policy.collection.powershell_logging {
        choices.push(EventChoice::PowerShell);
    }
    // DLL events: only if explicitly enabled (sysmon event 7 + dll_events_enabled flag)
    if policy.collection.dll_events_enabled && policy.collection.sysmon_events.contains(&7) {
        choices.push(EventChoice::DllLoad);
    }
    // File events
    if policy.collection.file_events.enabled {
        choices.push(EventChoice::FileEvent);
    }

    choices
}

fn pick<'a, T>(rng: &mut impl Rng, items: &'a [T]) -> &'a T {
    &items[rng.gen_range(0..items.len())]
}
