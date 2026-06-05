//! Windows PowerShell Script Block Log collector.
//! Reads from Microsoft-Windows-PowerShell/Operational (Event ID 4104).
//! Only active when policy.collection.powershell_logging == true.

#![cfg(windows)]

use crate::win_util::{get_latest_record_id, parse_event_xml, query_new_events};
use crate::Collector;
use ironclaw_core::{
    event::{Event, EventType},
    policy::Policy,
};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

pub struct PowerShellCollector;

impl PowerShellCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Collector for PowerShellCollector {
    fn name(&self) -> &str {
        "windows_powershell"
    }

    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()> {
        log::info!("[powershell] Starting PowerShell collector");

        let channel = "Microsoft-Windows-PowerShell/Operational";
        let mut last_record_id = unsafe { get_latest_record_id(channel) };
        log::info!("[powershell] Seeded last_record_id = {}", last_record_id);

        let mut has_warned = false;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            let enabled = {
                let pol = policy.read().await;
                pol.collection.powershell_logging
            };

            if !enabled {
                continue;
            }

            // Simple XPath: only filter by RecordID
            let xpath = format!("*[System[EventRecordID > {}]]", last_record_id);

            let xpath_clone = xpath.to_string();
            let query_res = tokio::task::spawn_blocking(move || unsafe {
                query_new_events(channel, &xpath_clone)
            })
            .await;

            match query_res {
                Ok(Ok(xml_events)) => {
                    has_warned = false;
                    for xml in xml_events {
                        if let Some(event) = parse_event_xml(
                            &xml,
                            "windows-agent",
                            EventType::PowerShell,
                            "powershell",
                        ) {
                            // Only process Script Block Logging (Event ID 4104)
                            if event.event_id != Some(4104) {
                                if let Some(payload_obj) = event.payload.as_object() {
                                    if let Some(rec_val) = payload_obj.get("event_record_id") {
                                        if let Some(rec_id) = rec_val.as_u64() {
                                            if rec_id > last_record_id {
                                                last_record_id = rec_id;
                                            }
                                        }
                                    }
                                }
                                continue;
                            }
                            if let Some(payload_obj) = event.payload.as_object() {
                                if let Some(rec_val) = payload_obj.get("event_record_id") {
                                    if let Some(rec_id) = rec_val.as_u64() {
                                        if rec_id > last_record_id {
                                            last_record_id = rec_id;
                                        }
                                    }
                                }
                            }
                            if let Err(e) = tx.send(event).await {
                                log::warn!("[powershell] Event channel closed: {}", e);
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    if !has_warned {
                        log::warn!("[powershell] EvtQuery failed: {}. (Note: PowerShell operational logging must be enabled and active)", e);
                        has_warned = true;
                    }
                }
                Err(e) => {
                    log::error!("[powershell] JoinError on query task: {}", e);
                }
            }
        }
    }
}
