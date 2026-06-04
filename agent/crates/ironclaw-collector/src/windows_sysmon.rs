//! Windows Sysmon event collector.
//! Reads from the Microsoft-Windows-Sysmon/Operational event log channel.
//! Event IDs collected are driven by the live policy (collection.sysmon_events).

#![cfg(windows)]

use crate::Collector;
use crate::win_util::{get_latest_record_id, query_new_events, parse_event_xml};
use ironclaw_core::{
    event::{Event, EventType},
    policy::Policy,
};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

pub struct SysmonCollector;

impl SysmonCollector {
    pub fn new() -> Self { Self }
}

#[async_trait::async_trait]
impl Collector for SysmonCollector {
    fn name(&self) -> &str { "windows_sysmon" }

    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()> {
        log::info!("[sysmon] Starting Sysmon collector");
        
        let channel = "Microsoft-Windows-Sysmon/Operational";
        let mut last_record_id = unsafe { get_latest_record_id(channel) };
        log::info!("[sysmon] Seeded last_record_id = {}", last_record_id);

        let mut has_warned = false;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            
            let (ids, dll_enabled) = {
                let pol = policy.read().await;
                (pol.collection.sysmon_events.clone(), pol.collection.dll_events_enabled)
            };

            let mut active_ids = ids;
            if !dll_enabled {
                active_ids.retain(|&id| id != 7);
            }

            if active_ids.is_empty() {
                continue;
            }

            // Use a simple XPath that only filters by RecordID — compound EventID
            // OR-chains can silently fail on some Windows versions. We filter by
            // EventID in Rust after parsing.
            let xpath = format!("*[System[EventRecordID > {}]]", last_record_id);
            log::info!("[sysmon] Querying with XPath: {} on channel {}", xpath, channel);
            let active_ids_clone = active_ids.clone();

            // Execute blocking Windows API call in spawn_blocking to avoid blocking tokio executor
            let xpath_clone = xpath.to_string();
            let query_res = tokio::task::spawn_blocking(move || {
                unsafe { query_new_events(channel, &xpath_clone) }
            }).await;

            match query_res {
                Ok(Ok(xml_events)) => {
                    has_warned = false; // Reset warning state on success
                    if !xml_events.is_empty() {
                        log::info!("[sysmon] Found {} raw Sysmon XML events", xml_events.len());
                    }
                    for xml in xml_events {
                        if let Some(event) = parse_event_xml(&xml, "windows-agent", EventType::Process, "sysmon") {
                            log::info!("[sysmon] Parsed Sysmon event: ID={:?}, record_id={:?}, type={:?}", event.event_id, event.payload.get("event_record_id"), event.event_type);
                            // Filter by the EventIDs enabled in the active policy
                            if let Some(eid) = event.event_id {
                                if !active_ids_clone.contains(&eid) {
                                    log::info!("[sysmon] Sysmon event ID={} skipped by policy (not in active_ids={:?})", eid, active_ids_clone);
                                    // Advance watermark even for skipped events
                                    if let Some(payload_obj) = event.payload.as_object() {
                                        if let Some(rec_val) = payload_obj.get("event_record_id") {
                                            if let Some(rec_id) = rec_val.as_u64() {
                                                if rec_id > last_record_id { last_record_id = rec_id; }
                                            }
                                        }
                                    }
                                    continue;
                                }
                            }
                            // Extract EventRecordID to advance our watermark
                            if let Some(payload_obj) = event.payload.as_object() {
                                if let Some(rec_val) = payload_obj.get("event_record_id") {
                                    if let Some(rec_id) = rec_val.as_u64() {
                                        if rec_id > last_record_id {
                                            last_record_id = rec_id;
                                        }
                                    }
                                }
                            }
                            log::info!("[sysmon] Sending Sysmon event to agent channel, advancing last_record_id to {}", last_record_id);
                            if let Err(e) = tx.send(event).await {
                                log::warn!("[sysmon] Event channel closed: {}", e);
                                return Ok(());
                            }
                        } else {
                            log::info!("[sysmon] Failed to parse XML as Sysmon event. XML:\n{}", xml);
                        }
                    }
                }
                Ok(Err(e)) => {
                    if !has_warned {
                        log::warn!("[sysmon] EvtQuery failed: {}. (Note: Sysmon must be installed and running to collect Sysmon events)", e);
                        has_warned = true;
                    }
                }
                Err(e) => {
                    log::error!("[sysmon] JoinError on query task: {}", e);
                }
            }
        }
    }
}
