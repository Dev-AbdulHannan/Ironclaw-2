//! Windows Security Event Log collector.
//! Reads from the Security channel. Event IDs driven by policy.collection.security_events.

#![cfg(windows)]

use crate::win_util::{get_latest_record_id, parse_event_xml, query_new_events};
use crate::Collector;
use ironclaw_core::{
    event::{Event, EventType},
    policy::Policy,
};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

pub struct SecurityLogCollector;

impl SecurityLogCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Collector for SecurityLogCollector {
    fn name(&self) -> &str {
        "windows_security_log"
    }

    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()> {
        log::info!("[security_log] Starting Security Event Log collector");

        let channel = "Security";
        let mut last_record_id = unsafe { get_latest_record_id(channel) };
        log::info!("[security_log] Seeded last_record_id = {}", last_record_id);

        let mut has_warned = false;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            let enabled_ids = {
                let pol = policy.read().await;
                pol.collection.security_events.clone()
            };

            if enabled_ids.is_empty() {
                continue;
            }

            // Simple XPath: only filter by RecordID. Compound EventID OR-chains
            // can silently fail on some Windows versions; filter in Rust instead.
            let xpath = format!("*[System[EventRecordID > {}]]", last_record_id);
            let enabled_ids_clone = enabled_ids.clone();

            let xpath_clone = xpath.to_string();
            let query_res = tokio::task::spawn_blocking(move || unsafe {
                query_new_events(channel, &xpath_clone)
            })
            .await;

            match query_res {
                Ok(Ok(xml_events)) => {
                    has_warned = false;
                    for xml in xml_events {
                        if let Some(event) =
                            parse_event_xml(&xml, "windows-agent", EventType::Auth, "security_log")
                        {
                            // Filter by EventIDs enabled in the active policy
                            if let Some(eid) = event.event_id {
                                if !enabled_ids_clone.contains(&eid) {
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
                                log::warn!("[security_log] Event channel closed: {}", e);
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    if !has_warned {
                        log::warn!("[security_log] EvtQuery failed: {}. (Note: The agent must run as Administrator to read the Security Event Log)", e);
                        has_warned = true;
                    }
                }
                Err(e) => {
                    log::error!("[security_log] JoinError on query task: {}", e);
                }
            }
        }
    }
}
