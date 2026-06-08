//! Windows Sysmon event collector.
//! Reads from the Microsoft-Windows-Sysmon/Operational event log channel.
//! Event IDs collected are driven by the live policy (collection.sysmon_events).
//!
//! Policy fields honored:
//!   - `collection.sysmon_events`      — the allow-list of Sysmon EventIDs
//!   - `collection.dll_events_enabled` — gates EventID 7 (ImageLoad / DLL load)
//!   - `collection.file_events.enabled` — gates the file-system EventIDs (2, 11, 15, 23)
//!   - `collection.file_events.path_filters` — substring/glob match on TargetFilename

#![cfg(windows)]

use crate::win_util::{get_latest_record_id, parse_event_xml, query_new_events};
use crate::Collector;
use ironclaw_core::{
    event::{Event, EventType},
    policy::Policy,
};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, RwLock};

/// Sysmon EventIDs that represent file-system activity.
const FILE_EVENT_IDS: &[u32] = &[2, 11, 15, 23];

pub struct SysmonCollector;

impl SysmonCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Collector for SysmonCollector {
    fn name(&self) -> &str {
        "windows_sysmon"
    }

    async fn run(&self, tx: Sender<Event>, policy: Arc<RwLock<Policy>>) -> anyhow::Result<()> {
        log::info!("[sysmon] Starting Sysmon collector");

        let channel = "Microsoft-Windows-Sysmon/Operational";
        let mut last_record_id = unsafe { get_latest_record_id(channel) };
        log::info!("[sysmon] Seeded last_record_id = {}", last_record_id);

        let mut has_warned = false;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            // Snapshot the slices of the policy we need so we don't hold the
            // RwLock across the blocking Windows query below.
            let (sysmon_ids, dll_enabled, file_events_enabled, path_filters) = {
                let pol = policy.read().await;
                (
                    pol.collection.sysmon_events.clone(),
                    pol.collection.dll_events_enabled,
                    pol.collection.file_events.enabled,
                    pol.collection.file_events.path_filters.clone(),
                )
            };

            let mut active_ids = sysmon_ids;
            if !dll_enabled {
                active_ids.retain(|&id| id != 7);
            }
            if !file_events_enabled {
                active_ids.retain(|&id| !FILE_EVENT_IDS.contains(&id));
            }

            if active_ids.is_empty() {
                continue;
            }

            // Use a simple XPath that only filters by RecordID — compound EventID
            // OR-chains can silently fail on some Windows versions. We filter by
            // EventID in Rust after parsing.
            let xpath = format!("*[System[EventRecordID > {}]]", last_record_id);
            log::debug!(
                "[sysmon] Querying with XPath: {} on channel {}",
                xpath,
                channel
            );
            let active_ids_clone = active_ids.clone();

            // Execute blocking Windows API call in spawn_blocking to avoid blocking tokio executor
            let xpath_clone = xpath.to_string();
            let query_res = tokio::task::spawn_blocking(move || unsafe {
                query_new_events(channel, &xpath_clone)
            })
            .await;

            match query_res {
                Ok(Ok(xml_events)) => {
                    has_warned = false; // Reset warning state on success
                    if !xml_events.is_empty() {
                        log::debug!("[sysmon] Found {} raw Sysmon XML events", xml_events.len());
                    }
                    for xml in xml_events {
                        let Some(event) =
                            parse_event_xml(&xml, "windows-agent", EventType::Process, "sysmon")
                        else {
                            log::debug!("[sysmon] Failed to parse XML as Sysmon event");
                            continue;
                        };

                        let rec_id = event
                            .payload
                            .as_object()
                            .and_then(|p| p.get("event_record_id"))
                            .and_then(|v| v.as_u64());

                        // Filter by the EventIDs enabled in the active policy.
                        if let Some(eid) = event.event_id {
                            if !active_ids_clone.contains(&eid) {
                                log::debug!(
                                    "[sysmon] event ID={} skipped by policy",
                                    eid
                                );
                                if let Some(r) = rec_id {
                                    if r > last_record_id {
                                        last_record_id = r;
                                    }
                                }
                                continue;
                            }

                            // For file events, apply path_filters if configured.
                            if FILE_EVENT_IDS.contains(&eid)
                                && !path_filters.is_empty()
                                && !event_matches_path_filters(&event, &path_filters)
                            {
                                log::debug!(
                                    "[sysmon] file event ID={} skipped by path_filters",
                                    eid
                                );
                                if let Some(r) = rec_id {
                                    if r > last_record_id {
                                        last_record_id = r;
                                    }
                                }
                                continue;
                            }
                        }

                        if let Some(r) = rec_id {
                            if r > last_record_id {
                                last_record_id = r;
                            }
                        }
                        log::debug!(
                            "[sysmon] event ID={:?} record_id={:?} -> agent channel",
                            event.event_id,
                            rec_id
                        );
                        if let Err(e) = tx.send(event).await {
                            log::warn!("[sysmon] Event channel closed: {}", e);
                            return Ok(());
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

/// Return true if any of the configured patterns matches the event's file path
/// (typically the `TargetFilename` payload field, falling back to `Image`).
fn event_matches_path_filters(event: &Event, patterns: &[String]) -> bool {
    let path = event
        .payload
        .get("TargetFilename")
        .or_else(|| event.payload.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if path.is_empty() {
        return false;
    }
    patterns.iter().any(|p| glob_match(p, path))
}

/// Lightweight case-insensitive glob matcher. Supports `*` (zero or more chars)
/// and `?` (single char). Sufficient for the Windows path patterns we get from
/// policy (e.g. `C:\\Windows\\Temp\\*`). Pulling in `globset` is overkill here.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    glob_match_inner(&p, 0, &t, 0)
}

fn glob_match_inner(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    while pi < p.len() {
        match p[pi] {
            '*' => {
                // Collapse runs of '*' and try every remaining suffix of t.
                while pi < p.len() && p[pi] == '*' {
                    pi += 1;
                }
                if pi == p.len() {
                    return true;
                }
                for k in ti..=t.len() {
                    if glob_match_inner(p, pi, t, k) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if ti >= t.len() {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            c => {
                if ti >= t.len() || t[ti] != c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
    ti == t.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn matches_trailing_wildcard() {
        assert!(glob_match("C:\\Windows\\Temp\\*", "C:\\Windows\\Temp\\foo.exe"));
        assert!(glob_match(
            "C:\\Windows\\Temp\\*",
            "C:\\windows\\temp\\sub\\bar.exe"
        ));
        assert!(!glob_match("C:\\Windows\\Temp\\*", "C:\\Users\\ahmed\\a.txt"));
    }

    #[test]
    fn matches_leading_wildcard() {
        assert!(glob_match("*.exe", "C:\\foo\\bar.exe"));
        assert!(!glob_match("*.exe", "C:\\foo\\bar.dll"));
    }

    #[test]
    fn matches_question_mark() {
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }
}
