#![cfg(windows)]

use ironclaw_core::event::{
    DnsInfo, Event, EventType, FileInfo, HostInfo, NetworkInfo, ProcessInfo, UserInfo,
};
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::*;

pub fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Return the last path component of a Windows path (after the last `\`).
fn win_basename(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or(path).to_string()
}

/// Return `Some(value)` when the field exists and is non-empty, else `None`.
fn opt_str(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Parse a port number from a JSON value that may be a string or integer.
fn opt_port(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u16> {
    map.get(key).and_then(|v| {
        v.as_u64()
            .map(|n| n as u16)
            .or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok()))
    })
}

/// Extract the hex SHA-256 digest from a Sysmon `Hashes` field.
/// Sysmon format: "SHA256=<hex>" or "MD5=<md5>,SHA256=<hex>,..."
fn extract_sha256(hashes: &str) -> Option<String> {
    hashes.split(',').find_map(|pair| {
        let pair = pair.trim();
        pair.strip_prefix("SHA256=")
            .or_else(|| pair.strip_prefix("sha256="))
            .map(|h| h.to_string())
    })
}

pub fn parse_event_xml(
    xml: &str,
    agent_id: &str,
    default_type: EventType,
    source: &str,
) -> Option<Event> {
    // Extract EventID
    let id_start = xml.find("<EventID>")? + 9;
    let id_end = xml[id_start..].find("</EventID>")?;
    let event_id: u32 = xml[id_start..id_start + id_end].parse().ok()?;

    // Extract SystemTime (can be SystemTime="xxx" or SystemTime='xxx')
    let time_start = if let Some(pos) = xml.find("SystemTime=\"") {
        pos + 12
    } else if let Some(pos) = xml.find("SystemTime='") {
        pos + 12
    } else {
        return None;
    };
    let quote_char = xml.chars().nth(time_start - 1)?;
    let time_end = xml[time_start..].find(quote_char)?;
    let timestamp = xml[time_start..time_start + time_end].to_string();

    // Extract EventRecordID (monotonically increasing ID per channel)
    let rec_start = xml.find("<EventRecordID>")? + 15;
    let rec_end = xml[rec_start..].find("</EventRecordID>")?;
    let record_id: u64 = xml[rec_start..rec_start + rec_end].parse().ok()?;

    // Extract Computer
    let comp_start = xml.find("<Computer>")? + 10;
    let comp_end = xml[comp_start..].find("</Computer>")?;
    let computer = xml[comp_start..comp_start + comp_end].to_string();

    // Extract Data Name="xyz" fields (can be Name="xyz" or Name='xyz')
    let mut payload = serde_json::Map::new();
    let mut search_pos = 0;
    while search_pos < xml.len() {
        let (_data_pos, name_start, quote_char) =
            if let Some(pos) = xml[search_pos..].find("<Data Name=\"") {
                (pos, search_pos + pos + 12, '"')
            } else if let Some(pos) = xml[search_pos..].find("<Data Name='") {
                (pos, search_pos + pos + 12, '\'')
            } else {
                break;
            };

        if let Some(name_end) = xml[name_start..].find(quote_char) {
            let name = &xml[name_start..name_start + name_end];
            let val_start = name_start + name_end + 2; // skip quote and '>'
            if let Some(val_end) = xml[val_start..].find("</Data>") {
                let value = &xml[val_start..val_start + val_end];
                payload.insert(
                    name.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
                search_pos = val_start + val_end + 7;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Include the Windows EventRecordID and system time in payload for tracking
    payload.insert(
        "event_record_id".to_string(),
        serde_json::Value::Number(record_id.into()),
    );
    payload.insert("computer".to_string(), serde_json::Value::String(computer));
    payload.insert(
        "system_time".to_string(),
        serde_json::Value::String(timestamp),
    );

    // Map Sysmon event IDs to canonical EventType variants (Dev B §7.8).
    let mut etype = default_type;
    if source == "sysmon" {
        etype = match event_id {
            1 => EventType::ProcessCreate,
            2 => EventType::FileCreateTime,
            3 => EventType::NetworkConnect,
            5 => EventType::ProcessTerminate,
            6 => EventType::DriverLoad,
            7 => EventType::ImageLoad,
            8 => EventType::RemoteThread,
            9 => EventType::RawDiskAccess,
            10 => EventType::ProcessAccess,
            11 => EventType::FileCreate,
            12 => EventType::RegistryCreateDelete,
            13 => EventType::RegistryValueSet,
            14 => EventType::RegistryCreateDelete,
            15 => EventType::FileStreamCreate,
            17 | 18 => EventType::Pipe,
            19 | 20 | 21 => EventType::WmiActivity,
            22 => EventType::DnsQuery,
            23 => EventType::FileDelete,
            24 => EventType::ClipboardAccess,
            _ => default_type,
        };
    }

    // Build canonical structured fields (§7.9 mapping).
    let host = opt_str(&payload, "computer").map(|name| HostInfo { name });

    let user = opt_str(&payload, "User").map(|raw| {
        if let Some(idx) = raw.find('\\') {
            UserInfo {
                domain: Some(raw[..idx].to_string()),
                name: raw[idx + 1..].to_string(),
            }
        } else {
            UserInfo { name: raw, domain: None }
        }
    });

    let (process, parent_process, file, network, dns) = match event_id {
        // ProcessCreate (1): process + parent_process
        1 => {
            let proc_info = Some(ProcessInfo {
                pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                path: opt_str(&payload, "Image"),
                command_line: opt_str(&payload, "CommandLine"),
                hash_sha256: payload
                    .get("Hashes")
                    .and_then(|v| v.as_str())
                    .and_then(|h| extract_sha256(h)),
            });
            let parent = Some(ProcessInfo {
                pid: opt_str(&payload, "ParentProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "ParentImage").map(|p| win_basename(&p)),
                path: opt_str(&payload, "ParentImage"),
                command_line: opt_str(&payload, "ParentCommandLine"),
                hash_sha256: None,
            });
            (proc_info, parent, None, None, None)
        }
        // ProcessTerminate (5): process only
        5 => {
            let proc_info = Some(ProcessInfo {
                pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                path: opt_str(&payload, "Image"),
                command_line: None,
                hash_sha256: None,
            });
            (proc_info, None, None, None, None)
        }
        // NetworkConnect (3): process + network
        3 => {
            let proc_info = Some(ProcessInfo {
                pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                path: opt_str(&payload, "Image"),
                command_line: None,
                hash_sha256: None,
            });
            let net = Some(NetworkInfo {
                src_ip: opt_str(&payload, "SourceIp"),
                src_port: opt_port(&payload, "SourcePort"),
                dst_ip: opt_str(&payload, "DestinationIp"),
                dst_port: opt_port(&payload, "DestinationPort"),
                protocol: opt_str(&payload, "Protocol"),
            });
            (proc_info, None, None, net, None)
        }
        // DnsQuery (22): process + dns
        22 => {
            let proc_info = Some(ProcessInfo {
                pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                path: opt_str(&payload, "Image"),
                command_line: None,
                hash_sha256: None,
            });
            let dns_info = Some(DnsInfo {
                query: opt_str(&payload, "QueryName"),
                query_type: opt_str(&payload, "QueryType"),
                response: opt_str(&payload, "QueryResults"),
            });
            (proc_info, None, None, None, dns_info)
        }
        // File events (2, 11, 15, 23): process + file
        2 | 11 | 15 | 23 => {
            let proc_info = Some(ProcessInfo {
                pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                path: opt_str(&payload, "Image"),
                command_line: None,
                hash_sha256: None,
            });
            let file_path = opt_str(&payload, "TargetFilename");
            let file_info = Some(FileInfo {
                name: file_path.as_deref().map(win_basename),
                path: file_path,
            });
            (proc_info, None, file_info, None, None)
        }
        // All other IDs: extract process fields where available
        _ => {
            let proc_info = if opt_str(&payload, "Image").is_some() {
                Some(ProcessInfo {
                    pid: opt_str(&payload, "ProcessId").and_then(|s| s.parse().ok()),
                    name: opt_str(&payload, "Image").map(|p| win_basename(&p)),
                    path: opt_str(&payload, "Image"),
                    command_line: opt_str(&payload, "CommandLine"),
                    hash_sha256: None,
                })
            } else {
                None
            };
            (proc_info, None, None, None, None)
        }
    };

    let mut event = Event::new(
        agent_id,
        etype,
        source,
        Some(event_id),
        serde_json::Value::Object(payload),
    );
    event.host = host;
    event.user = user;
    event.process = process;
    event.parent_process = parent_process;
    event.file = file;
    event.network = network;
    event.dns = dns;
    Some(event)
}

pub unsafe fn query_new_events(channel: &str, xpath_query: &str) -> anyhow::Result<Vec<String>> {
    let channel_w = to_utf16(channel);
    let xpath_w = to_utf16(xpath_query);

    let query_handle = match EvtQuery(
        None,
        PCWSTR::from_raw(channel_w.as_ptr()),
        PCWSTR::from_raw(xpath_w.as_ptr()),
        EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
    ) {
        Ok(h) => h,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "EvtQuery failed for channel '{}': {}",
                channel,
                e
            ))
        }
    };

    let mut event_handles = [0isize; 64];
    let mut returned = 0;
    let mut results = Vec::new();

    loop {
        let success = EvtNext(
            query_handle,
            &mut event_handles,
            500_u32, // timeout 500ms
            0,
            &mut returned,
        );

        if success.is_err() || returned == 0 {
            break;
        }

        for i in 0..returned as usize {
            let h_event = EVT_HANDLE(event_handles[i]);

            // Render XML
            let mut buffer_used = 0;
            let mut property_count = 0;

            let _ = EvtRender(
                None,
                h_event,
                EvtRenderEventXml.0,
                0,
                None,
                &mut buffer_used,
                &mut property_count,
            );

            if buffer_used > 0 {
                let mut buffer = vec![0u16; (buffer_used / 2) as usize + 2];
                let mut actual_used = 0;
                let render_ok = EvtRender(
                    None,
                    h_event,
                    EvtRenderEventXml.0,
                    buffer.len() as u32 * 2,
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut actual_used,
                    &mut property_count,
                );

                if render_ok.is_ok() {
                    // Convert buffer to string, stripping null terminator at end
                    let end_idx = ((actual_used / 2) as usize).saturating_sub(1);
                    if let Ok(xml_str) = String::from_utf16(&buffer[..end_idx]) {
                        results.push(xml_str);
                    }
                }
            }

            let _ = EvtClose(h_event);
        }
    }

    let _ = EvtClose(query_handle);
    Ok(results)
}

pub unsafe fn get_latest_record_id(channel: &str) -> u64 {
    let channel_w = to_utf16(channel);
    let xpath_w = to_utf16("*");

    let query_handle = match EvtQuery(
        None,
        PCWSTR::from_raw(channel_w.as_ptr()),
        PCWSTR::from_raw(xpath_w.as_ptr()),
        EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
    ) {
        Ok(h) => h,
        Err(_) => return 0,
    };

    let mut event_handles = [0isize; 1];
    let mut returned = 0;
    let mut latest_id = 0;

    let success = EvtNext(query_handle, &mut event_handles, 500_u32, 0, &mut returned);

    if success.is_ok() && returned > 0 {
        let h_event = EVT_HANDLE(event_handles[0]);
        let mut buffer_used = 0;
        let mut property_count = 0;
        let _ = EvtRender(
            None,
            h_event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut buffer_used,
            &mut property_count,
        );
        if buffer_used > 0 {
            let mut buffer = vec![0u16; (buffer_used / 2) as usize + 2];
            let mut actual_used = 0;
            let render_ok = EvtRender(
                None,
                h_event,
                EvtRenderEventXml.0,
                buffer.len() as u32 * 2,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut actual_used,
                &mut property_count,
            );
            if render_ok.is_ok() {
                let end_idx = ((actual_used / 2) as usize).saturating_sub(1);
                if let Ok(xml_str) = String::from_utf16(&buffer[..end_idx]) {
                    if let Some(rec_start) = xml_str.find("<EventRecordID>") {
                        let rec_start = rec_start + 15;
                        if let Some(rec_end) = xml_str[rec_start..].find("</EventRecordID>") {
                            if let Ok(record_id) =
                                xml_str[rec_start..rec_start + rec_end].parse::<u64>()
                            {
                                latest_id = record_id;
                            }
                        }
                    }
                }
            }
        }
        let _ = EvtClose(h_event);
    }
    let _ = EvtClose(query_handle);
    latest_id
}
