#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::*;
use ironclaw_core::event::{Event, EventType};

pub fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn parse_event_xml(xml: &str, agent_id: &str, default_type: EventType, source: &str) -> Option<Event> {
    // Extract EventID
    let id_start = xml.find("<EventID>")? + 9;
    let id_end = xml[id_start..].find("</EventID>")?;
    let event_id: u32 = xml[id_start..id_start+id_end].parse().ok()?;

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
    let timestamp = xml[time_start..time_start+time_end].to_string();

    // Extract EventRecordID (monotonically increasing ID per channel)
    let rec_start = xml.find("<EventRecordID>")? + 15;
    let rec_end = xml[rec_start..].find("</EventRecordID>")?;
    let record_id: u64 = xml[rec_start..rec_start+rec_end].parse().ok()?;

    // Extract Computer
    let comp_start = xml.find("<Computer>")? + 10;
    let comp_end = xml[comp_start..].find("</Computer>")?;
    let computer = xml[comp_start..comp_start+comp_end].to_string();

    // Extract Data Name="xyz" fields (can be Name="xyz" or Name='xyz')
    let mut payload = serde_json::Map::new();
    let mut search_pos = 0;
    while search_pos < xml.len() {
        let (data_pos, name_start, quote_char) = if let Some(pos) = xml[search_pos..].find("<Data Name=\"") {
            (pos, search_pos + pos + 12, '"')
        } else if let Some(pos) = xml[search_pos..].find("<Data Name='") {
            (pos, search_pos + pos + 12, '\'')
        } else {
            break;
        };
        
        if let Some(name_end) = xml[name_start..].find(quote_char) {
            let name = &xml[name_start..name_start+name_end];
            let val_start = name_start + name_end + 2; // skip quote and '>'
            if let Some(val_end) = xml[val_start..].find("</Data>") {
                let value = &xml[val_start..val_start+val_end];
                payload.insert(name.to_string(), serde_json::Value::String(value.to_string()));
                search_pos = val_start + val_end + 7;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Include the Windows EventRecordID and system time in payload for tracking
    payload.insert("event_record_id".to_string(), serde_json::Value::Number(record_id.into()));
    payload.insert("computer".to_string(), serde_json::Value::String(computer));
    payload.insert("system_time".to_string(), serde_json::Value::String(timestamp));

    // Determine specific EventType overrides
    let mut etype = default_type;
    if source == "sysmon" {
        match event_id {
            1 => etype = EventType::Process,
            3 => etype = EventType::Network,
            7 => etype = EventType::DriverLoad, // Image loaded (DLL load)
            22 => etype = EventType::Dns,
            11 => etype = EventType::FileSystem,
            _ => {}
        }
    }

    Some(Event::new(agent_id, etype, source, Some(event_id), serde_json::Value::Object(payload)))
}

pub unsafe fn query_new_events(
    channel: &str,
    xpath_query: &str,
) -> anyhow::Result<Vec<String>> {
    let channel_w = to_utf16(channel);
    let xpath_w = to_utf16(xpath_query);

    let query_handle = match EvtQuery(
        None,
        PCWSTR::from_raw(channel_w.as_ptr()),
        PCWSTR::from_raw(xpath_w.as_ptr()),
        EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
    ) {
        Ok(h) => h,
        Err(e) => return Err(anyhow::anyhow!("EvtQuery failed for channel '{}': {}", channel, e)),
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
    
    let success = EvtNext(
        query_handle,
        &mut event_handles,
        500_u32,
        0,
        &mut returned,
    );
    
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
                            if let Ok(record_id) = xml_str[rec_start..rec_start+rec_end].parse::<u64>() {
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
