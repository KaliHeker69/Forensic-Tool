use anyhow::Result;
use std::path::Path;

use crate::models::eventlog::*;
use crate::models::timeline::{Reliability, TimelineEvent, TimelineEventType};
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::parse_timestamp_opt;

/// Parse EvtxECmd JSON output for USB-related events
pub fn parse_eventlog_usb_events(path: &Path) -> Result<Vec<TimelineEvent>> {
    let entries: Vec<EvtxEntry> = load_json_array(path)?;
    let mut events: Vec<TimelineEvent> = Vec::new();

    for entry in &entries {
        let event_id = match entry.event_id {
            Some(id) => id,
            None => continue,
        };

        let timestamp = match parse_timestamp_opt(&entry.time_created) {
            Some(ts) => ts,
            None => continue,
        };

        let channel = entry.channel.as_deref().unwrap_or("").to_uppercase();

        // USB PnP events (System log)
        if USB_PNP_EVENT_IDS.contains(&event_id) && channel.contains("SYSTEM") {
            let event_type = match event_id {
                20001 => TimelineEventType::DriverInstalled,
                20003 => TimelineEventType::UsbDisconnected,
                _ => continue,
            };

            let description = entry
                .payload_data1
                .as_deref()
                .or(entry.map_description.as_deref())
                .unwrap_or("USB PnP event")
                .to_string();

            let device_serial = extract_serial_from_payload(entry);

            events.push(TimelineEvent {
                timestamp,
                event_type,
                source_artifact: format!("EventLog-System (Event ID {})", event_id),
                description,
                details: entry.payload.clone(),
                device_serial,
                file_path: None,
                user: entry.user_name.clone().or(entry.user_id.clone()),
                reliability: Reliability::High,
            });
        }

        // DriverFrameworks events
        if DRIVER_FRAMEWORK_EVENT_IDS.contains(&event_id)
            && (channel.contains("DRIVERFRAMEWORKS") || channel.contains("USERMODE"))
        {
            let event_type = match event_id {
                2003 => TimelineEventType::UsbConnected,
                2101 => TimelineEventType::UsbDisconnected,
                _ => TimelineEventType::UsbConnected,
            };

            let description = entry
                .map_description
                .as_deref()
                .or(entry.payload_data1.as_deref())
                .unwrap_or("DriverFrameworks USB event")
                .to_string();

            events.push(TimelineEvent {
                timestamp,
                event_type,
                source_artifact: format!(
                    "EventLog-DriverFrameworks (Event ID {})",
                    event_id
                ),
                description,
                details: entry.payload.clone(),
                device_serial: extract_serial_from_payload(entry),
                file_path: None,
                user: entry.user_name.clone(),
                reliability: Reliability::High,
            });
        }

        // Logon/Logoff events
        if LOGON_EVENT_IDS.contains(&event_id) && channel.contains("SECURITY") {
            let event_type = match event_id {
                4624 => TimelineEventType::UserLogon,
                4634 => TimelineEventType::UserLogoff,
                _ => continue,
            };

            events.push(TimelineEvent {
                timestamp,
                event_type,
                source_artifact: format!("EventLog-Security (Event ID {})", event_id),
                description: entry
                    .map_description
                    .as_deref()
                    .unwrap_or("Logon/Logoff")
                    .to_string(),
                details: entry.payload_data1.clone(),
                device_serial: None,
                file_path: None,
                user: entry.user_name.clone().or(entry.payload_data1.clone()),
                reliability: Reliability::High,
            });
        }
    }

    Ok(events)
}

/// Parse EvtxECmd JSON for file audit events (4663, 4656, 4660)
pub fn parse_eventlog_file_audit(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<EvtxEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let event_id = match entry.event_id {
            Some(id) => id,
            None => continue,
        };

        if !FILE_AUDIT_EVENT_IDS.contains(&event_id) {
            continue;
        }

        let channel = entry.channel.as_deref().unwrap_or("").to_uppercase();
        if !channel.contains("SECURITY") {
            continue;
        }

        let timestamp = parse_timestamp_opt(&entry.time_created);

        let access_type = match event_id {
            4656 => FileAccessType::Accessed,
            4663 => FileAccessType::Accessed,
            4660 => FileAccessType::Deleted,
            _ => FileAccessType::Unknown,
        };

        // Try to extract file path from payload data
        let file_path = entry
            .payload_data2
            .as_deref()
            .or(entry.payload_data1.as_deref())
            .unwrap_or("")
            .to_string();

        if file_path.is_empty() {
            continue;
        }

        let file_name = file_path
            .rsplit('\\')
            .next()
            .unwrap_or(&file_path)
            .to_string();

        events.push(FileAccessEvent {
            timestamp,
            file_path: file_path.clone(),
            file_name,
            access_type,
            source_artifact: format!("EventLog-Security (Event ID {})", event_id),
            drive_letter: crate::parsers::registry::extract_drive_letter(&file_path),
            volume_serial: None,
            user: entry.user_name.clone().or(entry.user_id.clone()),
            details: entry.map_description.clone(),
            ..Default::default()
        });
    }

    Ok(events)
}

fn extract_serial_from_payload(entry: &EvtxEntry) -> Option<String> {
    // Try to extract USB serial from various payload fields
    for payload in [
        &entry.payload,
        &entry.payload_data1,
        &entry.payload_data2,
        &entry.payload_data3,
    ]
    .iter()
    .filter_map(|p| p.as_ref())
    {
        // Look for USBSTOR pattern
        if let Some(pos) = payload.to_uppercase().find("USBSTOR") {
            let remainder = &payload[pos..];
            // Try to extract serial from pattern like USBSTOR\Disk&Ven_X&Prod_Y\SERIAL
            let parts: Vec<&str> = remainder.split('\\').collect();
            if parts.len() >= 3 {
                return Some(parts[2].trim().to_string());
            }
        }
    }
    None
}
