use anyhow::Result;
use regex::Regex;
use std::path::Path;

use crate::models::setupapi::SetupapiEntry;
use crate::models::timeline::{Reliability, TimelineEvent, TimelineEventType};
use crate::parsers::registry::parse_timestamp_str;

/// Parse setupapi.dev.log for USB first-connection events
/// This takes the raw log file, not JSON (setupapi isn't processed by EZ tools to JSON)
/// However, if the user provides a pre-parsed JSON version, we handle that too.
pub fn parse_setupapi_log(path: &Path) -> Result<Vec<TimelineEvent>> {
    let content = std::fs::read_to_string(path)?;
    let mut events: Vec<TimelineEvent> = Vec::new();

    // Try JSON first
    if content.trim().starts_with('[') || content.trim().starts_with('{') {
        if let Ok(entries) = serde_json::from_str::<Vec<SetupapiEntry>>(&content) {
            for entry in entries {
                if let Some(ts_str) = &entry.timestamp {
                    if let Some(ts) = parse_timestamp_str(ts_str) {
                        let is_usb = entry.device_description.to_uppercase().contains("USB")
                            || entry
                                .device_description
                                .to_uppercase()
                                .contains("USBSTOR");

                        if is_usb {
                            events.push(TimelineEvent {
                                timestamp: ts,
                                event_type: TimelineEventType::UsbFirstConnected,
                                source_artifact: "setupapi.dev.log".to_string(),
                                description: format!(
                                    "USB device driver installed: {}",
                                    entry.device_description
                                ),
                                details: entry.serial_number.clone(),
                                device_serial: entry.serial_number,
                                file_path: None,
                                user: None,
                                reliability: Reliability::VeryHigh,
                            });
                        }
                    }
                }
            }
            return Ok(events);
        }
    }

    // Parse raw setupapi.dev.log format
    let section_re =
        Regex::new(r"(?m)>>>\s*\[Device Install.*?\]")?;
    let timestamp_re =
        Regex::new(r"(?m)>>>\s*Section (start|end) (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)")?;
    let usb_re = Regex::new(r"(?i)(USBSTOR|USB\\VID)")?;

    let sections: Vec<_> = section_re.find_iter(&content).collect();

    for (i, section_match) in sections.iter().enumerate() {
        let start = section_match.start();
        let end = if i + 1 < sections.len() {
            sections[i + 1].start()
        } else {
            content.len()
        };

        let section_text = &content[start..end];

        // Check if this section relates to USB
        if !usb_re.is_match(section_text) {
            continue;
        }

        // Extract timestamp
        if let Some(ts_cap) = timestamp_re.captures(section_text) {
            let ts_str = ts_cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let ts_str_normalized = ts_str.replace('/', "-");
            if let Some(ts) = parse_timestamp_str(&ts_str_normalized) {
                // Extract device description
                let device_desc = section_text
                    .lines()
                    .find(|l| l.contains("Device Install") || l.contains("USBSTOR") || l.contains("USB\\VID"))
                    .unwrap_or("USB device")
                    .trim()
                    .to_string();

                // Try to extract serial number
                let serial = extract_serial_from_setupapi(section_text);

                events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: TimelineEventType::UsbFirstConnected,
                    source_artifact: "setupapi.dev.log".to_string(),
                    description: format!("USB device first connected: {}", device_desc),
                    details: Some(section_text.chars().take(500).collect()),
                    device_serial: serial,
                    file_path: None,
                    user: None,
                    reliability: Reliability::VeryHigh,
                });
            }
        }
    }

    Ok(events)
}

fn extract_serial_from_setupapi(section: &str) -> Option<String> {
    let re = Regex::new(r"(?i)USBSTOR\\[^\\]+\\([^\s\\]+)").ok()?;
    re.captures(section)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}
