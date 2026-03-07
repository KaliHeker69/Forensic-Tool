use anyhow::Result;
use regex::Regex;
use std::path::Path;

use crate::models::registry::*;
use crate::models::{FileAccessEvent, FileAccessType, UsbDevice};
use crate::parsers::load_json_array;

/// Parse RECmd JSON output and extract USB device information
pub fn parse_registry_for_usb(path: &Path) -> Result<Vec<UsbDevice>> {
    let entries: Vec<RegCmdEntry> = load_json_array(path)?;
    let mut devices: Vec<UsbDevice> = Vec::new();

    for entry in &entries {
        let key_path = match &entry.key_path {
            Some(k) => k.to_uppercase(),
            None => continue,
        };

        // Parse USBSTOR entries
        if key_path.contains("USBSTOR") {
            if let Some(device) = parse_usbstor_entry(entry) {
                // Check if we already have this device
                let existing = devices.iter_mut().find(|d| {
                    d.serial_number == device.serial_number
                        && d.vendor == device.vendor
                        && d.product == device.product
                });
                if let Some(existing) = existing {
                    merge_usb_device(existing, &device);
                } else {
                    devices.push(device);
                }
            }
        }

        // Parse MountPoints2 for user association
        if key_path.contains("MOUNTPOINTS2") {
            if let Some(value_data) = &entry.value_data {
                for device in &mut devices {
                    if let Some(guid) = &device.volume_guid {
                        if value_data.to_uppercase().contains(&guid.to_uppercase()) {
                            if let Some(hive_path) = &entry.hive_path {
                                device.associated_user =
                                    Some(extract_user_from_hive_path(hive_path));
                            }
                        }
                    }
                }
            }
        }

        // Parse MountedDevices for drive letter mapping
        if key_path.contains("MOUNTEDDEVICES") {
            if let (Some(value_name), Some(value_data)) = (&entry.value_name, &entry.value_data) {
                if value_name.starts_with("\\DosDevices\\") {
                    let drive_letter = value_name.replace("\\DosDevices\\", "");
                    for device in &mut devices {
                        if value_data.contains(&device.serial_number) {
                            device.drive_letter = Some(drive_letter.clone());
                        }
                    }
                }
                if value_name.starts_with("\\??\\Volume") {
                    let guid = value_name
                        .replace("\\??\\", "")
                        .trim_end_matches('\\')
                        .to_string();
                    for device in &mut devices {
                        if value_data.contains(&device.serial_number) {
                            device.volume_guid = Some(guid.clone());
                        }
                    }
                }
            }
        }
    }

    Ok(devices)
}

/// Parse RECmd JSON output for file access events from RecentDocs, Office MRU, etc.
pub fn parse_registry_for_file_access(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<RegCmdEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let key_path = match &entry.key_path {
            Some(k) => k,
            None => continue,
        };
        let key_upper = key_path.to_uppercase();

        // RecentDocs
        if key_upper.contains("RECENTDOCS") {
            if let Some(value_data) = &entry.value_data {
                if !value_data.is_empty() {
                    let file_name = extract_filename_from_path(value_data);
                    events.push(FileAccessEvent {
                        timestamp: parse_timestamp_opt(&entry.last_write_timestamp),
                        file_path: value_data.clone(),
                        file_name,
                        access_type: FileAccessType::Accessed,
                        source_artifact: "Registry-RecentDocs".to_string(),
                        drive_letter: extract_drive_letter(value_data),
                        volume_serial: None,
                        user: entry
                            .hive_path
                            .as_ref()
                            .map(|h| extract_user_from_hive_path(h)),
                        details: entry.comment.clone(),
                        ..Default::default()
                    });
                }
            }
        }

        // Office MRU
        if key_upper.contains("FILE MRU") || key_upper.contains("FILEMRU") {
            if let Some(value_data) = &entry.value_data {
                if value_data.contains('\\') || value_data.contains('/') {
                    let file_path = extract_path_from_office_mru(value_data);
                    let file_name = extract_filename_from_path(&file_path);
                    events.push(FileAccessEvent {
                        timestamp: parse_timestamp_opt(&entry.last_write_timestamp),
                        file_path: file_path.clone(),
                        file_name,
                        access_type: FileAccessType::Accessed,
                        source_artifact: "Registry-OfficeMRU".to_string(),
                        drive_letter: extract_drive_letter(&file_path),
                        volume_serial: None,
                        user: entry
                            .hive_path
                            .as_ref()
                            .map(|h| extract_user_from_hive_path(h)),
                        details: Some(format!("Office MRU entry: {}", key_path)),
                        ..Default::default()
                    });
                }
            }
        }

        // AppCompatCache / ShimCache
        if key_upper.contains("APPCOMPATCACHE") {
            if let Some(value_data) = &entry.value_data {
                if value_data.contains('\\') {
                    let file_name = extract_filename_from_path(value_data);
                    events.push(FileAccessEvent {
                        timestamp: parse_timestamp_opt(&entry.last_write_timestamp),
                        file_path: value_data.clone(),
                        file_name,
                        access_type: FileAccessType::Executed,
                        source_artifact: "Registry-AppCompatCache".to_string(),
                        drive_letter: extract_drive_letter(value_data),
                        volume_serial: None,
                        user: None,
                        details: Some("AppCompatCache/ShimCache entry".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    Ok(events)
}

/// Parse AppCompatCacheParser JSON output
pub fn parse_appcompat_cache(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<AppCompatCacheEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        if let Some(exe_path) = &entry.path {
            let file_name = extract_filename_from_path(exe_path);
            events.push(FileAccessEvent {
                timestamp: parse_timestamp_opt(&entry.last_modified_time_utc),
                file_path: exe_path.clone(),
                file_name,
                access_type: FileAccessType::Executed,
                source_artifact: "AppCompatCache".to_string(),
                drive_letter: extract_drive_letter(exe_path),
                volume_serial: None,
                user: None,
                details: entry.executed.as_ref().map(|e| format!("Executed: {}", e)),
                ..Default::default()
            });
        }
    }

    Ok(events)
}

fn parse_usbstor_entry(entry: &RegCmdEntry) -> Option<UsbDevice> {
    let key_path = entry.key_path.as_ref()?;

    // USBSTOR key format: ...\USBSTOR\Disk&Ven_VENDOR&Prod_PRODUCT&Rev_REV\SERIAL
    let re = Regex::new(
        r"(?i)USBSTOR\\Disk&Ven_([^&]+)&Prod_([^&]+)(?:&Rev_([^\\]+))?\\([^\\]+)",
    )
    .ok()?;

    if let Some(caps) = re.captures(key_path) {
        let vendor = caps.get(1)?.as_str().to_string();
        let product = caps.get(2)?.as_str().to_string();
        let _revision = caps.get(3).map(|m| m.as_str().to_string());
        let serial = caps.get(4)?.as_str().to_string();

        return Some(UsbDevice {
            vendor,
            product,
            serial_number: serial,
            device_class: Some("DiskDrive".to_string()),
            first_connected: parse_timestamp_opt(&entry.last_write_timestamp),
            last_connected: None,
            last_disconnected: None,
            drive_letter: None,
            volume_guid: None,
            volume_serial: None,
            volume_label: None,
            friendly_name: entry.value_data.clone().or_else(|| {
                entry
                    .plugin_detail_values
                    .as_ref()
                    .and_then(|v| v.get("FriendlyName"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            }),
            associated_user: None,
            ..Default::default()
        });
    }

    None
}

fn merge_usb_device(existing: &mut UsbDevice, new: &UsbDevice) {
    if existing.friendly_name.is_none() {
        existing.friendly_name = new.friendly_name.clone();
    }
    if existing.drive_letter.is_none() {
        existing.drive_letter = new.drive_letter.clone();
    }
    if existing.volume_guid.is_none() {
        existing.volume_guid = new.volume_guid.clone();
    }
    if let (Some(existing_ts), Some(new_ts)) = (&existing.first_connected, &new.first_connected) {
        if new_ts < existing_ts {
            existing.first_connected = Some(*new_ts);
        }
    } else if existing.first_connected.is_none() {
        existing.first_connected = new.first_connected;
    }
}

fn extract_user_from_hive_path(hive_path: &str) -> String {
    // Try to extract username from hive path like C:\Users\John\NTUSER.DAT
    let re = Regex::new(r"(?i)\\Users\\([^\\]+)").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(hive_path) {
            return caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        }
    }
    hive_path.to_string()
}

pub fn extract_drive_letter(path: &str) -> Option<String> {
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        Some(path[..2].to_string())
    } else {
        None
    }
}

fn extract_filename_from_path(path: &str) -> String {
    path.rsplit('\\')
        .next()
        .or_else(|| path.rsplit('/').next())
        .unwrap_or(path)
        .to_string()
}

fn extract_path_from_office_mru(value: &str) -> String {
    // Office MRU values sometimes have format: [F00000000][T01D...]*path
    if let Some(idx) = value.find('*') {
        return value[idx + 1..].to_string();
    }
    value.to_string()
}

pub fn parse_timestamp_opt(ts: &Option<String>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.as_ref().and_then(|s| parse_timestamp_str(s))
}

pub fn parse_timestamp_str(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Try various formats EZ tools may output
    let formats = [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ];

    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt.and_utc());
        }
    }

    // Try parsing with timezone
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }

    // Try ends with Z
    let trimmed = s.trim_end_matches('Z');
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Some(dt.and_utc());
        }
    }

    None
}
