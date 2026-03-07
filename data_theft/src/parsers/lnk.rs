use anyhow::Result;
use std::path::Path;

use crate::models::lnk::LnkEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::{extract_drive_letter, parse_timestamp_opt};

/// Parse LECmd JSON output for LNK file events
pub fn parse_lnk_files(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<LnkEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let local_path = entry
            .local_path
            .as_deref()
            .or(entry.target_id_absolute_path.as_deref())
            .or(entry.relative_path.as_deref());

        let file_path = match local_path {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => continue,
        };

        let file_name = file_path
            .rsplit('\\')
            .next()
            .unwrap_or(&file_path)
            .to_string();

        let timestamp = parse_timestamp_opt(&entry.target_accessed)
            .or_else(|| parse_timestamp_opt(&entry.target_modified))
            .or_else(|| parse_timestamp_opt(&entry.source_created));

        let is_removable = entry
            .drive_type
            .as_deref()
            .map(|dt| {
                let dt_upper = dt.to_uppercase();
                dt_upper.contains("REMOVABLE")
                    || dt_upper.contains("EXTERNAL")
                    || dt_upper.contains("UNKNOWN")
            })
            .unwrap_or(false);

        let drive_letter = extract_drive_letter(&file_path);

        let details = format!(
            "LNK Target: {} | DriveType: {} | VolumeSerial: {} | VolumeLabel: {} | FileSize: {}{}",
            file_path,
            entry.drive_type.as_deref().unwrap_or("N/A"),
            entry.drive_serial_number.as_deref().unwrap_or("N/A"),
            entry.volume_label.as_deref().unwrap_or("N/A"),
            entry.file_size.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string()),
            if is_removable {
                " [REMOVABLE DRIVE]"
            } else {
                ""
            }
        );

        events.push(FileAccessEvent {
            timestamp,
            file_path,
            file_name,
            access_type: FileAccessType::Accessed,
            source_artifact: "LNK File (LECmd)".to_string(),
            drive_letter,
            volume_serial: entry.drive_serial_number.clone(),
            user: None,
            details: Some(details),
            ..Default::default()
        });
    }

    Ok(events)
}

/// Check if a LNK entry points to a removable drive
#[allow(dead_code)]
pub fn is_removable_drive(entry: &LnkEntry) -> bool {
    if let Some(dt) = &entry.drive_type {
        let dt_upper = dt.to_uppercase();
        return dt_upper.contains("REMOVABLE") || dt_upper == "2";
    }
    false
}
