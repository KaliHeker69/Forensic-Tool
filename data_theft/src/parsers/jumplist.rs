use anyhow::Result;
use std::path::Path;

use crate::models::jumplist::JumpListEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::{extract_drive_letter, parse_timestamp_opt};

/// Parse JLECmd JSON output for JumpList events
pub fn parse_jumplists(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<JumpListEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let file_path = entry
            .local_path
            .as_deref()
            .or(entry.path.as_deref())
            .or(entry.target_id_absolute_path.as_deref());

        let file_path = match file_path {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => continue,
        };

        let file_name = file_path
            .rsplit('\\')
            .next()
            .unwrap_or(&file_path)
            .to_string();

        let timestamp = parse_timestamp_opt(&entry.last_modified)
            .or_else(|| parse_timestamp_opt(&entry.creation_time))
            .or_else(|| parse_timestamp_opt(&entry.target_accessed));

        let is_removable = entry
            .drive_type
            .as_deref()
            .map(|dt| {
                let dt_upper = dt.to_uppercase();
                dt_upper.contains("REMOVABLE") || dt_upper.contains("EXTERNAL")
            })
            .unwrap_or(false);

        let app_desc = entry
            .app_id_description
            .as_deref()
            .unwrap_or("Unknown App");
        let interaction_count = entry.interaction_count.unwrap_or(0);

        let details = format!(
            "App: {} | Interactions: {} | DriveType: {} | VolumeSerial: {}{}",
            app_desc,
            interaction_count,
            entry.drive_type.as_deref().unwrap_or("N/A"),
            entry.drive_serial_number.as_deref().unwrap_or("N/A"),
            if is_removable {
                " [REMOVABLE DRIVE]"
            } else {
                ""
            }
        );

        events.push(FileAccessEvent {
            timestamp,
            file_path: file_path.clone(),
            file_name,
            access_type: FileAccessType::Accessed,
            source_artifact: "JumpList (JLECmd)".to_string(),
            drive_letter: extract_drive_letter(&file_path),
            volume_serial: entry.drive_serial_number.clone(),
            user: None,
            details: Some(details),
            ..Default::default()
        });
    }

    Ok(events)
}
