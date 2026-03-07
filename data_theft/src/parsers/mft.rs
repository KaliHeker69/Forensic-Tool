use anyhow::Result;
use std::path::Path;

use crate::models::mft::MftEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::parse_timestamp_opt;

/// Parse MFTECmd JSON output for MFT entries
pub fn parse_mft(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<MftEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let file_name = match &entry.file_name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => continue,
        };

        let parent_path = entry.parent_path.as_deref().unwrap_or("");
        let full_path = if parent_path.is_empty() {
            file_name.clone()
        } else {
            format!("{}\\{}", parent_path, file_name)
        };

        // Detect timestomping (important for anti-forensics detection)
        let is_timestomped = entry.timestomped.unwrap_or(false);
        let is_copied = entry.copied.unwrap_or(false);

        // Use $FILE_NAME timestamps (0x30) as they're harder to manipulate
        let created = parse_timestamp_opt(&entry.created_0x30)
            .or_else(|| parse_timestamp_opt(&entry.created_0x10));
        let modified = parse_timestamp_opt(&entry.last_modified_0x30)
            .or_else(|| parse_timestamp_opt(&entry.last_modified_0x10));
        let accessed = parse_timestamp_opt(&entry.last_access_0x30)
            .or_else(|| parse_timestamp_opt(&entry.last_access_0x10));

        let in_use = entry.in_use.unwrap_or(true);
        let is_directory = entry.is_directory.unwrap_or(false);

        let mut details_parts = Vec::new();
        if is_timestomped {
            details_parts.push("[TIMESTOMPED] SI/FN timestamp mismatch detected!".to_string());
        }
        if is_copied {
            details_parts.push("[COPIED] File appears to be a copy".to_string());
        }
        if !in_use {
            details_parts.push("[DELETED] MFT entry not in use".to_string());
        }
        if is_directory {
            details_parts.push("[DIRECTORY]".to_string());
        }
        details_parts.push(format!(
            "Size: {} | Entry#: {} | Seq#: {}",
            entry
                .file_size
                .map(|s| format_file_size(s))
                .unwrap_or_else(|| "N/A".to_string()),
            entry.entry_number.unwrap_or(0),
            entry.sequence_number.unwrap_or(0)
        ));

        let details = details_parts.join(" | ");

        // Create event for file creation
        if let Some(ts) = created {
            events.push(FileAccessEvent {
                timestamp: Some(ts),
                file_path: full_path.clone(),
                file_name: file_name.clone(),
                access_type: if is_copied {
                    FileAccessType::Copied
                } else {
                    FileAccessType::Created
                },
                source_artifact: "MFT (MFTECmd)".to_string(),
                drive_letter: crate::parsers::registry::extract_drive_letter(&full_path),
                volume_serial: None,
                user: None,
                details: Some(details.clone()),
                ..Default::default()
            });
        }

        // Create event for file modification
        if let Some(ts) = modified {
            if modified != created {
                events.push(FileAccessEvent {
                    timestamp: Some(ts),
                    file_path: full_path.clone(),
                    file_name: file_name.clone(),
                    access_type: FileAccessType::Modified,
                    source_artifact: "MFT (MFTECmd)".to_string(),
                    drive_letter: crate::parsers::registry::extract_drive_letter(&full_path),
                    volume_serial: None,
                    user: None,
                    details: Some(details.clone()),
                    ..Default::default()
                });
            }
        }

        // Mark deleted files specifically
        if !in_use {
            events.push(FileAccessEvent {
                timestamp: accessed.or(modified).or(created),
                file_path: full_path.clone(),
                file_name: file_name.clone(),
                access_type: FileAccessType::Deleted,
                source_artifact: "MFT (MFTECmd)".to_string(),
                drive_letter: crate::parsers::registry::extract_drive_letter(&full_path),
                volume_serial: None,
                user: None,
                details: Some(details),
                ..Default::default()
            });
        }
    }

    Ok(events)
}

fn format_file_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
