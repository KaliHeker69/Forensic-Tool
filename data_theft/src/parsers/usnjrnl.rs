use anyhow::Result;
use std::path::Path;

use crate::models::usnjrnl::UsnJrnlEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::parse_timestamp_opt;

/// Parse MFTECmd USN Journal JSON output
pub fn parse_usnjrnl(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<UsnJrnlEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let name = match &entry.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => continue,
        };

        let timestamp = parse_timestamp_opt(&entry.update_timestamp);

        let parent_path = entry.parent_path.as_deref().unwrap_or("");
        let full_path = if parent_path.is_empty() {
            name.clone()
        } else {
            format!("{}\\{}", parent_path, name)
        };

        let update_reasons = entry
            .update_reasons
            .as_deref()
            .unwrap_or("")
            .to_uppercase();

        let access_type = classify_usn_reason(&update_reasons);

        let details = format!(
            "USN Reasons: {} | Attributes: {} | Entry#: {} | ParentEntry#: {}",
            entry.update_reasons.as_deref().unwrap_or("N/A"),
            entry.file_attributes.as_deref().unwrap_or("N/A"),
            entry.entry_number.unwrap_or(0),
            entry.parent_entry_number.unwrap_or(0)
        );

        events.push(FileAccessEvent {
            timestamp,
            file_path: full_path,
            file_name: name,
            access_type,
            source_artifact: "USN Journal (MFTECmd)".to_string(),
            drive_letter: None, // USN is per-volume, drive letter depends on context
            volume_serial: None,
            user: None,
            details: Some(details),
            ..Default::default()
        });
    }

    Ok(events)
}

fn classify_usn_reason(reasons: &str) -> FileAccessType {
    if reasons.contains("FILE_DELETE") || reasons.contains("FILEDELETE") {
        FileAccessType::Deleted
    } else if reasons.contains("RENAME") {
        FileAccessType::Renamed
    } else if reasons.contains("FILE_CREATE") || reasons.contains("FILECREATE") {
        FileAccessType::Created
    } else if reasons.contains("DATA_EXTEND")
        || reasons.contains("DATA_OVERWRITE")
        || reasons.contains("DATAEXTEND")
        || reasons.contains("DATAOVERWRITE")
    {
        FileAccessType::Modified
    } else if reasons.contains("CLOSE") {
        FileAccessType::Accessed
    } else {
        FileAccessType::Unknown
    }
}
