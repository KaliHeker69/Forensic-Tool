use anyhow::Result;
use std::path::Path;

use crate::models::prefetch::PrefetchEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::parse_timestamp_opt;

/// Parse PECmd JSON output for prefetch events
pub fn parse_prefetch(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<PrefetchEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let exe_name = match &entry.executable_name {
            Some(name) => name.clone(),
            None => continue,
        };

        let timestamp = parse_timestamp_opt(&entry.last_run)
            .or_else(|| parse_timestamp_opt(&entry.source_modified));

        // Check if any loaded files or directories reference removable drives
        let mut usb_references: Vec<String> = Vec::new();

        if let Some(files_loaded) = &entry.files_loaded {
            for file in files_loaded.split(',') {
                let file = file.trim();
                if is_non_system_drive(file) {
                    usb_references.push(file.to_string());
                }
            }
        }

        if let Some(directories) = &entry.directories {
            for dir in directories.split(',') {
                let dir = dir.trim();
                if is_non_system_drive(dir) {
                    usb_references.push(dir.to_string());
                }
            }
        }

        // Check volumes for non-system volumes (potential USB)
        let mut volume_info = Vec::new();
        if let Some(v0_name) = &entry.volume0_name {
            volume_info.push(format!(
                "Vol0: {} (Serial: {})",
                v0_name,
                entry.volume0_serial.as_deref().unwrap_or("N/A")
            ));
        }
        if let Some(v1_name) = &entry.volume1_name {
            volume_info.push(format!(
                "Vol1: {} (Serial: {})",
                v1_name,
                entry.volume1_serial.as_deref().unwrap_or("N/A")
            ));
        }

        let details = format!(
            "RunCount: {} | Volumes: {} | USB References: {}",
            entry.run_count.unwrap_or(0),
            if volume_info.is_empty() {
                "N/A".to_string()
            } else {
                volume_info.join("; ")
            },
            if usb_references.is_empty() {
                "None".to_string()
            } else {
                usb_references.join("; ")
            }
        );

        events.push(FileAccessEvent {
            timestamp,
            file_path: entry
                .source_filename
                .as_deref()
                .unwrap_or(&exe_name)
                .to_string(),
            file_name: exe_name,
            access_type: FileAccessType::Executed,
            source_artifact: "Prefetch (PECmd)".to_string(),
            drive_letter: None,
            volume_serial: entry.volume0_serial.clone(),
            user: None,
            details: Some(details),
            ..Default::default()
        });

        // Also create events for each USB-referenced file
        for usb_ref in &usb_references {
            let ref_name = usb_ref
                .rsplit('\\')
                .next()
                .unwrap_or(usb_ref)
                .to_string();
            events.push(FileAccessEvent {
                timestamp,
                file_path: usb_ref.clone(),
                file_name: ref_name,
                access_type: FileAccessType::Accessed,
                source_artifact: "Prefetch-FileRef (PECmd)".to_string(),
                drive_letter: crate::parsers::registry::extract_drive_letter(usb_ref),
                volume_serial: None,
                user: None,
                details: Some(format!(
                    "Referenced by prefetch for: {}",
                    entry.executable_name.as_deref().unwrap_or("Unknown")
                )),
                ..Default::default()
            });
        }
    }

    Ok(events)
}

/// Check if a path is on a non-system drive (potential USB)
fn is_non_system_drive(path: &str) -> bool {
    if path.len() < 2 {
        return false;
    }
    let first_char = path.chars().next().unwrap_or('C').to_ascii_uppercase();
    let second_char = path.chars().nth(1).unwrap_or(' ');

    // Common system drives are C: and sometimes D:
    // Drives E: through Z: are more likely removable
    second_char == ':' && first_char >= 'E' && first_char <= 'Z'
}
