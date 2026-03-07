pub mod registry;
pub mod eventlog;
pub mod lnk;
pub mod jumplist;
pub mod prefetch;
pub mod shellbags;
pub mod mft;
pub mod usnjrnl;
pub mod setupapi;

use anyhow::Result;
use std::path::Path;

/// Generic JSON array loader - loads a JSON file containing an array of items
pub fn load_json_array<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let content = std::fs::read_to_string(path)?;
    let trimmed = content.trim();

    // Handle JSON Lines format (one JSON object per line)
    if !trimmed.starts_with('[') {
        let mut items = Vec::new();
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<T>(line) {
                Ok(item) => items.push(item),
                Err(e) => {
                    eprintln!("  Warning: Failed to parse JSON line: {}", e);
                }
            }
        }
        return Ok(items);
    }

    // Standard JSON array
    let items: Vec<T> = serde_json::from_str(trimmed)?;
    Ok(items)
}

/// Try to find JSON files matching a pattern in a directory
pub fn find_json_files(dir: &Path, pattern: &str) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let name_lower = name.to_lowercase();
                if name_lower.contains(&pattern.to_lowercase()) && name_lower.ends_with(".json") {
                    results.push(path);
                }
            }
        }
    }
    results
}
