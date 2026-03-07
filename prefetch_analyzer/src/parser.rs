//! JSON Parser for PECmd output
//!
//! Parses NDJSON (newline-delimited JSON) prefetch data.

use crate::models::PrefetchEntry;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parse a PECmd JSON output file (NDJSON format - one JSON object per line)
pub fn parse_prefetch_json<P: AsRef<Path>>(path: P) -> Result<Vec<PrefetchEntry>> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open file: {:?}", path.as_ref()))?;
    
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut line_num = 0;

    for line_result in reader.lines() {
        line_num += 1;
        let line = line_result.with_context(|| format!("Failed to read line {}", line_num))?;
        
        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse each line as a separate JSON object
        match serde_json::from_str::<PrefetchEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                // Log warning but continue processing
                eprintln!("Warning: Failed to parse line {}: {}", line_num, e);
            }
        }
    }

    if entries.is_empty() {
        anyhow::bail!("No valid prefetch entries found in file");
    }

    Ok(entries)
}

/// Parse prefetch entries from a JSON string
pub fn parse_prefetch_str(content: &str) -> Result<Vec<PrefetchEntry>> {
    let mut entries = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<PrefetchEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                eprintln!("Warning: Failed to parse line {}: {}", i + 1, e);
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_entry() {
        let json = r#"{"filename": "/test/NOTEPAD.EXE-12345678.pf", "executable_name": "NOTEPAD.EXE", "run_times": {"Run 1": "2023-03-08 11:04:34.692143"}, "num_files": 10, "files": {"File 1": "\\VOLUME{}\\TEST.DLL"}, "num_volumes": 1, "volume_information": {"Volume 1": "\\VOLUME{}"}}"#;
        
        let entries = parse_prefetch_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].executable_name, "NOTEPAD.EXE");
        assert_eq!(entries[0].run_count(), 1);
    }
}
