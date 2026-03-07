// =============================================================================
// NTFS Forensic Analyzer - JSON Input Parser
// =============================================================================
// Handles loading and validating NTFS artifact data from JSON files.
// Supports single-file input or directory-based multi-file input.
// =============================================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::models::{MftECmdEntry, NtfsInput, UsnRecord};

#[derive(Debug, Deserialize)]
struct UsnECmdEntry {
    #[serde(rename = "UpdateSequenceNumber")]
    usn: u64,
    #[serde(rename = "UpdateTimestamp")]
    timestamp: String,
    #[serde(rename = "EntryNumber")]
    entry_number: u64,
    #[serde(rename = "SequenceNumber", default)]
    sequence_number: Option<u16>,
    #[serde(rename = "ParentEntryNumber", default)]
    parent_entry_number: Option<u64>,
    #[serde(rename = "ParentSequenceNumber", default)]
    parent_sequence_number: Option<u16>,
    #[serde(rename = "UpdateReasons", default)]
    update_reasons: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "FileAttributes", default)]
    file_attributes: Option<String>,
    #[serde(rename = "SourceInfo", default)]
    source_info: Option<u32>,
}

impl UsnECmdEntry {
    fn into_usn_record(self) -> UsnRecord {
        let reason_decoded = split_pipe_field(self.update_reasons);
        let file_attributes = split_pipe_field(self.file_attributes);

        UsnRecord {
            usn: self.usn,
            timestamp: self.timestamp,
            mft_entry_id: self.entry_number,
            mft_sequence: self.sequence_number,
            parent_entry_id: self.parent_entry_number,
            parent_sequence: self.parent_sequence_number,
            reason_flags: 0,
            reason_decoded,
            filename: self.name,
            file_attributes,
            source_info: self.source_info,
        }
    }
}

fn split_pipe_field(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Load and parse NTFS data from a JSON file.
/// Supports two formats:
/// 1. A single JSON object matching the NtfsInput schema
/// 2. NDJSON (newline-delimited JSON) from MFTECmd where each line is an MFT entry
pub fn load_ntfs_input(path: &Path) -> Result<NtfsInput> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read input file: {}", path.display()))?;

    // Detect format: if the first non-whitespace character is '{' and parsing as
    // NtfsInput fails, try NDJSON (MFTECmd) format. If it starts with '{' and the
    // second line also starts with '{', it's almost certainly NDJSON.
    let trimmed = content.trim_start();
    let is_ndjson = trimmed.starts_with('{') && {
        // Check if there are multiple JSON objects (one per line)
        let mut lines = trimmed.lines().filter(|l| !l.trim().is_empty());
        let first = lines.next().unwrap_or("");
        let second = lines.next();
        // If the second non-empty line also starts with '{', it's NDJSON
        // If there's only one line and it parses as MFTECmd entry, also NDJSON
        match second {
            Some(l) => l.trim_start().starts_with('{'),
            None => serde_json::from_str::<MftECmdEntry>(first).is_ok()
                && serde_json::from_str::<NtfsInput>(first).is_err(),
        }
    };

    if is_ndjson {
        return load_mftecmd_ndjson(&content, path);
    }

    // Try standard NtfsInput format
    let input: NtfsInput = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from: {}", path.display()))?;

    validate_input(&input)?;
    Ok(input)
}

/// Parse NDJSON content from MFTECmd (one JSON object per line) into NtfsInput
fn load_mftecmd_ndjson(content: &str, source_path: &Path) -> Result<NtfsInput> {
    let mut mft_entries = Vec::new();
    let mut ads_entries = Vec::new();
    let mut errors = 0u64;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<MftECmdEntry>(line) {
            Ok(entry) => {
                if entry.is_ads {
                    // Keep track of ADS entries separately for cross-reference
                    ads_entries.push(entry);
                } else {
                    mft_entries.push(entry.into_mft_entry());
                }
            }
            Err(e) => {
                errors += 1;
                if errors <= 5 {
                    eprintln!(
                        "  Warning: Failed to parse line {} of {}: {}",
                        line_num + 1,
                        source_path.display(),
                        e
                    );
                }
            }
        }
    }

    if errors > 5 {
        eprintln!("  ... and {} more parse errors suppressed", errors - 5);
    }

    // Convert ADS entries into data streams on their host files
    for ads in &ads_entries {
        let host_entry_num = ads.entry_number;
        let stream_name = ads
            .file_name
            .clone()
            .unwrap_or_else(|| "unnamed_ads".to_string());

        if let Some(host) = mft_entries.iter_mut().find(|e| e.entry_id == host_entry_num) {
            host.data_streams.push(crate::models::DataStream {
                name: stream_name,
                size: Some(ads.file_size),
                allocated_size: None,
                resident: false,
                content: None,
                data_runs: Vec::new(),
            });
        } else {
            // ADS without a matching host — include as a standalone entry
            mft_entries.push(ads.clone().into_mft_entry());
        }
    }

    eprintln!(
        "  Detected MFTECmd NDJSON format: {} MFT entries, {} ADS entries",
        mft_entries.len(),
        ads_entries.len()
    );

    let input = NtfsInput {
        case_info: None,
        volume_info: None,
        mft_entries,
        usn_records: Vec::new(),
        i30_entries: Vec::new(),
        bitmap_data: None,
    };

    validate_input(&input)?;
    Ok(input)
}

/// Load NTFS data from a directory containing multiple JSON files
/// Expects files named: mft.json, usn.json, i30.json, bitmap.json, case_info.json
pub fn load_ntfs_input_directory(dir: &Path) -> Result<NtfsInput> {
    let mut input = NtfsInput {
        case_info: None,
        volume_info: None,
        mft_entries: Vec::new(),
        usn_records: Vec::new(),
        i30_entries: Vec::new(),
        bitmap_data: None,
    };

    // Load case info if present
    let case_info_path = dir.join("case_info.json");
    if case_info_path.exists() {
        let content = std::fs::read_to_string(&case_info_path)?;
        let case_data: serde_json::Value = serde_json::from_str(&content)?;
        if let Ok(ci) = serde_json::from_value(case_data.clone()) {
            input.case_info = Some(ci);
        }
        if let Ok(vi) = serde_json::from_value(case_data) {
            input.volume_info = Some(vi);
        }
    }

    // Load MFT entries (supports JSON array or MFTECmd NDJSON)
    let mft_path = dir.join("mft.json");
    if mft_path.exists() {
        let content = std::fs::read_to_string(&mft_path)?;
        let trimmed = content.trim_start();

        // Detect NDJSON vs JSON array
        if trimmed.starts_with('[') {
            // Standard JSON array of MftEntry
            input.mft_entries = serde_json::from_str(&content)
                .with_context(|| "Failed to parse mft.json")?;
        } else if trimmed.starts_with('{') {
            // MFTECmd NDJSON format
            let ndjson_input = load_mftecmd_ndjson(&content, &mft_path)?;
            input.mft_entries = ndjson_input.mft_entries;
        } else {
            anyhow::bail!("Unrecognized format in mft.json: expected JSON array or NDJSON");
        }
    }

    // Load USN records (try $Extend subdirectory first, then root)
    let usn_paths = [
        dir.join("$Extend").join("$J.json"),
        dir.join("$Extend").join("usn.json"),
        dir.join("usn.json"),
    ];
    for usn_path in &usn_paths {
        if usn_path.exists() {
            let content = std::fs::read_to_string(usn_path)?;
            let trimmed = content.trim_start();
            if trimmed.starts_with('[') {
                input.usn_records = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse {}", usn_path.display()))?;
            } else if trimmed.starts_with('{') {
                input.usn_records = load_usn_ndjson(&content, usn_path)?;
            } else {
                anyhow::bail!(
                    "Unrecognized format in {}: expected JSON array or NDJSON",
                    usn_path.display()
                );
            }
            eprintln!("  Loaded {} USN journal ($J) records from {}", 
                input.usn_records.len(), usn_path.display());
            break;
        }
    }

    // Load I30 entries
    let i30_path = dir.join("i30.json");
    if i30_path.exists() {
        let content = std::fs::read_to_string(&i30_path)?;
        input.i30_entries = serde_json::from_str(&content)
            .with_context(|| "Failed to parse i30.json")?;
    }

    // Load $Bitmap cluster allocation data
    let bitmap_path = dir.join("bitmap.json");
    if bitmap_path.exists() {
        let content = std::fs::read_to_string(&bitmap_path)?;
        let bitmap_data = serde_json::from_str(&content)
            .with_context(|| "Failed to parse bitmap.json")?;
        input.bitmap_data = Some(bitmap_data);
        eprintln!("  Loaded $Bitmap cluster allocation data from bitmap.json");
    }

    validate_input(&input)?;
    Ok(input)
}

fn load_usn_ndjson(content: &str, source_path: &Path) -> Result<Vec<UsnRecord>> {
    let mut usn_records = Vec::new();
    let mut errors = 0u64;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parsed = serde_json::from_str::<UsnRecord>(line)
            .map_err(|_| ())
            .or_else(|_| serde_json::from_str::<UsnECmdEntry>(line).map(|e| e.into_usn_record()).map_err(|_| ())); 

        match parsed {
            Ok(rec) => usn_records.push(rec),
            Err(_) => {
                errors += 1;
                if errors <= 5 {
                    eprintln!(
                        "  Warning: Failed to parse USN line {} of {}",
                        line_num + 1,
                        source_path.display()
                    );
                }
            }
        }
    }

    if errors > 5 {
        eprintln!("  ... and {} more USN parse errors suppressed", errors - 5);
    }

    Ok(usn_records)
}

/// Validate the input data for basic consistency
fn validate_input(input: &NtfsInput) -> Result<()> {
    if input.mft_entries.is_empty()
        && input.usn_records.is_empty()
        && input.i30_entries.is_empty()
    {
        anyhow::bail!(
            "Input contains no NTFS artifacts. Provide at least one of: \
             mft_entries, usn_records, i30_entries"
        );
    }
    Ok(())
}
