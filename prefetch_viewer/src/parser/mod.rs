pub mod types;
pub mod hash;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::error::PrefetchError;
use types::{FileMetricEntry, PrefetchFile, PrefetchHeader, VolumeInfo};

// ── PECmd NDJSON record ────────────────────────────────────────────────────────

/// One line of a PECmd JSON output file (NDJSON).
/// Fields match PECmd's PascalCase naming via rename_all.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PECmdEntry {
    source_filename: Option<String>,
    executable_name: Option<String>,
    hash: Option<String>,
    size: Option<serde_json::Value>,
    run_count: Option<serde_json::Value>,
    last_run: Option<String>,
    volume0_name: Option<String>,
    volume0_serial: Option<String>,
    volume0_created: Option<String>,
    directories: Option<String>,
    files_loaded: Option<String>,
    previous_run0: Option<String>,
    previous_run1: Option<String>,
    previous_run2: Option<String>,
    previous_run3: Option<String>,
    previous_run4: Option<String>,
    previous_run5: Option<String>,
    previous_run6: Option<String>,
    previous_run7: Option<String>,
    parsing_error: Option<bool>,
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Parse PECmd datetime string "YYYY-MM-DD HH:MM:SS" as UTC.
fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| ndt.and_utc())
}

/// Parse a Value that may be a JSON string "123" or number 123 into u32.
fn value_to_u32(v: &serde_json::Value) -> u32 {
    match v {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Split a comma-separated PECmd field, filtering empty strings.
fn split_csv(s: &str) -> Vec<String> {
    s.split(", ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// ── Public entry point ─────────────────────────────────────────────────────────

/// Ingest a PECmd NDJSON file (one JSON object per line).
/// Returns `(parsed_entries, errors)` where errors are `(line_no, message)` pairs.
/// Skips entries with `ParsingError: true`.
pub fn ingest_pecmd_json(data: &[u8]) -> (Vec<PrefetchFile>, Vec<(usize, String)>) {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(e) => return (vec![], vec![(0, format!("UTF-8 decode error: {e}"))]),
    };

    let mut results = Vec::new();
    let mut errors: Vec<(usize, String)> = Vec::new();

    for (line_idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: PECmdEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(e) => {
                errors.push((line_idx + 1, format!("JSON parse error: {e}")));
                continue;
            }
        };

        if entry.parsing_error.unwrap_or(false) {
            errors.push((
                line_idx + 1,
                format!(
                    "PECmd parsing error for '{}'",
                    entry.source_filename.as_deref().unwrap_or("unknown")
                ),
            ));
            continue;
        }

        match convert_entry(entry) {
            Ok(pf) => results.push(pf),
            Err(e) => errors.push((line_idx + 1, e.to_string())),
        }
    }

    (results, errors)
}

// ── Conversion ─────────────────────────────────────────────────────────────────

fn convert_entry(entry: PECmdEntry) -> Result<PrefetchFile, PrefetchError> {
    let source_filename = entry.source_filename.unwrap_or_default();
    let exe_name = entry.executable_name.unwrap_or_default();
    let prefetch_hash = entry.hash.unwrap_or_default();
    let file_size = entry.size.as_ref().map(value_to_u32).unwrap_or(0);
    let run_count = entry.run_count.as_ref().map(value_to_u32).unwrap_or(0);

    // Collect run times: LastRun first, then PreviousRun0..7
    let run_time_strs: [Option<&str>; 9] = [
        entry.last_run.as_deref(),
        entry.previous_run0.as_deref(),
        entry.previous_run1.as_deref(),
        entry.previous_run2.as_deref(),
        entry.previous_run3.as_deref(),
        entry.previous_run4.as_deref(),
        entry.previous_run5.as_deref(),
        entry.previous_run6.as_deref(),
        entry.previous_run7.as_deref(),
    ];
    let last_run_times: Vec<DateTime<Utc>> = run_time_strs
        .into_iter()
        .flatten()
        .filter_map(|s| parse_datetime(s))
        .collect();

    // Build file metrics from FilesLoaded (comma-separated paths)
    let files_loaded = split_csv(entry.files_loaded.as_deref().unwrap_or(""));
    let file_metrics: Vec<FileMetricEntry> = files_loaded
        .iter()
        .enumerate()
        .map(|(i, f)| FileMetricEntry {
            index: i as u32,
            filename: f.clone(),
            mft_entry: 0,
            mft_sequence: 0,
            flags: 0,
            filename_offset: 0,
            filename_length: f.len() as u32,
        })
        .collect();
    let filename_strings = files_loaded;

    // Build volume from Volume0* fields
    let directories = split_csv(entry.directories.as_deref().unwrap_or(""));
    let vol_created = entry
        .volume0_created
        .as_deref()
        .and_then(parse_datetime)
        .unwrap_or_else(Utc::now);

    let volumes = match entry.volume0_name {
        Some(dev_path) => vec![VolumeInfo {
            device_path: dev_path,
            creation_time: vol_created,
            serial_number: entry.volume0_serial.unwrap_or_default(),
            directories,
        }],
        None => vec![],
    };

    let header = PrefetchHeader {
        version: 0, // not available from PECmd JSON
        exe_name,
        prefetch_hash,
        file_size,
        run_count,
        last_run_times,
        file_metrics_offset: 0,
        file_metrics_count: file_metrics.len() as u32,
        trace_chains_offset: 0,
        trace_chains_count: 0,
        filename_strings_offset: 0,
        filename_strings_size: 0,
        volume_info_offset: 0,
        volume_info_count: volumes.len() as u32,
        volume_info_size: 0,
    };

    Ok(PrefetchFile {
        source_filename,
        header,
        file_metrics,
        volumes,
        filename_strings,
        version: 0,
        was_compressed: false,
    })
}
