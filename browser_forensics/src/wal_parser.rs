// =============================================================================
// Browser Forensics — SQLite WAL/Journal Parser
// =============================================================================
// Recovers recently deleted rows by parsing WAL (Write-Ahead Log) and
// journal files alongside browser SQLite databases.
//
// WAL format: https://www.sqlite.org/walformat.html
// Journal format: https://www.sqlite.org/tempfiles.html
// =============================================================================

use std::path::Path;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use regex::Regex;
use crate::models::WalRecoveredRow;

// ---------------------------------------------------------------------------
// WAL file header constants
// ---------------------------------------------------------------------------

const WAL_MAGIC_BE: u32 = 0x377f0682;
const WAL_MAGIC_LE: u32 = 0x377f0683;
const WAL_HEADER_SIZE: usize = 32;
const FRAME_HEADER_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan all WAL and journal files in a profile directory for recoverable data.
pub fn recover_wal_data(profile_dir: &Path) -> Vec<WalRecoveredRow> {
    let mut recovered = Vec::new();

    // Find all .sqlite-wal files
    if let Ok(entries) = std::fs::read_dir(profile_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.ends_with("-wal") {
                eprintln!("    [*] Scanning WAL: {}", name);
                let mut rows = parse_wal_file(&path);
                recovered.append(&mut rows);
            } else if name.ends_with("-journal") {
                eprintln!("    [*] Scanning journal: {}", name);
                let mut rows = parse_journal_file(&path);
                recovered.append(&mut rows);
            }
        }
    }

    // Also check Network/ subdirectory (Chromium stores Cookies WAL there)
    let network_dir = profile_dir.join("Network");
    if network_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&network_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with("-wal") || name.ends_with("-journal") {
                    eprintln!("    [*] Scanning WAL/journal: Network/{}", name);
                    let mut rows = if name.ends_with("-wal") {
                        parse_wal_file(&path)
                    } else {
                        parse_journal_file(&path)
                    };
                    recovered.append(&mut rows);
                }
            }
        }
    }

    recovered
}

/// Parse a SQLite WAL file and extract recoverable strings.
fn parse_wal_file(wal_path: &Path) -> Vec<WalRecoveredRow> {
    let mut recovered = Vec::new();

    let data = match std::fs::read(wal_path) {
        Ok(d) => d,
        Err(_) => return recovered,
    };

    if data.len() < WAL_HEADER_SIZE {
        return recovered;
    }

    // Parse header
    let mut cursor = Cursor::new(&data[..WAL_HEADER_SIZE]);
    let magic = cursor.read_u32::<BigEndian>().unwrap_or(0);

    if magic != WAL_MAGIC_BE && magic != WAL_MAGIC_LE {
        // Not a valid WAL file — still try string scanning
        return scan_raw_strings(wal_path, &data);
    }

    let _version = cursor.read_u32::<BigEndian>().unwrap_or(0);
    let page_size = cursor.read_u32::<BigEndian>().unwrap_or(4096) as usize;

    if page_size == 0 || page_size > 65536 {
        return scan_raw_strings(wal_path, &data);
    }

    let source_name = wal_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Parse frames
    let mut offset = WAL_HEADER_SIZE;
    let mut frame_num = 0u32;

    while offset + FRAME_HEADER_SIZE + page_size <= data.len() {
        frame_num += 1;

        // Skip frame header (24 bytes)
        let page_data = &data[offset + FRAME_HEADER_SIZE..offset + FRAME_HEADER_SIZE + page_size];

        // Extract strings from this page
        let strings = extract_interesting_strings(page_data);
        for (text, dtype) in strings {
            recovered.push(WalRecoveredRow {
                source_file: source_name.clone(),
                frame_number: Some(frame_num),
                recovered_text: text,
                data_type: Some(dtype),
            });
        }

        offset += FRAME_HEADER_SIZE + page_size;
    }

    // Deduplicate
    dedup_recovered(&mut recovered);
    recovered
}

/// Parse a SQLite journal file and extract recoverable strings.
fn parse_journal_file(journal_path: &Path) -> Vec<WalRecoveredRow> {
    let data = match std::fs::read(journal_path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    scan_raw_strings(journal_path, &data)
}

// ---------------------------------------------------------------------------
// String extraction from raw bytes
// ---------------------------------------------------------------------------

/// Scan raw bytes for interesting forensic strings.
fn scan_raw_strings(path: &Path, data: &[u8]) -> Vec<WalRecoveredRow> {
    let source_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let strings = extract_interesting_strings(data);
    let mut recovered: Vec<WalRecoveredRow> = strings
        .into_iter()
        .map(|(text, dtype)| WalRecoveredRow {
            source_file: source_name.clone(),
            frame_number: None,
            recovered_text: text,
            data_type: Some(dtype),
        })
        .collect();

    dedup_recovered(&mut recovered);
    recovered
}

/// Extract forensically interesting strings from a byte buffer.
fn extract_interesting_strings(data: &[u8]) -> Vec<(String, String)> {
    let mut results = Vec::new();

    // Build regexes once (thread_local for efficiency)
    let url_re = Regex::new(r"https?://[^\x00-\x1f\x7f\s]{4,500}").unwrap();
    let email_re = Regex::new(r"[\w.+-]+@[\w-]+\.[\w.]+").unwrap();
    let path_re = Regex::new(r"(?:[A-Z]:\\[^\x00-\x1f\x7f]{4,200}|/(?:home|Users|tmp|var)[^\x00-\x1f\x7f]{4,200})").unwrap();

    // Convert to string (lossy — replace invalid UTF-8 with replacement chars)
    let text = String::from_utf8_lossy(data);

    // Extract URLs
    for m in url_re.find_iter(&text) {
        let s = m.as_str().to_string();
        // Filter out garbage
        if s.chars().filter(|c| c.is_ascii_graphic()).count() > 8 {
            results.push((s, "url".into()));
        }
    }

    // Extract emails
    for m in email_re.find_iter(&text) {
        let s = m.as_str().to_string();
        if s.len() > 5 && s.contains('.') {
            results.push((s, "email".into()));
        }
    }

    // Extract file paths
    for m in path_re.find_iter(&text) {
        let s = m.as_str().trim().to_string();
        if s.len() > 5 {
            results.push((s, "filepath".into()));
        }
    }

    results
}

/// Deduplicate recovered rows by (source, text) pair.
fn dedup_recovered(rows: &mut Vec<WalRecoveredRow>) {
    let mut seen = std::collections::HashSet::new();
    rows.retain(|r| {
        let key = format!("{}:{}", r.source_file, r.recovered_text);
        seen.insert(key)
    });
}
