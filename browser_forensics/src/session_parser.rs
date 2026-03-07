// =============================================================================
// Browser Forensics — Session Store Decoder
// =============================================================================
// Chrome:  SNSS format (Session_*, Current Session, Current Tabs)
// Firefox: jsonlz4 format (sessionstore-backups/recovery.jsonlz4)
// =============================================================================

use std::path::Path;
use crate::models::SessionEntry;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse session data from a Chromium profile directory.
pub fn parse_chromium_sessions(profile_dir: &Path) -> Vec<SessionEntry> {
    let mut sessions = Vec::new();

    // Chromium session files
    let session_files = [
        "Current Session",
        "Current Tabs",
        "Last Session",
        "Last Tabs",
    ];

    for fname in &session_files {
        let path = profile_dir.join(fname);
        if path.exists() {
            let mut entries = parse_snss_file(&path, fname);
            sessions.append(&mut entries);
        }
    }

    // Also look for Session_* files in the profile root
    if let Ok(entries) = std::fs::read_dir(profile_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Session_") || name.starts_with("Tabs_") {
                let path = entry.path();
                if path.is_file() {
                    let mut entries = parse_snss_file(&path, &name);
                    sessions.append(&mut entries);
                }
            }
        }
    }

    // Chrome/Brave may store session files under a "Sessions" subdirectory
    let sessions_dir = profile_dir.join("Sessions");
    if sessions_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Session_") || name.starts_with("Tabs_") {
                    let path = entry.path();
                    if path.is_file() {
                        let mut entries = parse_snss_file(&path, &name);
                        sessions.append(&mut entries);
                    }
                }
            }
        }
    }

    sessions
}

/// Parse session data from a Firefox profile directory.
pub fn parse_firefox_sessions(profile_dir: &Path) -> Vec<SessionEntry> {
    let mut sessions = Vec::new();

    // Firefox session store files
    let candidates = [
        profile_dir.join("sessionstore-backups/recovery.jsonlz4"),
        profile_dir.join("sessionstore-backups/recovery.baklz4"),
        profile_dir.join("sessionstore-backups/previous.jsonlz4"),
        profile_dir.join("sessionstore.jsonlz4"),
        profile_dir.join("sessionstore.js"),
        profile_dir.join("sessionstore-backups/recovery.js"),
    ];

    for path in &candidates {
        if path.exists() {
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            if name.ends_with(".jsonlz4") || name.ends_with(".baklz4") {
                // Mozilla LZ4 compressed JSON
                if let Some(mut entries) = parse_jsonlz4_session(path) {
                    eprintln!("    [+] Session (jsonlz4): {} tabs from {}", entries.len(), name);
                    sessions.append(&mut entries);
                }
            } else if name.ends_with(".js") || name.ends_with(".json") {
                // Plain JSON
                if let Some(mut entries) = parse_json_session(path) {
                    eprintln!("    [+] Session (JSON): {} tabs from {}", entries.len(), name);
                    sessions.append(&mut entries);
                }
            }
        }
    }

    sessions
}

// ---------------------------------------------------------------------------
// Chrome SNSS format parser
// ---------------------------------------------------------------------------

/// Parse a Chrome SNSS (Session Save) file.
/// SNSS is a proprietary binary format containing serialized tab/window data.
/// We extract URLs and titles using pattern scanning since the format is not
/// publicly documented and changes between Chrome versions.
fn parse_snss_file(path: &Path, source: &str) -> Vec<SessionEntry> {
    let mut sessions = Vec::new();

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return sessions,
    };

    if data.len() < 8 {
        return sessions;
    }

    // SNSS files start with "SNSS" magic (4 bytes) then version (4 bytes)
    let has_snss_header = data.len() >= 4 && &data[..4] == b"SNSS";

    if !has_snss_header {
        // Try raw string scanning
        return extract_urls_from_binary(&data, source);
    }

    // The SNSS format stores commands as length-prefixed records.
    // Each command: [length: u32 LE] [command_id: u8] [payload]
    // Command types we care about:
    //   1 = SetTabWindow
    //   2 = SetTabIndexInWindow
    //   6 = UpdateTabNavigation (URL, title, etc.)

    let mut offset = 8; // Skip header + version

    while offset + 5 < data.len() {
        // Read payload length (4 bytes LE)
        let payload_len = u32::from_le_bytes([
            data[offset],
            data.get(offset + 1).copied().unwrap_or(0),
            data.get(offset + 2).copied().unwrap_or(0),
            data.get(offset + 3).copied().unwrap_or(0),
        ]) as usize;

        offset += 4;

        if payload_len == 0 || payload_len > data.len() - offset {
            break;
        }

        let payload = &data[offset..offset + payload_len];
        let _command_id = payload[0];

        // Try to extract URLs from the payload
        let payload_str = String::from_utf8_lossy(payload);
        extract_urls_from_text(&payload_str, source, &mut sessions);

        offset += payload_len;
    }

    // Also do a general scan for URLs we might have missed
    let scanned = extract_urls_from_binary(&data, source);
    for entry in scanned {
        if !sessions.iter().any(|s| s.url == entry.url) {
            sessions.push(entry);
        }
    }

    sessions
}

// ---------------------------------------------------------------------------
// Firefox jsonlz4 parser
// ---------------------------------------------------------------------------

/// Parse a Mozilla jsonlz4 compressed session file.
fn parse_jsonlz4_session(path: &Path) -> Option<Vec<SessionEntry>> {
    let data = std::fs::read(path).ok()?;

    // Mozilla LZ4 format:
    // Magic: "mozLz40\0" (8 bytes)
    // Uncompressed size: u32 LE (4 bytes)
    // LZ4 block compressed data
    if data.len() < 12 {
        return None;
    }

    let magic = &data[..8];
    if magic != b"mozLz40\0" {
        eprintln!("    [!] Not a valid mozlz4 file: {:?}", path);
        return None;
    }

    let uncompressed_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

    if uncompressed_size == 0 || uncompressed_size > 256 * 1024 * 1024 {
        return None;
    }

    // Decompress using lz4
    let decompressed = match lz4_flex::decompress(&data[12..], uncompressed_size) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("    [!] LZ4 decompression failed: {}", e);
            return None;
        }
    };

    // Parse the JSON
    let json_str = String::from_utf8_lossy(&decompressed);
    parse_firefox_session_json(&json_str)
}

/// Parse a plain JSON Firefox session file.
fn parse_json_session(path: &Path) -> Option<Vec<SessionEntry>> {
    let raw = std::fs::read_to_string(path).ok()?;
    parse_firefox_session_json(&raw)
}

/// Parse Firefox session JSON structure and extract tabs.
fn parse_firefox_session_json(json_str: &str) -> Option<Vec<SessionEntry>> {
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let mut sessions = Vec::new();

    // Firefox session JSON structure:
    // { "windows": [ { "tabs": [ { "entries": [ { "url": "...", "title": "..." } ] } ] } ] }
    if let Some(windows) = val.get("windows").and_then(|v| v.as_array()) {
        for (win_idx, window) in windows.iter().enumerate() {
            if let Some(tabs) = window.get("tabs").and_then(|v| v.as_array()) {
                for (tab_idx, tab) in tabs.iter().enumerate() {
                    let pinned = tab.get("pinned").and_then(|v| v.as_bool());

                    // Get the last entry (most recent URL for this tab)
                    if let Some(entries) = tab.get("entries").and_then(|v| v.as_array()) {
                        if let Some(entry) = entries.last() {
                            let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let title = entry.get("title").and_then(|v| v.as_str()).map(String::from);

                            if !url.is_empty() && url != "about:blank" {
                                sessions.push(SessionEntry {
                                    url,
                                    title,
                                    window_id: Some(win_idx as u32),
                                    tab_index: Some(tab_idx as u32),
                                    last_active_time: None,
                                    pinned,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Also check for closed windows
    if let Some(closed) = val.get("_closedWindows").and_then(|v| v.as_array()) {
        for window in closed {
            if let Some(tabs) = window.get("tabs").and_then(|v| v.as_array()) {
                for tab in tabs {
                    if let Some(entries) = tab.get("entries").and_then(|v| v.as_array()) {
                        if let Some(entry) = entries.last() {
                            let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let title = entry
                                .get("title")
                                .and_then(|v| v.as_str())
                                .map(|t| format!("[closed] {}", t));

                            if !url.is_empty() && url != "about:blank" {
                                sessions.push(SessionEntry {
                                    url,
                                    title,
                                    window_id: None,
                                    tab_index: None,
                                    last_active_time: None,
                                    pinned: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Some(sessions)
}

// ---------------------------------------------------------------------------
// Binary URL extraction helpers
// ---------------------------------------------------------------------------

/// Extract URLs from binary data by scanning for http:// and https:// patterns.
fn extract_urls_from_binary(data: &[u8], source: &str) -> Vec<SessionEntry> {
    let mut sessions = Vec::new();
    let text = String::from_utf8_lossy(data);

    extract_urls_from_text(&text, source, &mut sessions);
    sessions
}

/// Extract URLs from text data.
fn extract_urls_from_text(text: &str, _source: &str, sessions: &mut Vec<SessionEntry>) {
    let url_re = regex::Regex::new(r"https?://[^\x00-\x1f\x7f\s\x22\x27<>\\\{\}]{4,500}").unwrap();

    for m in url_re.find_iter(text) {
        let url = m.as_str().to_string();
        // Skip internal Chrome URLs
        if url.starts_with("chrome://") || url.starts_with("chrome-extension://") {
            continue;
        }
        if !sessions.iter().any(|s| s.url == url) {
            sessions.push(SessionEntry {
                url,
                title: None,
                window_id: None,
                tab_index: None,
                last_active_time: None,
                pinned: None,
            });
        }
    }
}
