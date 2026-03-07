// =============================================================================
// Browser Forensics — Cache Extraction Module
// =============================================================================
// Parses Chrome/Chromium Simple Cache and Firefox cache2 entries.
// Extracts URLs, content types, sizes, and response headers from cache files.
// =============================================================================

use std::path::Path;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use crate::models::CacheExtractedItem;

// ---------------------------------------------------------------------------
// Chrome Simple Cache format constants
// ---------------------------------------------------------------------------

const SIMPLE_CACHE_MAGIC: u64 = 0xfcfb6d1ba7725c30;
const SIMPLE_EOF_MAGIC: u64 = 0xf4fa6f45970d41d8;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse cache entries from a Chromium profile directory.
pub fn parse_chromium_cache(profile_dir: &Path) -> Vec<CacheExtractedItem> {
    let mut items = Vec::new();

    // Chromium stores cache in Cache_Data/ or Cache/ directory
    let cache_dirs = [
        profile_dir.join("Cache_Data"),
        profile_dir.join("Cache"),
        profile_dir.join("Code Cache"),
        profile_dir.join("Service Worker/CacheStorage"),
    ];

    for cache_dir in &cache_dirs {
        if cache_dir.is_dir() {
            eprintln!("    [*] Scanning cache: {}", cache_dir.display());
            parse_simple_cache_dir(cache_dir, &mut items);
        }
    }

    items
}

/// Parse cache entries from a Firefox profile directory.
pub fn parse_firefox_cache(profile_dir: &Path) -> Vec<CacheExtractedItem> {
    let mut items = Vec::new();

    // Firefox stores cache in cache2/entries/
    let cache_dir = profile_dir.join("cache2").join("entries");
    if cache_dir.is_dir() {
        eprintln!("    [*] Scanning Firefox cache2 entries");
        parse_firefox_cache2_dir(&cache_dir, &mut items);
    }

    items
}

// ---------------------------------------------------------------------------
// Chrome Simple Cache parsing
// ---------------------------------------------------------------------------

fn parse_simple_cache_dir(cache_dir: &Path, items: &mut Vec<CacheExtractedItem>) {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Simple cache files end with _0 (first stream — metadata + data)
        if name.ends_with("_0") && path.is_file() {
            if let Some(item) = parse_simple_cache_entry(&path) {
                items.push(item);
            }
        }
    }
}

/// Parse a single Simple Cache _0 file to extract the URL and metadata.
fn parse_simple_cache_entry(path: &Path) -> Option<CacheExtractedItem> {
    let data = std::fs::read(path).ok()?;

    if data.len() < 40 {
        return None;
    }

    // Strategy 1: Try to parse the file header (newer format)
    if let Some(item) = try_parse_with_header(&data, path) {
        return Some(item);
    }

    // Strategy 2: Look for the EOF record at the end of the file
    if let Some(item) = try_parse_from_eof(&data, path) {
        return Some(item);
    }

    // Strategy 3: Scan for URL pattern in the file
    try_parse_by_url_scan(&data, path)
}

fn try_parse_with_header(data: &[u8], path: &Path) -> Option<CacheExtractedItem> {
    if data.len() < 20 {
        return None;
    }

    let mut cursor = Cursor::new(data);
    let magic = cursor.read_u64::<LittleEndian>().ok()?;

    if magic != SIMPLE_CACHE_MAGIC {
        return None;
    }

    let _version = cursor.read_u32::<LittleEndian>().ok()?;
    let key_length = cursor.read_u32::<LittleEndian>().ok()? as usize;
    let _key_hash = cursor.read_u32::<LittleEndian>().ok()?;

    if key_length == 0 || key_length > 8192 {
        return None;
    }

    // Read the key (URL)
    let key_offset = 20usize;
    if key_offset + key_length > data.len() {
        return None;
    }

    let url = String::from_utf8_lossy(&data[key_offset..key_offset + key_length]).to_string();
    if !url.starts_with("http") && !url.starts_with("1/") {
        return None;
    }

    // Clean up URL (remove "1/" prefix used for some entries)
    let clean_url = if url.starts_with("1/") {
        url[2..].to_string()
    } else {
        url
    };

    // Try to find HTTP headers after the key+data
    let headers = extract_http_headers(data);
    let content_type = headers.as_ref().and_then(|h| extract_header_value(h, "content-type"));
    let content_length = headers
        .as_ref()
        .and_then(|h| extract_header_value(h, "content-length"))
        .and_then(|v| v.parse::<u64>().ok());

    Some(CacheExtractedItem {
        url: clean_url,
        content_type,
        content_length,
        request_time: None,
        response_headers: headers,
        cache_file: Some(path.to_string_lossy().to_string()),
    })
}

fn try_parse_from_eof(data: &[u8], path: &Path) -> Option<CacheExtractedItem> {
    // The EOF structure is at the end of the file
    // SimpleFileEOF: { magic: u64, flags: u32, data_crc32: u32, stream_size: u32 }
    // = 20 bytes
    // Before the EOF, there's the HTTP response headers, and before that, the key (URL)

    if data.len() < 28 {
        return None;
    }

    // Check for EOF magic at end
    let eof_start = data.len() - 20;
    let mut cursor = Cursor::new(&data[eof_start..]);
    let eof_magic = cursor.read_u64::<LittleEndian>().ok()?;

    if eof_magic != SIMPLE_EOF_MAGIC {
        return None;
    }

    let _flags = cursor.read_u32::<LittleEndian>().ok()?;
    let _crc = cursor.read_u32::<LittleEndian>().ok()?;
    let stream_size = cursor.read_u32::<LittleEndian>().ok()? as usize;

    // The stream data (HTTP headers) is before the EOF record
    if stream_size > 0 && stream_size < data.len() - 20 {
        let headers_start = eof_start - stream_size;
        let headers_raw = &data[headers_start..eof_start];
        let headers = String::from_utf8_lossy(headers_raw).to_string();

        // Look for URL in the header data or earlier in the file
        let url = extract_url_from_data(data).unwrap_or_else(|| "(unknown)".to_string());

        let content_type = extract_header_value(&headers, "content-type");
        let content_length = extract_header_value(&headers, "content-length")
            .and_then(|v| v.parse::<u64>().ok());

        return Some(CacheExtractedItem {
            url,
            content_type,
            content_length,
            request_time: None,
            response_headers: Some(headers),
            cache_file: Some(path.to_string_lossy().to_string()),
        });
    }

    None
}

fn try_parse_by_url_scan(data: &[u8], path: &Path) -> Option<CacheExtractedItem> {
    let url = extract_url_from_data(data)?;
    let headers = extract_http_headers(data);
    let content_type = headers.as_ref().and_then(|h| extract_header_value(h, "content-type"));

    Some(CacheExtractedItem {
        url,
        content_type,
        content_length: None,
        request_time: None,
        response_headers: headers,
        cache_file: Some(path.to_string_lossy().to_string()),
    })
}

// ---------------------------------------------------------------------------
// Firefox cache2 parsing
// ---------------------------------------------------------------------------

fn parse_firefox_cache2_dir(cache_dir: &Path, items: &mut Vec<CacheExtractedItem>) {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if let Some(item) = parse_firefox_cache2_entry(&path) {
            items.push(item);
        }
    }
}

/// Parse a Firefox cache2 entry file.
/// Firefox cache2 format: content data, then metadata chunk at the end.
fn parse_firefox_cache2_entry(path: &Path) -> Option<CacheExtractedItem> {
    let data = std::fs::read(path).ok()?;

    if data.len() < 8 {
        return None;
    }

    // Firefox cache2 metadata is at the end of the file.
    // The last 4 bytes indicate the metadata offset/size.
    // The metadata contains the key (URL) and other info.

    // Read the last 4 bytes as metadata size
    let meta_end = data.len();
    if meta_end < 4 {
        return None;
    }

    // Try to find URL in the raw data
    let url = extract_url_from_data(&data)?;

    // Try to extract HTTP headers
    let headers = extract_http_headers(&data);
    let content_type = headers.as_ref().and_then(|h| extract_header_value(h, "content-type"));

    Some(CacheExtractedItem {
        url,
        content_type,
        content_length: Some(data.len() as u64),
        request_time: None,
        response_headers: headers,
        cache_file: Some(path.to_string_lossy().to_string()),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the first HTTP URL from raw data.
fn extract_url_from_data(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let url_re = regex::Regex::new(r#"https?://[^\x00-\x1f\x7f\s"'<>]{4,500}"#).ok()?;
    url_re.find(&text).map(|m| m.as_str().to_string())
}

/// Extract HTTP response headers from raw data.
fn extract_http_headers(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    // Look for HTTP response start
    if let Some(start) = text.find("HTTP/") {
        // Find the end of headers (double CRLF or double LF)
        let remaining = &text[start..];
        let end = remaining
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .or_else(|| remaining.find("\n\n").map(|i| i + 2))
            .unwrap_or(std::cmp::min(remaining.len(), 4096));

        let headers = remaining[..end].to_string();
        if headers.len() > 10 {
            return Some(headers);
        }
    }
    None
}

/// Extract a specific header value from HTTP headers text.
fn extract_header_value(headers: &str, header_name: &str) -> Option<String> {
    let lower = headers.to_lowercase();
    let search = format!("{}:", header_name.to_lowercase());
    if let Some(pos) = lower.find(&search) {
        let after = &headers[pos + search.len()..];
        let value = after
            .lines()
            .next()
            .map(|l| l.trim().to_string())?;
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}
