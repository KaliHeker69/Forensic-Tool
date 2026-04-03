#![recursion_limit = "256"]

use chrono::{DateTime, Datelike, Local, NaiveDateTime, Utc};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DEFAULT_OUTPUT: &str = "portal_from_azure/rust-backend/data/dashboard_quick_view.json";
const WINDOWS_EVENT_REPORT_HTML_ENV: &str = "WINDOWS_EVENT_REPORT_HTML";
const FETCHED_FILES_DIR: &str = "/srv/forensics/fetched_files";
const JSON_FILES_PATH_CONFIG_ENV: &str = "JSON_FILES_PATH_CONFIG";
const MAX_LIST_ITEMS: usize = 8;
const MAX_SUPERTIMELINE_EVENTS: usize = 600;
const MAX_CONNECTION_NODES: usize = 64;
const MAX_CONNECTION_LINKS: usize = 96;

#[derive(Deserialize, Default)]
struct DashboardInputPathConfig {
    #[serde(default)]
    memory_analysis: Vec<String>,
    #[serde(default)]
    host_registry_system: Vec<String>,
    #[serde(default)]
    host_registry_software: Vec<String>,
    #[serde(default)]
    host_registry_hardware: Vec<String>,
    #[serde(default)]
    host_registry_sam: Vec<String>,
    #[serde(default)]
    host_event_logs_csv: Vec<String>,
    #[serde(default)]
    host_filesystem_boot_csv: Vec<String>,
    #[serde(default)]
    host_setupapi_logs: Vec<String>,
    #[serde(default)]
    host_filefolderaccess_csv: Vec<String>,
    #[serde(default)]
    browser_report: Vec<String>,
    #[serde(default)]
    network_report: Vec<String>,
    #[serde(default)]
    network_events_csv: Vec<String>,
    #[serde(default)]
    ntfs_mft: Vec<String>,
    #[serde(default)]
    prefetch_report: Vec<String>,
    #[serde(default)]
    user_execution_registry: Vec<String>,
    #[serde(default)]
    user_execution_console_history: Vec<String>,
    #[serde(default)]
    windows_event_report_html: Vec<String>,
    #[serde(default)]
    srum_report: Vec<String>,
}

fn workspace_roots(root_override: Option<PathBuf>) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(root) = root_override {
        roots.push(root);
    }

    if let Ok(from_env) = env::var("FORENSICS_WORKSPACE_ROOT") {
        roots.push(PathBuf::from(from_env));
    }

    if let Ok(cwd) = env::current_dir() {
        roots.push(cwd.clone());
        roots.push(cwd.join(".."));
        roots.push(cwd.join("../.."));
        roots.push(cwd.join("../../.."));
    }

    roots.push(PathBuf::from("/Users/kali/Codes/wsl"));

    let mut unique = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        let key = root.to_string_lossy().into_owned();
        if seen.insert(key) {
            unique.push(root);
        }
    }

    unique
}

fn resolve_existing_path(relative_path: &str, roots: &[PathBuf]) -> Option<PathBuf> {
    let direct = PathBuf::from(relative_path);
    if direct.exists() {
        return Some(direct);
    }

    for root in roots {
        let candidate = root.join(relative_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn read_json(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let bytes = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes.as_slice()
    };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn resolve_json_path_config_file(roots: &[PathBuf]) -> Option<PathBuf> {
    if let Ok(from_env) = env::var(JSON_FILES_PATH_CONFIG_ENV) {
        if let Some(path) = resolve_existing_path(&from_env, roots) {
            return Some(path);
        }
    }

    resolve_existing_path("portal_from_azure/json_files_path.json", roots)
        .or_else(|| resolve_existing_path("json_files_path.json", roots))
}

fn load_input_path_config(roots: &[PathBuf]) -> DashboardInputPathConfig {
    let Some(path) = resolve_json_path_config_file(roots) else {
        return DashboardInputPathConfig::default();
    };

    let Some(raw) = read_text(&path) else {
        return DashboardInputPathConfig::default();
    };

    if raw.trim().is_empty() {
        return DashboardInputPathConfig::default();
    }

    serde_json::from_str(&raw).unwrap_or_default()
}

fn resolve_configured_path(
    roots: &[PathBuf],
    configured_paths: &[String],
    default_paths: &[&str],
) -> Option<PathBuf> {
    for candidate in configured_paths
        .iter()
        .map(String::as_str)
        .chain(default_paths.iter().copied())
    {
        if let Some(path) = resolve_existing_path(candidate, roots) {
            return Some(path);
        }
    }

    None
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let truncated: String = value.chars().take(max_chars).collect();
    format!("{}...", truncated.trim_end())
}

fn parse_event_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        let utc = parsed.with_timezone(&Utc);
        if utc.year() >= 2000 {
            return Some(utc);
        }
    }

    for format in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            let utc = DateTime::<Utc>::from_naive_utc_and_offset(parsed, Utc);
            if utc.year() >= 2000 {
                return Some(utc);
            }
        }
    }

    None
}

fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }

    trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_lowercase()
}

fn extract_ipv4_tokens(text: &str) -> Vec<String> {
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid ipv4 token regex");
    let mut tokens = Vec::new();
    for matched in ip_re.find_iter(text) {
        let candidate = matched.as_str();
        if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
            tokens.push(candidate.to_string());
        }
    }

    tokens
}

fn connection_node_id(entity_type: &str, raw: &str) -> String {
    format!("{}:{}", entity_type, raw.trim().to_lowercase())
}

fn upsert_connection_node(
    nodes: &mut HashMap<String, Value>,
    entity_type: &str,
    raw_key: &str,
    label: &str,
    group: &str,
    detail: &str,
) -> Option<String> {
    let trimmed_key = raw_key.trim();
    let trimmed_label = label.trim();
    if trimmed_key.is_empty() || trimmed_label.is_empty() {
        return None;
    }

    let id = connection_node_id(entity_type, trimmed_key);
    let entry = nodes.entry(id.clone()).or_insert_with(|| {
        json!({
            "id": id.clone(),
            "label": trimmed_label,
            "entity_type": entity_type,
            "group": group,
            "detail": truncate_chars(detail, 160),
            "hits": 0u64,
        })
    });

    let hits = entry
        .get("hits")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .saturating_add(1);
    if let Some(object) = entry.as_object_mut() {
        object.insert("hits".to_string(), json!(hits));

        if object
            .get("detail")
            .and_then(Value::as_str)
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
            && !detail.trim().is_empty()
        {
            object.insert("detail".to_string(), json!(truncate_chars(detail, 160)));
        }
    }

    Some(id)
}

fn record_connection_link(
    links: &mut HashMap<(String, String, String), u64>,
    source: &str,
    target: &str,
    relationship: &str,
) {
    if source.is_empty() || target.is_empty() || source == target {
        return;
    }

    let key = (
        source.to_string(),
        target.to_string(),
        relationship.to_string(),
    );
    *links.entry(key).or_insert(0) += 1;
}

fn sort_and_trim_timeline_events(events: &mut Vec<Value>, limit: usize) {
    events.sort_by(|a, b| {
        as_u64(a.get("epoch_seconds"))
            .cmp(&as_u64(b.get("epoch_seconds")))
            .then_with(|| {
                a.get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("timestamp").and_then(Value::as_str).unwrap_or(""))
            })
    });

    if events.len() > limit {
        let keep_from = events.len().saturating_sub(limit);
        events.drain(0..keep_from);
    }
}

fn macb_signature(flags: &[char]) -> String {
    ['M', 'A', 'C', 'B']
        .iter()
        .map(|flag| if flags.contains(flag) { *flag } else { '.' })
        .collect()
}

fn resolve_case_artifact_dir(roots: &[PathBuf]) -> Option<PathBuf> {
    if let Ok(from_env) = env::var("CASE_ARTIFACT_DIR") {
        let path = PathBuf::from(from_env);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(from_env) = env::var("FETCHED_FILES_DIR") {
        let path = PathBuf::from(from_env);
        if path.exists() {
            return Some(path);
        }
    }

    let default = PathBuf::from(FETCHED_FILES_DIR);
    if default.exists() {
        return Some(default);
    }

    resolve_existing_path("fetched_files", roots)
        .or_else(|| resolve_existing_path("portal_from_azure/rust-backend/fetched_files", roots))
}

fn collect_directory_size_bytes(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }

    let mut total = 0u64;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }

    total
}

fn write_json(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    fs::write(path, pretty)
}

fn as_u64(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        Some(Value::Object(map)) => map.get("decimal").and_then(Value::as_u64).unwrap_or(0),
        _ => 0,
    }
}

fn as_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.trim().to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Some(Value::Object(map)) => {
            if let Some(text) = map.get("decoded").and_then(Value::as_str) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }

            if let Some(text) = map.get("ascii_preview").and_then(Value::as_str) {
                let trimmed = text.trim_matches('.').trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }

            if let Some(decimal) = map.get("decimal").and_then(Value::as_u64) {
                return if decimal == 0 {
                    String::new()
                } else {
                    decimal.to_string()
                };
            }

            String::new()
        }
        _ => String::new(),
    }
}

fn parse_registry_hex_bytes(value: Option<&Value>) -> Option<Vec<u8>> {
    let hex = value?
        .as_object()?
        .get("hex")?
        .as_str()?
        .split_whitespace()
        .filter_map(|part| u8::from_str_radix(part, 16).ok())
        .collect::<Vec<_>>();

    (!hex.is_empty()).then_some(hex)
}

fn parse_registry_systemtime(value: Option<&Value>) -> Option<String> {
    let bytes = parse_registry_hex_bytes(value)?;
    if bytes.len() < 16 {
        return None;
    }

    let parts = bytes
        .chunks_exact(2)
        .take(8)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if parts.len() != 8 {
        return None;
    }

    let year = parts[0] as i32;
    let month = parts[1] as u32;
    let day = parts[3] as u32;
    let hour = parts[4] as u32;
    let minute = parts[5] as u32;
    let second = parts[6] as u32;
    let millis = parts[7] as u32;

    let parsed = chrono::NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_milli_opt(hour, minute, second, millis)?;
    Some(parsed.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn format_utc_timestamp(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn normalize_display_timestamp(raw: &str) -> String {
    parse_event_timestamp(raw)
        .map(format_utc_timestamp)
        .unwrap_or_else(|| raw.trim().to_string())
}

fn format_mac_address(value: Option<&Value>) -> String {
    parse_registry_hex_bytes(value)
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default()
}

fn filetime_to_timestamp(filetime: u64) -> Option<String> {
    const FILETIME_EPOCH: u64 = 116_444_736_000_000_000;

    if filetime <= FILETIME_EPOCH || filetime == u64::MAX {
        return None;
    }

    let ticks = filetime.saturating_sub(FILETIME_EPOCH);
    let seconds = (ticks / 10_000_000) as i64;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    let parsed = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    Some(format_utc_timestamp(parsed))
}

fn unix_timestamp_to_string(value: u64) -> Option<String> {
    let parsed = DateTime::<Utc>::from_timestamp(value as i64, 0)?;
    Some(format_utc_timestamp(parsed))
}

fn filetime_parts_to_timestamp(low: u64, high: u64) -> Option<String> {
    let combined = (high << 32) | low;
    filetime_to_timestamp(combined)
}

fn extract_filetime_from_value(value: Option<&Value>) -> Option<String> {
    let bytes = parse_registry_hex_bytes(value)?;
    if bytes.len() < 8 {
        return None;
    }

    let raw = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    filetime_to_timestamp(raw)
}

fn collect_registry_index<'a>(node: &'a Value, index: &mut HashMap<String, &'a Value>) {
    if let Some(path) = node.get("path").and_then(Value::as_str) {
        index.insert(path.to_string(), node);
    }

    for child in node
        .get("subkeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        collect_registry_index(child, index);
    }
}

fn build_registry_index<'a>(hive: &'a Value) -> HashMap<String, &'a Value> {
    let mut index = HashMap::new();
    let root = hive.get("root").unwrap_or(hive);
    collect_registry_index(root, &mut index);
    index
}

fn registry_value<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.get("values")
        .and_then(Value::as_array)?
        .iter()
        .find(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .map(|candidate| candidate.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .and_then(|entry| entry.get("data"))
}

fn registry_subkeys<'a>(node: &'a Value) -> Vec<&'a Value> {
    node.get("subkeys")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn registry_values<'a>(node: &'a Value) -> Vec<&'a Value> {
    node.get("values")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn value_name(entry: &Value) -> String {
    entry
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn value_data<'a>(entry: &'a Value) -> Option<&'a Value> {
    entry.get("data")
}

fn parse_utf16le_string(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }

    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words).trim().to_string()
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

fn is_noise_usb_device(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }

    lower.starts_with("@usb")
        || lower.starts_with("@input")
        || lower.contains("root hub")
        || lower.contains("composite device")
        || lower.contains("input device")
        || lower.contains("host controller")
        || lower.contains("generic superspeed usb hub")
        || lower.contains("usb xhci compliant host controller")
}

fn non_empty_strings(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn file_stem_string(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn username_from_parsed_artifact(path: &Path) -> String {
    let stem = file_stem_string(path);
    stem.split('_')
        .find(|part| !part.trim().is_empty() && !part.chars().all(|ch| ch.is_ascii_digit()))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn drive_letter_from_path(value: &str) -> Option<String> {
    let regex = Regex::new(r"(?i)\b([A-Z]:\\?)").ok()?;
    let captures = regex.captures(value)?;
    let drive = captures
        .get(1)?
        .as_str()
        .trim_end_matches('\\')
        .to_ascii_uppercase();
    (!drive.is_empty() && drive != "C:").then_some(drive)
}

fn infer_architecture(build_lab: &str) -> String {
    let lower = build_lab.to_ascii_lowercase();
    if lower.contains("amd64") || lower.contains("x64") {
        "AMD64 (x64)".to_string()
    } else if lower.contains("arm64") {
        "ARM64".to_string()
    } else if lower.contains("x86") {
        "x86".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn map_uac_prompt_level(raw: u64) -> String {
    match raw {
        0 => "Elevate without prompting".to_string(),
        1 => "Prompt for credentials on secure desktop".to_string(),
        2 => "Prompt for consent on secure desktop".to_string(),
        3 => "Prompt for credentials".to_string(),
        4 => "Prompt for consent".to_string(),
        5 => "Default".to_string(),
        other => format!("Level {other}"),
    }
}

fn firewall_status(value: u64) -> String {
    if value == 0 {
        "Off".to_string()
    } else {
        "On".to_string()
    }
}

fn remote_desktop_status(deny_connections: u64) -> String {
    if deny_connections == 0 {
        "Allowed".to_string()
    } else {
        "Blocked".to_string()
    }
}

fn account_state_label(sid: &str, flags: u64, state: u64, source: &str) -> String {
    let mut parts = Vec::new();

    if sid.ends_with("-500") {
        parts.push("Builtin Admin".to_string());
    } else if sid.ends_with("-501") {
        parts.push("Guest".to_string());
    }

    if flags & 0x1 == 0x1 {
        parts.push("Temp".to_string());
    }

    if state == 0 {
        parts.push("Healthy".to_string());
    } else {
        parts.push(format!("State 0x{state:03x}"));
    }

    if !source.is_empty() {
        parts.push(source.to_string());
    }

    parts.join(" · ")
}

fn latest_profile_activity(load: Option<String>, unload: Option<String>, fallback: &str) -> String {
    let mut candidates = Vec::new();
    if let Some(value) = load {
        candidates.push(value);
    }
    if let Some(value) = unload {
        candidates.push(value);
    }
    candidates.push(fallback.to_string());

    candidates
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .max_by(|left, right| parse_event_timestamp(left).cmp(&parse_event_timestamp(right)))
        .map(|value| normalize_display_timestamp(&value))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn parse_hex_rid(raw: &str) -> Option<u32> {
    u32::from_str_radix(raw.trim(), 16).ok()
}

fn decode_sam_f_metrics(value: Option<&Value>) -> (Option<String>, Option<String>, u64, u64, u32) {
    let bytes = match parse_registry_hex_bytes(value) {
        Some(bytes) if bytes.len() >= 68 => bytes,
        _ => return (None, None, 0, 0, 0),
    };

    let read_u64 = |offset: usize| -> u64 {
        bytes
            .get(offset..offset + 8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    };
    let read_u16 = |offset: usize| -> u64 {
        bytes
            .get(offset..offset + 2)
            .and_then(|slice| slice.try_into().ok())
            .map(u16::from_le_bytes)
            .map(u64::from)
            .unwrap_or(0)
    };
    let read_u32 = |offset: usize| -> u32 {
        bytes
            .get(offset..offset + 4)
            .and_then(|slice| slice.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0)
    };

    let last_logon = filetime_to_timestamp(read_u64(0x08));
    let password_last_set = filetime_to_timestamp(read_u64(0x18));
    let bad_password_count = read_u16(0x40);
    let logon_count = read_u16(0x42);
    let account_flags = read_u32(0x38);

    (
        last_logon,
        password_last_set,
        logon_count,
        bad_password_count,
        account_flags,
    )
}

fn sam_account_flags_label(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0002 != 0 {
        parts.push("Disabled");
    }
    if flags & 0x0010 != 0 {
        parts.push("Locked/Restricted");
    }
    if flags & 0x0020 != 0 {
        parts.push("NoPasswordReq");
    }
    if flags & 0x0200 != 0 {
        parts.push("Normal");
    }
    if parts.is_empty() {
        format!("0x{flags:03x}")
    } else {
        parts.join(" · ")
    }
}

fn extract_builtin_admin_rids(
    sam_index: &HashMap<String, &Value>,
) -> std::collections::HashSet<u32> {
    let mut admin_rids = std::collections::HashSet::new();
    let root_path = "ROOT\\SAM\\Domains\\Builtin\\Aliases\\Members";

    for (path, node) in sam_index {
        if !path.starts_with(root_path) {
            continue;
        }

        let member_rid = path.rsplit('\\').next().and_then(parse_hex_rid);
        let Some(member_rid) = member_rid else {
            continue;
        };

        let default_value = registry_value(node, "(Default)");
        let mut alias_ids = Vec::new();
        if let Some(decimal) = default_value
            .and_then(|value| value.as_object())
            .and_then(|map| map.get("decimal"))
            .and_then(Value::as_u64)
        {
            alias_ids.push(decimal as u32);
        }
        if let Some(bytes) = parse_registry_hex_bytes(default_value) {
            for chunk in bytes.chunks_exact(4) {
                alias_ids.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }

        if alias_ids.iter().any(|alias| *alias == 544) {
            admin_rids.insert(member_rid);
        }
    }

    admin_rids
}

fn normalize_account_name(raw: &str) -> String {
    raw.trim()
        .rsplit('\\')
        .next()
        .unwrap_or(raw.trim())
        .trim()
        .to_ascii_lowercase()
}

fn parse_event_target_account(row: &HashMap<String, String>) -> String {
    let payload_1 = row.get("PayloadData1").map(String::as_str).unwrap_or("");
    if let Some(target) = payload_1.split("Target:").nth(1) {
        return normalize_account_name(target);
    }

    let username = row.get("UserName").map(String::as_str).unwrap_or("").trim();
    let username = username.strip_prefix("Target: ").unwrap_or(username);
    normalize_account_name(username)
}

fn network_category_label(value: u64) -> String {
    match value {
        0 => "Public".to_string(),
        1 => "Private".to_string(),
        2 => "Domain".to_string(),
        other => format!("Category {other}"),
    }
}

fn normalize_install_date(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() == 8 && trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return format!("{}-{}-{}", &trimmed[0..4], &trimmed[4..6], &trimmed[6..8]);
    }
    normalize_display_timestamp(trimmed)
}

fn pick_latest_matching_file(path: &Path, needle: &str) -> Option<PathBuf> {
    if path.is_file() {
        return Some(path.to_path_buf());
    }

    let mut matches = fs::read_dir(path)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|candidate| candidate.is_file())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains(needle))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| {
        right
            .file_name()
            .and_then(|name| name.to_str())
            .cmp(&left.file_name().and_then(|name| name.to_str()))
    });
    matches.into_iter().next()
}

fn sort_label_counts(map: HashMap<String, u64>, limit: usize) -> Vec<Value> {
    let mut items: Vec<(String, u64)> = map.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
        .into_iter()
        .take(limit)
        .map(|(label, count)| json!({ "label": label, "count": count }))
        .collect()
}

fn extract_domain(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);

    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches("www.")
        .to_string()
}

fn resolve_memory_source(roots: &[PathBuf]) -> Option<PathBuf> {
    let config = load_input_path_config(roots);
    resolve_configured_path(
        roots,
        &config.memory_analysis,
        &[
            "memory_corelation/reports/analysis.json",
            "memory_corelation/analysis.json",
            "portal_from_azure/rust-backend/data/memory_analysis.json",
        ],
    )
}

fn default_memory_quickview(source: String) -> Value {
    json!({
        "source": source,
        "risk_level": "UNKNOWN",
        "risk_score": 0,
        "total_findings": 0,
        "unique_pids": 0,
        "unique_ips": 0,
        "severity_segments": [],
        "top_categories": [],
    })
}

fn build_memory_quickview(roots: &[PathBuf]) -> Value {
    let Some(path) = resolve_memory_source(roots) else {
        return default_memory_quickview(String::new());
    };

    let Some(json) = read_json(&path) else {
        return default_memory_quickview(path.to_string_lossy().to_string());
    };

    let Some(summary) = json.get("summary") else {
        return default_memory_quickview(path.to_string_lossy().to_string());
    };

    let critical_count = as_u64(summary.get("critical_count"));
    let high_count = as_u64(summary.get("high_count"));
    let medium_count = as_u64(summary.get("medium_count"));
    let low_count = as_u64(summary.get("low_count"));
    let info_count = as_u64(summary.get("info_count"));
    let severity_total = [
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
    ]
    .iter()
    .sum::<u64>()
    .max(1);

    let severity_segments = vec![
        json!({"label":"Critical","count":critical_count,"percent":((critical_count as f64 / severity_total as f64) * 1000.0).round() / 10.0,"color":"#ff7351"}),
        json!({"label":"High","count":high_count,"percent":((high_count as f64 / severity_total as f64) * 1000.0).round() / 10.0,"color":"#f6b73c"}),
        json!({"label":"Medium","count":medium_count,"percent":((medium_count as f64 / severity_total as f64) * 1000.0).round() / 10.0,"color":"#78b8ff"}),
        json!({"label":"Low","count":low_count,"percent":((low_count as f64 / severity_total as f64) * 1000.0).round() / 10.0,"color":"#2ea043"}),
        json!({"label":"Info","count":info_count,"percent":((info_count as f64 / severity_total as f64) * 1000.0).round() / 10.0,"color":"#7b8490"}),
    ];

    let mut category_counts = HashMap::new();
    if let Some(categories) = json.get("findings_by_category").and_then(Value::as_object) {
        for (category, list) in categories {
            let count = list.as_array().map(|arr| arr.len() as u64).unwrap_or(0);
            category_counts.insert(category.clone(), count);
        }
    }

    json!({
        "source": path.to_string_lossy().to_string(),
        "risk_level": summary.get("risk_level").and_then(Value::as_str).unwrap_or("UNKNOWN"),
        "risk_score": as_u64(summary.get("risk_score")),
        "total_findings": as_u64(summary.get("total_findings")),
        "unique_pids": as_u64(summary.get("unique_pids")),
        "unique_ips": as_u64(summary.get("unique_ips")),
        "severity_segments": severity_segments,
        "top_categories": sort_label_counts(category_counts, 6),
        "analysis_metadata": json.get("metadata").cloned().unwrap_or(Value::Null),
        "findings_by_category": json.get("findings_by_category").cloned().unwrap_or(Value::Null),
    })
}

fn default_browser_quickview(source: String) -> Value {
    json!({
        "source": source,
        "total_browsers": 0,
        "total_history_entries": 0,
        "total_downloads": 0,
        "total_cookies": 0,
        "total_sessions": 0,
        "browsers_found": [],
        "top_domains": [],
        "recent_history": [],
    })
}

fn build_browser_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let Some(path) = resolve_configured_path(
        roots,
        &config.browser_report,
        &["browser_forensics/report.json"],
    ) else {
        return default_browser_quickview(String::new());
    };

    let Some(json) = read_json(&path) else {
        return default_browser_quickview(path.to_string_lossy().to_string());
    };

    let Some(summary) = json.get("summary") else {
        return default_browser_quickview(path.to_string_lossy().to_string());
    };

    let browsers_found = summary
        .get("browsers_found")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut domain_counts = HashMap::new();
    let mut recent_history = Vec::new();

    if let Some(artifacts) = json.get("artifacts").and_then(Value::as_array) {
        for artifact in artifacts {
            let browser = artifact
                .get("browser")
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_string();

            if let Some(history_entries) = artifact.get("history").and_then(Value::as_array) {
                for entry in history_entries {
                    let url = entry
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let title = entry
                        .get("title")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or("Untitled")
                        .to_string();
                    let last_visit = entry
                        .get("last_visit_time")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string();

                    let domain = extract_domain(&url);
                    if !domain.is_empty() {
                        *domain_counts.entry(domain.clone()).or_insert(0) += 1;
                    }

                    recent_history.push(json!({
                        "browser": browser,
                        "title": title,
                        "url": url,
                        "domain": domain,
                        "last_visit": last_visit,
                    }));
                }
            }
        }
    }

    recent_history.sort_by(|a, b| {
        b.get("last_visit")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(a.get("last_visit").and_then(Value::as_str).unwrap_or(""))
            .then_with(|| {
                a.get("browser")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("browser").and_then(Value::as_str).unwrap_or(""))
            })
    });
    recent_history.truncate(8);

    json!({
        "source": path.to_string_lossy().to_string(),
        "total_browsers": as_u64(summary.get("total_browsers")),
        "total_history_entries": as_u64(summary.get("total_history_entries")),
        "total_downloads": as_u64(summary.get("total_downloads")),
        "total_cookies": as_u64(summary.get("total_cookies")),
        "total_sessions": as_u64(summary.get("total_sessions")),
        "browsers_found": browsers_found,
        "top_domains": sort_label_counts(domain_counts, 6),
        "recent_history": recent_history,
    })
}

fn default_execution_quickview(source: String) -> Value {
    json!({
        "source": source,
        "command_count": 0,
        "recent_commands": [],
    })
}

fn normalize_command(command: &str) -> String {
    command
        .replace("\\\\", "\\")
        .replace("\\\"", "\"")
        .replace("\n", " ")
        .replace("\r", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn execution_command_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let normalized = normalize_command(text);
            (!normalized.is_empty()).then_some(normalized)
        }
        Value::Array(items) => {
            let text = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let normalized = normalize_command(&text);
            (!normalized.is_empty()).then_some(normalized)
        }
        Value::Object(map) => map
            .get("data")
            .and_then(execution_command_text)
            .or_else(|| {
                map.get("ascii_preview")
                    .and_then(Value::as_str)
                    .map(normalize_command)
            })
            .or_else(|| {
                map.get("text")
                    .and_then(Value::as_str)
                    .map(normalize_command)
            }),
        _ => None,
    }
}

fn collect_runmru_commands_from_registry_key(
    key: &Value,
    commands: &mut Vec<Value>,
    seen: &mut std::collections::HashSet<String>,
) {
    let Some(path) = key.get("path").and_then(Value::as_str) else {
        return;
    };
    let path_lower = path.to_lowercase();
    let name = key.get("name").and_then(Value::as_str).unwrap_or("");
    if !name.eq_ignore_ascii_case("runmru") && !path_lower.contains("\\runmru") {
        if let Some(subkeys) = key.get("subkeys").and_then(Value::as_array) {
            for subkey in subkeys {
                collect_runmru_commands_from_registry_key(subkey, commands, seen);
            }
        }
        return;
    }

    let timestamp = key
        .get("last_write_time")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    let mut command_map: HashMap<String, String> = HashMap::new();
    let mut mru_order: Vec<String> = Vec::new();

    if let Some(values) = key.get("values").and_then(Value::as_array) {
        for value in values {
            let value_name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let value_name_lower = value_name.to_lowercase();
            if value_name.is_empty() || value_name == "(Default)" || value_name_lower == "mrulistex"
            {
                continue;
            }

            if value_name_lower == "mrulist" {
                if let Some(order) = value.get("data").and_then(Value::as_str) {
                    mru_order = order
                        .chars()
                        .filter(|ch| !ch.is_whitespace())
                        .map(|ch| ch.to_string())
                        .collect();
                }
                continue;
            }

            if let Some(command) = value.get("data").and_then(execution_command_text) {
                command_map.insert(value_name.to_string(), command);
            }
        }
    }

    let mut ordered_names = Vec::new();
    if !mru_order.is_empty() {
        for name in mru_order {
            if command_map.contains_key(&name) {
                ordered_names.push(name);
            }
        }
    } else {
        let mut names: Vec<_> = command_map.keys().cloned().collect();
        names.sort();
        names.reverse();
        ordered_names = names;
    }

    for value_name in ordered_names {
        let Some(command) = command_map.get(&value_name).cloned() else {
            continue;
        };
        let key_id = format!(
            "runmru|{}|{}",
            timestamp.to_lowercase(),
            command.to_lowercase()
        );
        if !seen.insert(key_id) {
            continue;
        }

        commands.push(json!({
            "timestamp": timestamp,
            "process": "RunMRU",
            "command": command,
            "pid": "n/a",
            "source": path,
        }));
    }

    if let Some(subkeys) = key.get("subkeys").and_then(Value::as_array) {
        for subkey in subkeys {
            collect_runmru_commands_from_registry_key(subkey, commands, seen);
        }
    }
}

fn collect_console_history_commands(
    path: &Path,
    commands: &mut Vec<Value>,
    seen: &mut std::collections::HashSet<String>,
) {
    let Some(raw) = read_text(path) else {
        return;
    };

    let timestamp = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .map(|modified| {
            let dt: DateTime<Utc> = modified.into();
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        })
        .unwrap_or_else(|| "ConsoleHost history".to_string());

    for line in raw.lines().rev() {
        let command = normalize_command(line);
        if command.is_empty() {
            continue;
        }

        let key_id = format!("consolehost|{}", command.to_lowercase());
        if !seen.insert(key_id) {
            continue;
        }

        commands.push(json!({
            "timestamp": timestamp,
            "process": "ConsoleHost",
            "command": command,
            "pid": "n/a",
            "source": path.to_string_lossy().to_string(),
        }));
        if commands.len() >= MAX_LIST_ITEMS * 4 {
            break;
        }
    }
}

fn fallback_recent_commands_from_memory(roots: &[PathBuf]) -> Vec<Value> {
    let mut commands = Vec::new();
    let Some(path) = resolve_configured_path(
        roots,
        &[],
        &[
            "memory_corelation/jsonl/cmdscan.jsonl",
            "memory_corelation/jsonl/cmdline.jsonl",
        ],
    ) else {
        return commands;
    };
    let Ok(file) = fs::File::open(&path) else {
        return commands;
    };

    let mut seen = std::collections::HashSet::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let property = record.get("Property").and_then(Value::as_str).unwrap_or("");
        let is_command = property.contains("CommandBucket_Command_");
        let is_bucket = property == "_COMMAND_HISTORY.CommandBucket";
        if !is_command && !is_bucket {
            continue;
        }

        let Some(command) = record
            .get("Data")
            .and_then(Value::as_str)
            .map(normalize_command)
        else {
            continue;
        };
        if command.is_empty() {
            continue;
        }

        let pid = record.get("PID").and_then(Value::as_u64).unwrap_or(0);
        let process = record
            .get("Application")
            .and_then(Value::as_str)
            .or_else(|| record.get("Process").and_then(Value::as_str))
            .unwrap_or("conhost.exe")
            .to_string();
        let key_id = format!("memory|{}|{}", pid, command.to_lowercase());
        if !seen.insert(key_id) {
            continue;
        }

        commands.push(json!({
            "timestamp": "memory cmdscan",
            "process": process,
            "command": command,
            "pid": if pid > 0 { pid.to_string() } else { "n/a".to_string() },
            "source": "memory_corelation/jsonl/cmdscan.jsonl",
        }));

        if commands.len() >= MAX_LIST_ITEMS * 4 {
            break;
        }
    }

    commands
}

fn build_execution_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let registry_path = resolve_configured_path(
        roots,
        &config.user_execution_registry,
        &[
            "registry_parser/output/NTUSER.DAT.json",
            "registry_parser/output/ntuser.dat.json",
            "registry_parser/output/combined.json",
        ],
    );
    let console_history_path = resolve_configured_path(
        roots,
        &config.user_execution_console_history,
        &[
            "ConsoleHost_history.txt",
            "PowerShell/ConsoleHost_history.txt",
            "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        ],
    );

    let mut commands = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut sources = Vec::new();

    if let Some(path) = registry_path.as_ref() {
        if let Some(json) = read_json(path) {
            let root = json.get("root").unwrap_or(&json);
            collect_runmru_commands_from_registry_key(root, &mut commands, &mut seen);
            sources.push(path.to_string_lossy().to_string());
        } else {
            sources.push(path.to_string_lossy().to_string());
        }
    }

    if let Some(path) = console_history_path.as_ref() {
        collect_console_history_commands(path, &mut commands, &mut seen);
        sources.push(path.to_string_lossy().to_string());
    }

    if commands.is_empty() {
        commands = fallback_recent_commands_from_memory(roots);
        if commands.is_empty() {
            return default_execution_quickview(sources.join(" | "));
        }
        sources.push("memory_corelation/jsonl/cmdscan.jsonl".to_string());
    }

    commands.sort_by(|a, b| {
        let a_ts = a.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let b_ts = b.get("timestamp").and_then(Value::as_str).unwrap_or("");
        parse_event_timestamp(b_ts)
            .cmp(&parse_event_timestamp(a_ts))
            .then_with(|| {
                a.get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("command").and_then(Value::as_str).unwrap_or(""))
            })
    });
    commands.truncate(MAX_LIST_ITEMS);

    json!({
        "source": sources.join(" | "),
        "command_count": commands.len() as u64,
        "recent_commands": commands,
    })
}

fn default_host_information_quickview(source: String) -> Value {
    json!({
        "source": source,
        "hostname": "",
        "machine_guid": "",
        "registered_owner": "",
        "registered_organization": "",
        "product_id": "",
        "domain": "",
        "time_zone": "",
        "current_control_set": "",
        "os_product_name": "",
        "os_display_version": "",
        "os_build": "",
        "install_date": "",
        "last_shutdown_time": "",
        "system_root": "",
        "os_architecture": "",
        "installation_type": "",
        "cpu_name": "",
        "cpu_count": 0,
        "bios_vendor": "",
        "bios_version": "",
        "system_manufacturer": "",
        "system_model": "",
        "physical_memory_human": "",
        "firewall_domain": "",
        "firewall_public": "",
        "firewall_standard": "",
        "uac_status": "",
        "uac_level": "",
        "remote_desktop_status": "",
        "remote_desktop_port": "",
        "remote_desktop_nla": "",
        "defender_status": "",
        "defender_tamper_protection": "",
        "timeline_anchors": [],
        "active_hardware_profile": "",
        "hardware_profiles": [],
        "network_interfaces": [],
        "network_profiles": [],
        "storage_volumes": [],
        "usb_storage_devices": [],
        "usb_user_attribution": [],
        "usb_supporting_evidence": [],
        "connected_devices": [],
        "system_locale": "",
        "keyboard_layouts": [],
        "country_code": "",
        "user_locale_hints": [],
        "input_method_hints": [],
        "bitlocker_status": "Unknown",
        "volume_shadow_copies_present": false,
        "third_party_encryption": [],
        "user_accounts": [],
        "installed_software_count": 0,
        "installed_software": [],
        "forensic_note": "",
    })
}

fn build_host_information_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);

    let system_path = resolve_configured_path(
        roots,
        &config.host_registry_system,
        &["registry_parser/output/SYSTEM.json"],
    );
    let software_path = resolve_configured_path(
        roots,
        &config.host_registry_software,
        &["registry_parser/output/SOFTWARE.json"],
    );
    let hardware_path = resolve_configured_path(
        roots,
        &config.host_registry_hardware,
        &["registry_parser/output/HARDWARE.json"],
    );
    let sam_path = resolve_configured_path(
        roots,
        &config.host_registry_sam,
        &["registry_parser/output/SAM.json"],
    );
    let boot_csv_path = resolve_configured_path(
        roots,
        &config.host_filesystem_boot_csv,
        &["Transfer/Parsed/FileSystem"],
    );
    let setupapi_logs_path = resolve_configured_path(roots, &config.host_setupapi_logs, &[]);
    let filefolderaccess_path = resolve_configured_path(
        roots,
        &config.host_filefolderaccess_csv,
        &["Transfer/Parsed/FileFolderAccess"],
    );
    let user_locale_hive_path =
        resolve_configured_path(roots, &config.user_execution_registry, &[]);

    let mut sources = Vec::new();
    if let Some(path) = system_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = software_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = hardware_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = sam_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = boot_csv_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = setupapi_logs_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = filefolderaccess_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }
    if let Some(path) = user_locale_hive_path.as_ref() {
        sources.push(path.to_string_lossy().to_string());
    }

    let Some(system_hive) = system_path.as_ref().and_then(|path| read_json(path)) else {
        return default_host_information_quickview(sources.join(" | "));
    };
    let Some(software_hive) = software_path.as_ref().and_then(|path| read_json(path)) else {
        return default_host_information_quickview(sources.join(" | "));
    };

    let hardware_hive = hardware_path.as_ref().and_then(|path| read_json(path));
    let sam_hive = sam_path.as_ref().and_then(|path| read_json(path));
    let user_locale_hive = user_locale_hive_path
        .as_ref()
        .and_then(|path| read_json(path));
    let has_hardware_hive = hardware_hive.is_some();

    let system_index = build_registry_index(&system_hive);
    let software_index = build_registry_index(&software_hive);
    let hardware_index = hardware_hive
        .as_ref()
        .map(build_registry_index)
        .unwrap_or_default();
    let sam_index = sam_hive
        .as_ref()
        .map(build_registry_index)
        .unwrap_or_default();
    let user_locale_index = user_locale_hive
        .as_ref()
        .map(build_registry_index)
        .unwrap_or_default();

    let current_control_set_number = as_u64(
        system_index
            .get("ROOT\\Select")
            .and_then(|node| registry_value(node, "Current")),
    );
    let current_control_set = if current_control_set_number > 0 {
        format!("ControlSet{current_control_set_number:03}")
    } else {
        "ControlSet001".to_string()
    };

    let current_version = software_index
        .get("ROOT\\Microsoft\\Windows NT\\CurrentVersion")
        .copied();
    let computer_name_path =
        format!("ROOT\\{current_control_set}\\Control\\ComputerName\\ComputerName");
    let tcpip_parameters_path = format!("ROOT\\{current_control_set}\\Services\\Tcpip\\Parameters");
    let timezone_path = format!("ROOT\\{current_control_set}\\Control\\TimeZoneInformation");
    let firewall_domain_path = format!(
        "ROOT\\{current_control_set}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile"
    );
    let firewall_public_path = format!(
        "ROOT\\{current_control_set}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    );
    let firewall_standard_path = format!(
        "ROOT\\{current_control_set}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"
    );
    let terminal_server_path = format!("ROOT\\{current_control_set}\\Control\\Terminal Server");
    let rdp_tcp_path =
        format!("ROOT\\{current_control_set}\\Control\\Terminal Server\\WinStations\\RDP-Tcp");

    let hostname = system_index
        .get(&computer_name_path)
        .and_then(|node| registry_value(node, "ComputerName"))
        .map(|value| as_string(Some(value)))
        .filter(|value| !value.is_empty())
        .or_else(|| {
            system_index
                .get(&tcpip_parameters_path)
                .and_then(|node| registry_value(node, "Hostname"))
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default();

    let domain = system_index
        .get(&tcpip_parameters_path)
        .and_then(|node| {
            registry_value(node, "DhcpDomain").or_else(|| registry_value(node, "Domain"))
        })
        .map(|value| as_string(Some(value)))
        .filter(|value| !value.is_empty())
        .unwrap_or_default();

    let machine_guid = software_index
        .get("ROOT\\Microsoft\\Cryptography")
        .and_then(|node| registry_value(node, "MachineGuid"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();

    let registered_owner = current_version
        .and_then(|node| registry_value(node, "RegisteredOwner"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let registered_organization = current_version
        .and_then(|node| registry_value(node, "RegisteredOrganization"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let product_id = current_version
        .and_then(|node| registry_value(node, "ProductId"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let time_zone = system_index
        .get(&timezone_path)
        .and_then(|node| registry_value(node, "TimeZoneKeyName"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let os_product_name = current_version
        .and_then(|node| registry_value(node, "ProductName"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let os_display_version = current_version
        .and_then(|node| {
            registry_value(node, "DisplayVersion").or_else(|| registry_value(node, "ReleaseId"))
        })
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let build_number = current_version
        .and_then(|node| {
            registry_value(node, "CurrentBuildNumber")
                .or_else(|| registry_value(node, "CurrentBuild"))
        })
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let ubr = current_version
        .and_then(|node| registry_value(node, "UBR"))
        .map(|value| as_u64(Some(value)))
        .unwrap_or(0);
    let os_build = if !build_number.is_empty() && ubr > 0 {
        format!("{build_number}.{ubr}")
    } else {
        build_number
    };
    let system_root = current_version
        .and_then(|node| registry_value(node, "SystemRoot"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let build_lab = current_version
        .and_then(|node| {
            registry_value(node, "BuildLabEx").or_else(|| registry_value(node, "BuildLab"))
        })
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let environment_path =
        format!("ROOT\\{current_control_set}\\Control\\Session Manager\\Environment");
    let environment_node = system_index.get(&environment_path).copied();
    let os_architecture = environment_node
        .and_then(|node| registry_value(node, "PROCESSOR_ARCHITECTURE"))
        .map(|value| as_string(Some(value)))
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let inferred = infer_architecture(&build_lab);
            (!inferred.is_empty()).then_some(inferred)
        })
        .unwrap_or_else(|| "Unknown".to_string());
    let installation_type = current_version
        .and_then(|node| registry_value(node, "InstallationType"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();

    let install_time = current_version
        .and_then(|node| registry_value(node, "InstallTime"))
        .and_then(|value| filetime_to_timestamp(as_u64(Some(value))))
        .or_else(|| {
            current_version
                .and_then(|node| registry_value(node, "InstallDate"))
                .and_then(|value| unix_timestamp_to_string(as_u64(Some(value))))
        })
        .unwrap_or_default();

    let hardware_bios_node = hardware_index
        .get("ROOT\\DESCRIPTION\\System\\BIOS")
        .copied();
    let hardware_cpu_node = hardware_index
        .get("ROOT\\DESCRIPTION\\System\\CentralProcessor\\0")
        .copied();

    let cpu_name = if has_hardware_hive {
        hardware_cpu_node
            .and_then(|node| {
                registry_value(node, "ProcessorNameString")
                    .or_else(|| registry_value(node, "Identifier"))
            })
            .map(|value| as_string(Some(value)))
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let cpu_count = if has_hardware_hive {
        hardware_index
            .get("ROOT\\DESCRIPTION\\System\\CentralProcessor")
            .map(|node| registry_subkeys(node).len() as u64)
            .filter(|count| *count > 0)
            .unwrap_or(0)
    } else {
        0
    };
    let bios_vendor = hardware_bios_node
        .and_then(|node| registry_value(node, "BIOSVendor"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let bios_version = hardware_bios_node
        .and_then(|node| {
            registry_value(node, "BIOSVersion").or_else(|| registry_value(node, "BIOSReleaseDate"))
        })
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let system_manufacturer = hardware_bios_node
        .and_then(|node| registry_value(node, "SystemManufacturer"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let system_model = hardware_bios_node
        .and_then(|node| registry_value(node, "SystemProductName"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let idconfig_profiles_path =
        format!("ROOT\\{current_control_set}\\Control\\IDConfigDB\\Hardware Profiles");
    let mapped_profiles_path = format!("ROOT\\{current_control_set}\\Hardware Profiles");
    let idconfig_profiles_root = system_index.get(&idconfig_profiles_path).copied();
    let mapped_profiles_root = system_index.get(&mapped_profiles_path).copied();
    let mut active_hardware_profile = String::new();
    let mut hardware_profiles = Vec::new();

    if let Some(idconfig_profiles_root) = idconfig_profiles_root {
        let hardware_profiles_unknown = registry_value(idconfig_profiles_root, "Unknown")
            .map(|value| as_u64(Some(value)) == 1)
            .unwrap_or(false);
        let hardware_profiles_undocked = registry_value(idconfig_profiles_root, "Undocked")
            .map(|value| as_u64(Some(value)) == 1)
            .unwrap_or(false);

        for profile in registry_subkeys(idconfig_profiles_root) {
            let profile_id = profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if profile_id.is_empty() {
                continue;
            }

            let friendly_name = registry_value(profile, "FriendlyName")
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("Hardware Profile {profile_id}"));
            let profile_guid = registry_value(profile, "HwProfileGuid")
                .map(|value| as_string(Some(value)))
                .unwrap_or_default();
            let preference_raw = registry_value(profile, "PreferenceOrder")
                .map(|value| as_u64(Some(value)))
                .unwrap_or(u32::MAX as u64);
            let preference_order = if preference_raw == u32::MAX as u64 {
                "Fallback".to_string()
            } else {
                preference_raw.to_string()
            };

            let mapped_profile = mapped_profiles_root.and_then(|root| {
                registry_subkeys(root).into_iter().find(|candidate| {
                    candidate
                        .get("name")
                        .and_then(Value::as_str)
                        .map(|name| name == profile_id)
                        .unwrap_or(false)
                })
            });

            let attach_to_desktop = mapped_profile
                .and_then(|node| {
                    system_index.get(&format!(
                        "{}\\System\\CurrentControlSet\\SERVICES\\TSDDD\\DEVICE0",
                        node.get("path").and_then(Value::as_str).unwrap_or("")
                    ))
                })
                .and_then(|node| registry_value(node, "Attach.ToDesktop"))
                .map(|value| as_u64(Some(value)) == 1)
                .unwrap_or(false);

            let mut status_bits = Vec::new();
            if preference_raw == 0 {
                status_bits.push("Active Preference".to_string());
                if active_hardware_profile.is_empty() {
                    active_hardware_profile = friendly_name.clone();
                }
            }
            if registry_value(profile, "Cloned")
                .map(|value| as_u64(Some(value)) == 1)
                .unwrap_or(false)
            {
                status_bits.push("Cloned".to_string());
            }
            if registry_value(profile, "Pristine")
                .map(|value| as_u64(Some(value)) == 1)
                .unwrap_or(false)
            {
                status_bits.push("Pristine".to_string());
            }
            if registry_value(profile, "Aliasable")
                .map(|value| as_u64(Some(value)) == 1)
                .unwrap_or(false)
            {
                status_bits.push("Aliasable".to_string());
            }
            if hardware_profiles_undocked && friendly_name.to_ascii_lowercase().contains("undocked")
            {
                status_bits.push("Undocked".to_string());
            }
            if hardware_profiles_unknown {
                status_bits.push("Unknown Flag Present".to_string());
            }
            if attach_to_desktop {
                status_bits.push("Attach.ToDesktop".to_string());
            }

            let last_seen = mapped_profile
                .and_then(|node| node.get("last_write_time").and_then(Value::as_str))
                .or_else(|| profile.get("last_write_time").and_then(Value::as_str))
                .map(normalize_display_timestamp)
                .unwrap_or_default();

            hardware_profiles.push(json!({
                "profile_id": profile_id,
                "friendly_name": friendly_name,
                "profile_guid": profile_guid,
                "preference_order": preference_order,
                "status": if status_bits.is_empty() { "Observed".to_string() } else { status_bits.join(" · ") },
                "last_seen": last_seen,
                "source": "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles + SYSTEM\\CurrentControlSet\\Hardware Profiles",
            }));
        }
    }

    hardware_profiles.sort_by(|left, right| {
        let left_preference = left
            .get("preference_order")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(u64::MAX);
        let right_preference = right
            .get("preference_order")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(u64::MAX);

        left_preference.cmp(&right_preference).then_with(|| {
            parse_event_timestamp(right.get("last_seen").and_then(Value::as_str).unwrap_or("")).cmp(
                &parse_event_timestamp(left.get("last_seen").and_then(Value::as_str).unwrap_or("")),
            )
        })
    });

    let mut parsed_candidates = Vec::new();
    for hive in [&system_hive, &software_hive] {
        if let Some(parsed_at) = hive.get("parsed_at").and_then(Value::as_str) {
            parsed_candidates.push(parsed_at.to_string());
        }
    }
    if let Some(hive) = hardware_hive.as_ref() {
        if let Some(parsed_at) = hive.get("parsed_at").and_then(Value::as_str) {
            parsed_candidates.push(parsed_at.to_string());
        }
    }
    if let Some(hive) = sam_hive.as_ref() {
        if let Some(parsed_at) = hive.get("parsed_at").and_then(Value::as_str) {
            parsed_candidates.push(parsed_at.to_string());
        }
    }
    let evidence_parsed_at = parsed_candidates
        .into_iter()
        .max_by(|left, right| parse_event_timestamp(left).cmp(&parse_event_timestamp(right)))
        .map(|value| normalize_display_timestamp(&value))
        .unwrap_or_default();

    let mut last_shutdown = system_index
        .get(&format!("ROOT\\{current_control_set}\\Control\\Windows"))
        .and_then(|node| extract_filetime_from_value(registry_value(node, "ShutdownTime")))
        .unwrap_or_default();
    let mut last_boot = String::new();
    let mut event_log_host = String::new();
    let mut user_logon_metrics: HashMap<String, (String, u64, u64)> = HashMap::new();

    if let Some(event_log_path) = resolve_configured_path(
        roots,
        &config.host_event_logs_csv,
        &["Transfer/Parsed/EventLogs"],
    )
    .and_then(|path| pick_latest_matching_file(&path, "EvtxECmd_Output"))
    {
        sources.push(event_log_path.to_string_lossy().to_string());
        if let Ok(file) = fs::File::open(&event_log_path) {
            let mut header_map = HashMap::new();
            let mut latest_boot: Option<(DateTime<Utc>, String)> = None;
            let mut latest_shutdown: Option<(DateTime<Utc>, String)> = None;
            let mut matching_host_only = hostname.is_empty();

            for (line_idx, line) in BufReader::new(file)
                .lines()
                .map_while(Result::ok)
                .enumerate()
            {
                if line_idx == 0 {
                    for (idx, name) in parse_csv_line(&line).into_iter().enumerate() {
                        header_map.insert(name, idx);
                    }
                    continue;
                }

                let cols = parse_csv_line(&line);
                let value_at = |name: &str| -> &str {
                    header_map
                        .get(name)
                        .and_then(|idx| cols.get(*idx))
                        .map(String::as_str)
                        .unwrap_or("")
                };

                let event_id = value_at("EventId");
                let timestamp = value_at("TimeCreated");
                let computer = value_at("Computer");

                if event_log_host.is_empty() && !computer.trim().is_empty() {
                    event_log_host = computer.trim().to_string();
                    matching_host_only =
                        hostname.is_empty() || hostname.eq_ignore_ascii_case(event_log_host.trim());
                }

                if !matching_host_only {
                    continue;
                }

                let Some(parsed) = parse_event_timestamp(timestamp) else {
                    continue;
                };

                if matches!(event_id, "12" | "6005" | "4608") {
                    let rendered = format_utc_timestamp(parsed);
                    if latest_boot
                        .as_ref()
                        .map(|(ts, _)| parsed > *ts)
                        .unwrap_or(true)
                    {
                        latest_boot = Some((parsed, rendered));
                    }
                }

                if matches!(event_id, "13" | "1074" | "6006" | "6008") {
                    let rendered = format_utc_timestamp(parsed);
                    if latest_shutdown
                        .as_ref()
                        .map(|(ts, _)| parsed > *ts)
                        .unwrap_or(true)
                    {
                        latest_shutdown = Some((parsed, rendered));
                    }
                }

                if matches!(event_id, "4624" | "4625" | "4634" | "4647") {
                    let mut event_row = HashMap::new();
                    for (name, index) in &header_map {
                        if let Some(value) = cols.get(*index) {
                            event_row.insert(name.clone(), value.clone());
                        }
                    }

                    let account = parse_event_target_account(&event_row);
                    if account.is_empty() || account.ends_with('$') {
                        continue;
                    }

                    let entry = user_logon_metrics
                        .entry(account)
                        .or_insert_with(|| (String::new(), 0, 0));
                    if event_id == "4624" {
                        entry.1 = entry.1.saturating_add(1);
                        let rendered = format_utc_timestamp(parsed);
                        if entry.0.is_empty()
                            || parse_event_timestamp(&rendered) > parse_event_timestamp(&entry.0)
                        {
                            entry.0 = rendered;
                        }
                    }
                    if event_id == "4625" {
                        entry.2 = entry.2.saturating_add(1);
                    }
                }
            }

            if let Some((_, rendered)) = latest_boot {
                last_boot = rendered;
            }
            if let Some((_, rendered)) = latest_shutdown {
                last_shutdown = rendered;
            }
            if !matching_host_only {
                user_logon_metrics.clear();
                event_log_host.clear();
            }
        }
    }

    let firewall_domain = system_index
        .get(&firewall_domain_path)
        .and_then(|node| registry_value(node, "EnableFirewall"))
        .map(|value| firewall_status(as_u64(Some(value))))
        .unwrap_or_else(|| "Unknown".to_string());
    let firewall_public = system_index
        .get(&firewall_public_path)
        .and_then(|node| registry_value(node, "EnableFirewall"))
        .map(|value| firewall_status(as_u64(Some(value))))
        .unwrap_or_else(|| "Unknown".to_string());
    let firewall_standard = system_index
        .get(&firewall_standard_path)
        .and_then(|node| registry_value(node, "EnableFirewall"))
        .map(|value| firewall_status(as_u64(Some(value))))
        .unwrap_or_else(|| "Unknown".to_string());

    let policies_system = software_index
        .get("ROOT\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
        .copied();
    let uac_enabled = policies_system
        .and_then(|node| registry_value(node, "EnableLUA"))
        .map(|value| as_u64(Some(value)))
        .unwrap_or(0);
    let uac_prompt = policies_system
        .and_then(|node| registry_value(node, "ConsentPromptBehaviorAdmin"))
        .map(|value| as_u64(Some(value)))
        .unwrap_or(0);
    let terminal_server = system_index.get(&terminal_server_path).copied();
    let rdp_tcp = system_index.get(&rdp_tcp_path).copied();
    let remote_desktop_status = terminal_server
        .and_then(|node| registry_value(node, "fDenyTSConnections"))
        .map(|value| remote_desktop_status(as_u64(Some(value))))
        .unwrap_or_else(|| "Unknown".to_string());
    let remote_desktop_port = rdp_tcp
        .and_then(|node| registry_value(node, "PortNumber"))
        .map(|value| as_u64(Some(value)).to_string())
        .unwrap_or_default();
    let remote_desktop_nla = rdp_tcp
        .and_then(|node| registry_value(node, "UserAuthentication"))
        .map(|value| {
            if as_u64(Some(value)) == 1 {
                "Required".to_string()
            } else {
                "Disabled".to_string()
            }
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let defender_root = software_index
        .get("ROOT\\Microsoft\\Windows Defender")
        .copied();
    let defender_features = software_index
        .get("ROOT\\Microsoft\\Windows Defender\\Features")
        .copied();
    let defender_status = match (
        defender_root
            .and_then(|node| registry_value(node, "IsServiceRunning"))
            .map(|value| as_u64(Some(value)))
            .unwrap_or(0),
        defender_root
            .and_then(|node| registry_value(node, "DisableAntiVirus"))
            .map(|value| as_u64(Some(value)))
            .unwrap_or(0),
    ) {
        (1, 0) => "Active".to_string(),
        (0, _) => "Stopped".to_string(),
        (_, 1) => "Disabled".to_string(),
        _ => "Unknown".to_string(),
    };
    let defender_tamper_protection = defender_features
        .and_then(|node| registry_value(node, "TamperProtection"))
        .map(|value| {
            if as_u64(Some(value)) == 1 {
                "Enabled".to_string()
            } else {
                "Off".to_string()
            }
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let mut network_profiles = Vec::new();
    if let Some(profiles_root) =
        software_index.get("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
    {
        let signatures_root = software_index
            .get("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged")
            .copied();
        let mut signature_map: HashMap<String, (String, String)> = HashMap::new();
        if let Some(signatures_root) = signatures_root {
            for signature in registry_subkeys(signatures_root) {
                let profile_guid = registry_value(signature, "ProfileGuid")
                    .map(|value| as_string(Some(value)))
                    .unwrap_or_default();
                if profile_guid.is_empty() {
                    continue;
                }
                signature_map.insert(
                    profile_guid.to_ascii_uppercase(),
                    (
                        registry_value(signature, "DnsSuffix")
                            .map(|value| as_string(Some(value)))
                            .unwrap_or_default(),
                        format_mac_address(registry_value(signature, "DefaultGatewayMac")),
                    ),
                );
            }
        }

        for profile in registry_subkeys(profiles_root) {
            let guid = profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_uppercase();
            let (dns_suffix, gateway_mac) = signature_map
                .get(&guid)
                .cloned()
                .unwrap_or_else(|| (String::new(), String::new()));

            network_profiles.push(json!({
                "profile_name": registry_value(profile, "ProfileName").map(|value| as_string(Some(value))).unwrap_or_else(|| guid.clone()),
                "category": registry_value(profile, "Category").map(|value| network_category_label(as_u64(Some(value)))).unwrap_or_else(|| "Unknown".to_string()),
                "first_connected": parse_registry_systemtime(registry_value(profile, "DateCreated")).unwrap_or_default(),
                "last_connected": parse_registry_systemtime(registry_value(profile, "DateLastConnected")).unwrap_or_default(),
                "dns_suffix": dns_suffix,
                "gateway_mac": gateway_mac,
            }));
        }
    }
    network_profiles.sort_by(|left, right| {
        parse_event_timestamp(
            right
                .get("last_connected")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .cmp(&parse_event_timestamp(
            left.get("last_connected")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ))
    });
    network_profiles.truncate(6);

    let mut installed_software = Vec::new();
    for (root_path, arch_label) in [
        ("ROOT\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "x64"),
        (
            "ROOT\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "x86",
        ),
    ] {
        if let Some(uninstall_root) = software_index.get(root_path) {
            for app in registry_subkeys(uninstall_root) {
                if registry_value(app, "SystemComponent")
                    .map(|value| as_u64(Some(value)) == 1)
                    .unwrap_or(false)
                {
                    continue;
                }

                let name = registry_value(app, "DisplayName")
                    .map(|value| as_string(Some(value)))
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }

                let install_date = registry_value(app, "InstallDate")
                    .map(|value| normalize_install_date(&as_string(Some(value))))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| {
                        normalize_display_timestamp(
                            app.get("last_write_time")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                        )
                    });

                installed_software.push(json!({
                    "name": name,
                    "version": registry_value(app, "DisplayVersion").map(|value| as_string(Some(value))).unwrap_or_default(),
                    "publisher": registry_value(app, "Publisher").map(|value| as_string(Some(value))).unwrap_or_default(),
                    "install_date": install_date,
                    "architecture": arch_label,
                }));
            }
        }
    }
    let installed_software_count = installed_software.len() as u64;
    let third_party_encryption = {
        let mut seen = HashSet::new();
        let mut hits = installed_software
            .iter()
            .filter_map(|app| app.get("name").and_then(Value::as_str))
            .filter_map(|name| {
                let lower = name.to_ascii_lowercase();
                (lower.contains("veracrypt")
                    || lower.contains("diskcryptor")
                    || lower.contains("truecrypt")
                    || lower.contains("safeguard")
                    || lower.contains("symantec endpoint encryption")
                    || lower.contains("mcafee endpoint encryption"))
                .then_some(name.trim().to_string())
            })
            .filter(|name| seen.insert(name.to_ascii_lowercase()))
            .collect::<Vec<_>>();
        hits.sort();
        hits.truncate(6);
        hits
    };
    installed_software.sort_by(|left, right| {
        parse_event_timestamp(
            right
                .get("install_date")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .cmp(&parse_event_timestamp(
            left.get("install_date")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ))
        .then_with(|| {
            left.get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .cmp(right.get("name").and_then(Value::as_str).unwrap_or(""))
        })
    });
    installed_software.truncate(8);

    let mut boot_drive_letter = String::new();
    let mut boot_volume_serial = String::new();
    let mut boot_partition_layout = String::new();
    let mut boot_source = String::new();
    let resolved_boot_csv = boot_csv_path.as_ref().and_then(|path| {
        if path.is_dir() {
            pick_latest_matching_file(path, "Boot_Output")
        } else {
            path.exists().then_some(path.clone())
        }
    });
    if let Some(path) = resolved_boot_csv.as_ref() {
        if let Ok(file) = fs::File::open(path) {
            let mut lines = BufReader::new(file).lines().map_while(Result::ok);
            if let (Some(header), Some(first_row)) = (lines.next(), lines.next()) {
                let header_cols = parse_csv_line(&header);
                let row_cols = parse_csv_line(&first_row);
                let mut cols = HashMap::new();
                for (idx, name) in header_cols.iter().enumerate() {
                    cols.insert(name.clone(), row_cols.get(idx).cloned().unwrap_or_default());
                }

                boot_volume_serial = cols
                    .get("VolumeSerialNumber")
                    .cloned()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| {
                        cols.get("VolumeSerialNumberRaw")
                            .cloned()
                            .unwrap_or_default()
                    });

                let bytes_per_sector = cols.get("BytesPerSector").cloned().unwrap_or_default();
                let cluster_size = cols.get("ClusterSize").cloned().unwrap_or_default();
                let total_sectors = cols.get("TotalSectors").cloned().unwrap_or_default();
                let serial_fragment = if boot_volume_serial.is_empty() {
                    String::new()
                } else {
                    format!("serial {boot_volume_serial}")
                };
                boot_partition_layout = [
                    (!bytes_per_sector.is_empty())
                        .then_some(format!("{bytes_per_sector} B/sector")),
                    (!cluster_size.is_empty()).then_some(format!("{cluster_size} B cluster")),
                    (!total_sectors.is_empty()).then_some(format!("{total_sectors} sectors")),
                    (!serial_fragment.is_empty()).then_some(serial_fragment),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ");

                boot_source = cols.get("SourceFile").cloned().unwrap_or_default();
                if let Some(captures) = Regex::new(r"\\([A-Z])\\\$Boot")
                    .ok()
                    .and_then(|re| re.captures(&boot_source))
                {
                    boot_drive_letter =
                        format!("{}:", captures.get(1).map(|m| m.as_str()).unwrap_or(""));
                }
            }
        }
    }

    let bitlocker_status = system_index
        .get(&format!("ROOT\\{current_control_set}\\Control\\FVE"))
        .map(|node| {
            if registry_values(node).is_empty() {
                "Configured".to_string()
            } else if registry_values(node).iter().any(|entry| {
                let entry_name = value_name(entry).to_ascii_lowercase();
                entry_name.contains("enable")
                    || entry_name.contains("protect")
                    || entry_name.contains("encrypt")
            }) {
                "Configured".to_string()
            } else {
                "Present".to_string()
            }
        })
        .unwrap_or_else(|| "Not Detected".to_string());

    let volume_shadow_copies_present = resolve_case_artifact_dir(roots)
        .map(|case_dir| {
            case_dir.join("System Volume Information").exists()
                || WalkDir::new(case_dir)
                    .max_depth(3)
                    .into_iter()
                    .filter_map(|entry| entry.ok())
                    .any(|entry| entry.file_name().to_string_lossy() == "System Volume Information")
        })
        .unwrap_or(false);

    let mut volume_guid_by_signature: HashMap<String, String> = HashMap::new();
    let mut drive_entries: Vec<(String, String, String)> = Vec::new();
    if let Some(mounted_devices) =
        system_index.get(&format!("ROOT\\{current_control_set}\\MountedDevices"))
    {
        for entry in registry_values(mounted_devices) {
            let name = value_name(entry);
            let Some(data) = value_data(entry) else {
                continue;
            };
            let bytes = parse_registry_hex_bytes(Some(data)).unwrap_or_default();
            let signature = bytes_hex(&bytes);
            let decoded = parse_utf16le_string(&bytes);

            if name.starts_with("\\??\\Volume{") {
                volume_guid_by_signature
                    .insert(signature, name.trim_start_matches("\\??\\").to_string());
            } else if let Some(drive) = name.strip_prefix("\\DosDevices\\") {
                drive_entries.push((drive.to_string(), signature, decoded));
            }
        }
    }

    let mut storage_volumes = Vec::new();
    for (drive_letter, signature, decoded_mount) in drive_entries {
        let volume_guid = volume_guid_by_signature
            .get(&signature)
            .cloned()
            .unwrap_or_default();
        let mut partition_layout = String::new();
        let mut serial_number = String::new();
        let mut volume_label = String::new();
        if !boot_drive_letter.is_empty() && drive_letter.eq_ignore_ascii_case(&boot_drive_letter) {
            partition_layout = boot_partition_layout.clone();
            serial_number = boot_volume_serial.clone();
            volume_label = "System Volume".to_string();
        }
        if volume_label.is_empty() && !decoded_mount.is_empty() {
            volume_label = decoded_mount;
        }

        storage_volumes.push(json!({
            "drive_letter": drive_letter,
            "volume_guid": volume_guid,
            "volume_label": volume_label,
            "serial_number": serial_number,
            "partition_layout": partition_layout,
            "bitlocker_status": bitlocker_status,
            "shadow_copies": if volume_shadow_copies_present { "Present" } else { "Not Observed" },
            "source": "SYSTEM\\MountedDevices + MFTECmd $Boot",
        }));
    }
    if storage_volumes.is_empty() && !boot_volume_serial.is_empty() {
        storage_volumes.push(json!({
            "drive_letter": if boot_drive_letter.is_empty() { "Unknown".to_string() } else { boot_drive_letter.clone() },
            "volume_guid": "",
            "volume_label": "NTFS Volume",
            "serial_number": boot_volume_serial,
            "partition_layout": boot_partition_layout,
            "bitlocker_status": bitlocker_status,
            "shadow_copies": if volume_shadow_copies_present { "Present" } else { "Not Observed" },
            "source": if boot_source.is_empty() { "MFTECmd $Boot".to_string() } else { boot_source },
        }));
    }

    let mut usb_storage_devices = Vec::new();
    let mut usb_core_seen = HashSet::new();
    let mut push_usb_core = |name: String,
                             identifier: String,
                             category: &str,
                             first_seen: String,
                             last_seen: String,
                             source: &str| {
        let name = name.trim().to_string();
        let identifier = identifier.trim().to_string();
        if name.is_empty() && identifier.is_empty() {
            return;
        }

        let key = format!(
            "{}|{}|{}|{}",
            category,
            name.to_ascii_lowercase(),
            identifier.to_ascii_lowercase(),
            source
        );
        if usb_core_seen.insert(key) {
            usb_storage_devices.push(json!({
                "name": if name.is_empty() { category.to_string() } else { name },
                "identifier": identifier,
                "category": category,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "source": source,
            }));
        }
    };

    if let Some(usbstor_root) =
        system_index.get(&format!("ROOT\\{current_control_set}\\Enum\\USBSTOR"))
    {
        for family in registry_subkeys(usbstor_root) {
            let family_name = family
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            for device in registry_subkeys(family) {
                let device_name = registry_value(device, "FriendlyName")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        registry_value(device, "DeviceDesc")
                            .map(|value| as_string(Some(value)))
                            .filter(|value| !value.is_empty())
                    })
                    .unwrap_or_else(|| family_name.clone());
                push_usb_core(
                    device_name,
                    device
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    "USB Storage",
                    normalize_display_timestamp(
                        family
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    normalize_display_timestamp(
                        device
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    "SYSTEM\\Enum\\USBSTOR",
                );
            }
        }
    }

    if let Some(storage_root) =
        system_index.get(&format!("ROOT\\{current_control_set}\\Enum\\STORAGE"))
    {
        for storage_class in registry_subkeys(storage_root) {
            let class_name = storage_class
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Storage")
                .to_string();
            for device in registry_subkeys(storage_class) {
                let device_name = registry_value(device, "FriendlyName")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        registry_value(device, "DeviceDesc")
                            .map(|value| as_string(Some(value)))
                            .filter(|value| !value.is_empty())
                    })
                    .unwrap_or_else(|| class_name.clone());
                push_usb_core(
                    device_name,
                    device
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    &format!("Storage {}", class_name),
                    normalize_display_timestamp(
                        storage_class
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    normalize_display_timestamp(
                        device
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    "SYSTEM\\Enum\\STORAGE",
                );
            }
        }
    }

    if let Some(usb_root) = system_index.get(&format!("ROOT\\{current_control_set}\\Enum\\USB")) {
        for family in registry_subkeys(usb_root) {
            let category_name = family
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            for device in registry_subkeys(family) {
                let name = registry_value(device, "FriendlyName")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        registry_value(device, "DeviceDesc")
                            .map(|value| as_string(Some(value)))
                            .filter(|value| !value.is_empty())
                    })
                    .unwrap_or_else(|| category_name.clone());
                if is_noise_usb_device(&name) {
                    continue;
                }

                push_usb_core(
                    name,
                    device
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    "USB Device",
                    normalize_display_timestamp(
                        family
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    normalize_display_timestamp(
                        device
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    "SYSTEM\\Enum\\USB",
                );
            }
        }
    }

    for volume in &storage_volumes {
        let drive_letter = volume
            .get("drive_letter")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if drive_letter.is_empty() || drive_letter.eq_ignore_ascii_case("C:") {
            continue;
        }

        let volume_label = volume
            .get("volume_label")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let identifier = non_empty_strings(&[
            volume
                .get("serial_number")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            volume
                .get("volume_guid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ]);

        push_usb_core(
            if volume_label.is_empty() {
                format!("Mounted {}", drive_letter)
            } else {
                format!("{drive_letter} ({volume_label})")
            },
            identifier,
            "Mounted Device",
            String::new(),
            String::new(),
            "SYSTEM\\MountedDevices",
        );
    }

    if let Some(device_classes_root) = system_index.get(&format!(
        "ROOT\\{current_control_set}\\Control\\DeviceClasses"
    )) {
        for class_key in registry_subkeys(device_classes_root) {
            let class_guid = class_key
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            for instance in registry_subkeys(class_key) {
                let instance_name = instance
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let normalized = instance_name.to_ascii_uppercase();
                if !normalized.contains("USB")
                    && !normalized.contains("USBSTOR")
                    && !normalized.contains("STORAGE")
                    && !normalized.contains("WPDBUSENUM")
                {
                    continue;
                }

                push_usb_core(
                    truncate_chars(&instance_name.replace('#', "\\"), 92),
                    class_guid.clone(),
                    "Device Class",
                    String::new(),
                    normalize_display_timestamp(
                        instance
                            .get("last_write_time")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    "SYSTEM\\Control\\DeviceClasses",
                );
            }
        }
    }

    let usb_category_rank = |category: &str| -> u8 {
        match category {
            "Mounted Device" => 0,
            "USB Storage" => 1,
            "USB Device" => 2,
            value if value.starts_with("Storage ") => 3,
            "Device Class" => 4,
            _ => 5,
        }
    };
    usb_storage_devices.sort_by(|left, right| {
        let left_category = left.get("category").and_then(Value::as_str).unwrap_or("");
        let right_category = right.get("category").and_then(Value::as_str).unwrap_or("");

        usb_category_rank(left_category)
            .cmp(&usb_category_rank(right_category))
            .then_with(|| {
                parse_event_timestamp(right.get("last_seen").and_then(Value::as_str).unwrap_or(""))
                    .cmp(&parse_event_timestamp(
                        left.get("last_seen").and_then(Value::as_str).unwrap_or(""),
                    ))
            })
            .then_with(|| {
                left.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("name").and_then(Value::as_str).unwrap_or(""))
            })
    });
    usb_storage_devices.truncate(14);

    let mut usb_user_attribution = Vec::new();
    if let Some(filefolderaccess_root) = filefolderaccess_path.as_ref() {
        let parsed_user_csvs = if filefolderaccess_root.is_dir() {
            fs::read_dir(filefolderaccess_root)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.ok().map(|item| item.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .map(|name| {
                            let lower = name.to_ascii_lowercase();
                            lower.ends_with(".csv")
                                && (lower.contains("usrclass") || lower.contains("ntuser"))
                        })
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>()
        } else {
            vec![filefolderaccess_root.clone()]
        };

        for csv_path in parsed_user_csvs {
            let username = username_from_parsed_artifact(&csv_path);
            let file_name = csv_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let artifact_name = if file_name.contains("usrclass") {
                "Shellbags"
            } else if file_name.contains("ntuser") {
                "NTUSER Parsed"
            } else {
                "User Artifact"
            };

            if let Ok(file) = fs::File::open(&csv_path) {
                let mut header_map = HashMap::new();
                for (line_idx, line) in BufReader::new(file)
                    .lines()
                    .map_while(Result::ok)
                    .enumerate()
                {
                    if line_idx == 0 {
                        for (idx, name) in parse_csv_line(&line).into_iter().enumerate() {
                            header_map.insert(name.trim().to_string(), idx);
                        }
                        continue;
                    }

                    let cols = parse_csv_line(&line);
                    let cell = |name: &str| -> String {
                        header_map
                            .get(name)
                            .and_then(|idx| cols.get(*idx))
                            .map(|value| value.trim().trim_matches('\u{feff}').to_string())
                            .unwrap_or_default()
                    };

                    let absolute_path = cell("AbsolutePath");
                    let value = cell("Value");
                    let observed_item = drive_letter_from_path(&absolute_path)
                        .or_else(|| drive_letter_from_path(&value))
                        .unwrap_or_default();
                    if observed_item.is_empty() {
                        continue;
                    }

                    let detail = non_empty_strings(&[
                        absolute_path.clone(),
                        value.clone(),
                        cell("ShellType"),
                        cell("Miscellaneous"),
                    ]);
                    let first_seen = [
                        cell("FirstInteracted"),
                        cell("CreatedOn"),
                        cell("ModifiedOn"),
                    ]
                    .into_iter()
                    .find(|value| !value.is_empty())
                    .map(|value| normalize_display_timestamp(&value))
                    .unwrap_or_default();
                    let last_seen = [
                        cell("LastInteracted"),
                        cell("LastWriteTime"),
                        cell("AccessedOn"),
                    ]
                    .into_iter()
                    .find(|value| !value.is_empty())
                    .map(|value| normalize_display_timestamp(&value))
                    .unwrap_or_default();

                    usb_user_attribution.push(json!({
                        "username": username,
                        "artifact": artifact_name,
                        "observed_item": observed_item,
                        "detail": detail,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "source": csv_path.to_string_lossy().to_string(),
                    }));
                }
            }
        }
    }
    usb_user_attribution.sort_by(|left, right| {
        parse_event_timestamp(right.get("last_seen").and_then(Value::as_str).unwrap_or("")).cmp(
            &parse_event_timestamp(left.get("last_seen").and_then(Value::as_str).unwrap_or("")),
        )
    });
    usb_user_attribution.dedup_by(|left, right| {
        left.get("username") == right.get("username")
            && left.get("artifact") == right.get("artifact")
            && left.get("observed_item") == right.get("observed_item")
            && left.get("detail") == right.get("detail")
    });
    usb_user_attribution.truncate(10);

    let mut usb_supporting_evidence = Vec::new();
    let mut usb_supporting_seen = HashSet::new();
    let mut push_usb_support = |text: String| {
        let trimmed = text.trim().to_string();
        if trimmed.is_empty() {
            return;
        }
        if usb_supporting_seen.insert(trimmed.to_ascii_lowercase()) {
            usb_supporting_evidence.push(trimmed);
        }
    };

    push_usb_support(format!(
        "SYSTEM\\Select resolved the active hardware context to {current_control_set}."
    ));

    if let Some(services_root) = system_index.get(&format!("ROOT\\{current_control_set}\\Services"))
    {
        let mut usb_services = registry_subkeys(services_root)
            .into_iter()
            .filter_map(|service| service.get("name").and_then(Value::as_str))
            .filter(|name| name.to_ascii_uppercase().starts_with("USB"))
            .map(str::to_string)
            .collect::<Vec<_>>();
        usb_services.sort();
        usb_services.truncate(8);
        if !usb_services.is_empty() {
            push_usb_support(format!(
                "SYSTEM\\Services exposed USB stack services: {}.",
                usb_services.join(", ")
            ));
        }
    }

    if let Some(wpd_devices_root) =
        software_index.get("ROOT\\Microsoft\\Windows Portable Devices\\Devices")
    {
        push_usb_support(format!(
            "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices contained {} device entries.",
            registry_subkeys(wpd_devices_root).len()
        ));
    }

    if let Some(storage_policy_root) =
        software_index.get("ROOT\\Microsoft\\PolicyManager\\default\\Storage")
    {
        let mut storage_policies = registry_subkeys(storage_policy_root)
            .into_iter()
            .filter_map(|policy| policy.get("name").and_then(Value::as_str))
            .filter(|name| {
                let lower = name.to_ascii_lowercase();
                lower.contains("wpddevices")
                    || lower.contains("removablestorage")
                    || lower.contains("denyread")
                    || lower.contains("denywrite")
            })
            .map(str::to_string)
            .collect::<Vec<_>>();
        storage_policies.sort();
        storage_policies.truncate(8);
        if !storage_policies.is_empty() {
            push_usb_support(format!(
                "SOFTWARE policy controls were present for removable storage: {}.",
                storage_policies.join(", ")
            ));
        }
    }

    let mut connected_devices = Vec::new();
    if let Some(printers_root) =
        software_index.get("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers")
    {
        for printer in registry_subkeys(printers_root) {
            connected_devices.push(json!({
                "name": printer.get("name").and_then(Value::as_str).unwrap_or("Printer").to_string(),
                "identifier": registry_value(printer, "Port").map(|value| as_string(Some(value))).unwrap_or_default(),
                "category": "Printer",
                "first_seen": "",
                "last_seen": normalize_display_timestamp(
                    printer.get("last_write_time").and_then(Value::as_str).unwrap_or("")
                ),
                "source": "SOFTWARE\\...\\Print\\Printers",
            }));
        }
    }
    if let Some(bt_root) = system_index.get(&format!(
        "ROOT\\{current_control_set}\\Services\\BTHPORT\\Parameters\\Devices"
    )) {
        for device in registry_subkeys(bt_root) {
            connected_devices.push(json!({
                "name": registry_value(device, "Name")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| device.get("name").and_then(Value::as_str).unwrap_or("Bluetooth").to_string()),
                "identifier": device.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                "category": "Bluetooth",
                "first_seen": "",
                "last_seen": normalize_display_timestamp(
                    device.get("last_write_time").and_then(Value::as_str).unwrap_or("")
                ),
                "source": "SYSTEM\\...\\BTHPORT\\Parameters\\Devices",
            }));
        }
    }
    if let Some(display_root) =
        system_index.get(&format!("ROOT\\{current_control_set}\\Enum\\DISPLAY"))
    {
        for vendor in registry_subkeys(display_root) {
            let vendor_name = vendor
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            for panel in registry_subkeys(vendor) {
                connected_devices.push(json!({
                    "name": registry_value(panel, "FriendlyName")
                        .map(|value| as_string(Some(value)))
                        .filter(|value| !value.is_empty())
                        .or_else(|| registry_value(panel, "DeviceDesc").map(|value| as_string(Some(value))).filter(|value| !value.is_empty()))
                        .unwrap_or_else(|| vendor_name.clone()),
                    "identifier": panel.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                    "category": "Display",
                    "first_seen": normalize_display_timestamp(
                        vendor.get("last_write_time").and_then(Value::as_str).unwrap_or("")
                    ),
                    "last_seen": normalize_display_timestamp(
                        panel.get("last_write_time").and_then(Value::as_str).unwrap_or("")
                    ),
                    "source": "SYSTEM\\Enum\\DISPLAY",
                }));
            }
        }
    }
    connected_devices.sort_by(|left, right| {
        parse_event_timestamp(right.get("last_seen").and_then(Value::as_str).unwrap_or(""))
            .cmp(&parse_event_timestamp(
                left.get("last_seen").and_then(Value::as_str).unwrap_or(""),
            ))
            .then_with(|| {
                left.get("category")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("category").and_then(Value::as_str).unwrap_or(""))
            })
    });
    connected_devices.truncate(12);

    let language_node = system_index
        .get(&format!(
            "ROOT\\{current_control_set}\\Control\\Nls\\Language"
        ))
        .copied();
    let system_locale = language_node
        .and_then(|node| {
            registry_value(node, "Default").or_else(|| registry_value(node, "InstallLanguage"))
        })
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let country_code = software_index
        .get("ROOT\\Microsoft\\Windows\\CurrentVersion\\Telephony")
        .and_then(|node| registry_value(node, "CountryCode"))
        .map(|value| as_string(Some(value)))
        .unwrap_or_default();
    let mut keyboard_layouts = Vec::new();
    if let Some(preload_root) = user_locale_index.get("ROOT\\Keyboard Layout\\Preload") {
        for entry in registry_values(preload_root) {
            let value = as_string(value_data(entry));
            if !value.is_empty() {
                keyboard_layouts.push(value);
            }
        }
    }
    if keyboard_layouts.is_empty() {
        if let Some(kbd_root) = system_index.get(&format!(
            "ROOT\\{current_control_set}\\Control\\Keyboard Layouts"
        )) {
            for layout in registry_subkeys(kbd_root).into_iter().take(4) {
                let label = registry_value(layout, "Layout Text")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| {
                        layout
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string()
                    });
                if !label.is_empty() {
                    keyboard_layouts.push(label);
                }
            }
        }
    }
    keyboard_layouts.sort();
    keyboard_layouts.dedup();
    keyboard_layouts.truncate(6);

    let mut user_locale_hints = Vec::new();
    if let Some(international_root) = user_locale_index.get("ROOT\\Control Panel\\International") {
        let locale_name = registry_value(international_root, "LocaleName")
            .map(|value| as_string(Some(value)))
            .filter(|value| !value.is_empty())
            .or_else(|| {
                registry_value(international_root, "Locale")
                    .map(|value| as_string(Some(value)))
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_default();
        let s_language = registry_value(international_root, "sLanguage")
            .map(|value| as_string(Some(value)))
            .unwrap_or_default();
        if !locale_name.is_empty() || !s_language.is_empty() {
            user_locale_hints.push(
                [
                    (!locale_name.is_empty()).then_some(locale_name),
                    (!s_language.is_empty()).then_some(s_language),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · "),
            );
        }
    }
    let mut input_method_hints = Vec::new();
    if let Some(preload_root) = user_locale_index.get("ROOT\\Keyboard Layout\\Preload") {
        for entry in registry_values(preload_root) {
            let slot = value_name(entry);
            let layout = as_string(value_data(entry));
            if !layout.is_empty() {
                input_method_hints.push(format!("{slot}: {layout}"));
            }
        }
    }

    let mut adapter_map: HashMap<String, String> = HashMap::new();
    if let Some(network_cards) =
        software_index.get("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
    {
        for card in registry_subkeys(network_cards) {
            let guid = registry_value(card, "ServiceName")
                .map(|value| as_string(Some(value)))
                .unwrap_or_default()
                .trim()
                .trim_matches('{')
                .trim_matches('}')
                .to_ascii_lowercase();
            if guid.is_empty() {
                continue;
            }

            let description = registry_value(card, "Description")
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| guid.clone());
            adapter_map.insert(guid, description);
        }
    }

    let interfaces_root =
        format!("ROOT\\{current_control_set}\\Services\\Tcpip\\Parameters\\Interfaces");
    let mut network_interfaces = Vec::new();
    if let Some(interface_root) = system_index.get(&interfaces_root) {
        for interface in registry_subkeys(interface_root) {
            let guid = interface
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_matches('{')
                .trim_matches('}')
                .to_ascii_lowercase();
            if guid.is_empty() {
                continue;
            }

            let ip = registry_value(interface, "DhcpIPAddress")
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    registry_value(interface, "IPAddress")
                        .map(|value| as_string(Some(value)))
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_default();
            let gateway = registry_value(interface, "DhcpDefaultGateway")
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    registry_value(interface, "DefaultGateway")
                        .map(|value| as_string(Some(value)))
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_default();
            let dns = registry_value(interface, "DhcpNameServer")
                .map(|value| as_string(Some(value)))
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    registry_value(interface, "NameServer")
                        .map(|value| as_string(Some(value)))
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_default();
            let adapter = adapter_map.get(&guid).cloned().unwrap_or_else(|| {
                interface
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("Interface")
                    .to_string()
            });
            let dhcp_enabled = registry_value(interface, "EnableDHCP")
                .map(|value| as_u64(Some(value)) == 1)
                .unwrap_or(false);

            if ip.is_empty() && gateway.is_empty() && dns.is_empty() {
                continue;
            }

            network_interfaces.push(json!({
                "adapter": adapter,
                "ip_address": ip,
                "gateway": gateway,
                "dns": dns,
                "status": if !ip.is_empty() { "Connected" } else { "Standby" },
                "dhcp": if dhcp_enabled { "DHCP" } else { "Static/Unknown" },
            }));
        }
    }
    network_interfaces.sort_by(|left, right| {
        right
            .get("status")
            .and_then(Value::as_str)
            .cmp(&left.get("status").and_then(Value::as_str))
            .then_with(|| {
                left.get("adapter")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("adapter").and_then(Value::as_str).unwrap_or(""))
            })
    });
    network_interfaces.truncate(6);

    let admin_rids = extract_builtin_admin_rids(&sam_index);
    let mut sam_user_metrics: HashMap<u32, (Option<String>, Option<String>, u64, u64, u32)> =
        HashMap::new();
    for (path, node) in &sam_index {
        if !path.starts_with("ROOT\\SAM\\Domains\\Account\\Users\\") {
            continue;
        }
        let rid_hex = path.rsplit('\\').next().unwrap_or("");
        let Some(rid) = parse_hex_rid(rid_hex) else {
            continue;
        };
        if rid < 500 {
            continue;
        }

        sam_user_metrics.insert(rid, decode_sam_f_metrics(registry_value(node, "F")));
    }

    let mut user_accounts = Vec::new();
    let mut seen_users = std::collections::HashSet::new();
    if let Some(profile_list) =
        software_index.get("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    {
        for profile in registry_subkeys(profile_list) {
            let sid = profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if sid.is_empty() || !sid.starts_with("S-1-5-21-") {
                continue;
            }

            let profile_path = registry_value(profile, "ProfileImagePath")
                .map(|value| as_string(Some(value)))
                .unwrap_or_default();
            let username = profile_path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if username.is_empty() {
                continue;
            }
            let rid = sid
                .rsplit('-')
                .next()
                .and_then(|value| value.parse::<u32>().ok());

            let flags = registry_value(profile, "Flags")
                .map(|value| as_u64(Some(value)))
                .unwrap_or(0);
            let state = registry_value(profile, "State")
                .map(|value| as_u64(Some(value)))
                .unwrap_or(0);
            let load_time = filetime_parts_to_timestamp(
                registry_value(profile, "LocalProfileLoadTimeLow")
                    .map(|value| as_u64(Some(value)))
                    .unwrap_or(0),
                registry_value(profile, "LocalProfileLoadTimeHigh")
                    .map(|value| as_u64(Some(value)))
                    .unwrap_or(0),
            );
            let unload_time = filetime_parts_to_timestamp(
                registry_value(profile, "LocalProfileUnloadTimeLow")
                    .map(|value| as_u64(Some(value)))
                    .unwrap_or(0),
                registry_value(profile, "LocalProfileUnloadTimeHigh")
                    .map(|value| as_u64(Some(value)))
                    .unwrap_or(0),
            );
            let last_activity = latest_profile_activity(
                load_time,
                unload_time,
                profile
                    .get("last_write_time")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown"),
            );
            let (sam_last_logon, password_last_set, sam_logon_count, bad_password_count, sam_flags) =
                rid.and_then(|rid| sam_user_metrics.get(&rid).cloned())
                    .unwrap_or((None, None, 0, 0, 0));
            let event_metrics = user_logon_metrics.get(&username.to_ascii_lowercase());
            let last_logon = event_metrics
                .map(|metrics| metrics.0.clone())
                .filter(|value| !value.is_empty())
                .or(sam_last_logon.clone())
                .unwrap_or_else(|| last_activity.clone());
            let successful_logons = event_metrics
                .map(|metrics| metrics.1)
                .filter(|count| *count > 0)
                .unwrap_or(sam_logon_count);
            let failed_logons = event_metrics
                .map(|metrics| metrics.2)
                .unwrap_or(bad_password_count);
            let is_admin = rid.map(|rid| admin_rids.contains(&rid)).unwrap_or(false);
            let mut state_label = account_state_label(&sid, flags, state, "Profile");
            let sam_flags_label = sam_account_flags_label(sam_flags);
            if !sam_flags_label.is_empty() && sam_flags != 0 {
                state_label = format!("{state_label} · {sam_flags_label}");
            }
            if is_admin {
                state_label = format!("Administrator · {state_label}");
            }

            seen_users.insert(username.to_ascii_lowercase());
            user_accounts.push(json!({
                "username": username,
                "sid": sid.clone(),
                "last_activity": last_activity,
                "last_logon": last_logon,
                "logon_count": successful_logons,
                "failed_logons": failed_logons,
                "password_last_set": password_last_set.unwrap_or_default(),
                "profile_path": profile_path,
                "state": state_label,
                "is_admin": is_admin,
            }));
        }
    }

    if let Some(user_names_root) = sam_index.get("ROOT\\SAM\\Domains\\Account\\Users\\Names") {
        for account in registry_subkeys(user_names_root) {
            let username = account
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if username.is_empty() || seen_users.contains(&username.to_ascii_lowercase()) {
                continue;
            }

            user_accounts.push(json!({
                "username": username,
                "sid": "",
                "last_activity": normalize_display_timestamp(
                    account
                        .get("last_write_time")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown"),
                ),
                "last_logon": "",
                "logon_count": 0,
                "failed_logons": 0,
                "password_last_set": "",
                "profile_path": "",
                "state": "SAM only".to_string(),
                "is_admin": false,
            }));
        }
    }

    user_accounts.sort_by(|left, right| {
        let left_ts = left
            .get("last_logon")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                left.get("last_activity")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            });
        let right_ts = right
            .get("last_logon")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                right
                    .get("last_activity")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            });
        parse_event_timestamp(right_ts)
            .cmp(&parse_event_timestamp(left_ts))
            .then_with(|| {
                left.get("username")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("username").and_then(Value::as_str).unwrap_or(""))
            })
    });
    user_accounts.truncate(8);

    let mut timeline_anchors = Vec::new();
    if !install_time.is_empty() {
        timeline_anchors.push(json!({
            "label": "System Install",
            "timestamp": install_time,
            "accent": "primary",
        }));
    }
    if !last_boot.is_empty() {
        timeline_anchors.push(json!({
            "label": "Last Boot",
            "timestamp": last_boot,
            "accent": "neutral",
        }));
    }
    if !last_shutdown.is_empty() {
        timeline_anchors.push(json!({
            "label": "Last Shutdown",
            "timestamp": last_shutdown,
            "accent": "neutral",
        }));
    }
    if let Some(account) = user_accounts.first() {
        if let Some(last_activity) = account.get("last_activity").and_then(Value::as_str) {
            if !last_activity.is_empty() {
                timeline_anchors.push(json!({
                    "label": "Latest Profile Activity",
                    "timestamp": last_activity,
                    "accent": "primary",
                }));
            }
        }
    }
    if !evidence_parsed_at.is_empty() {
        timeline_anchors.push(json!({
            "label": "Registry Parsed",
            "timestamp": evidence_parsed_at,
            "accent": "success",
        }));
    }

    json!({
        "source": sources.join(" | "),
        "hostname": if !hostname.is_empty() { hostname } else { event_log_host },
        "machine_guid": machine_guid,
        "registered_owner": registered_owner,
        "registered_organization": registered_organization,
        "product_id": product_id,
        "domain": domain,
        "time_zone": time_zone,
        "current_control_set": current_control_set,
        "os_product_name": os_product_name,
        "os_display_version": os_display_version,
        "os_build": os_build,
        "install_date": install_time.clone(),
        "last_shutdown_time": last_shutdown.clone(),
        "system_root": system_root,
        "os_architecture": os_architecture,
        "installation_type": installation_type,
        "cpu_name": cpu_name,
        "cpu_count": cpu_count,
        "bios_vendor": bios_vendor,
        "bios_version": bios_version,
        "system_manufacturer": system_manufacturer,
        "system_model": system_model,
        "physical_memory_human": "",
        "firewall_domain": firewall_domain,
        "firewall_public": firewall_public,
        "firewall_standard": firewall_standard,
        "uac_status": if uac_enabled == 1 { "Enabled" } else { "Disabled" },
        "uac_level": map_uac_prompt_level(uac_prompt),
        "remote_desktop_status": remote_desktop_status,
        "remote_desktop_port": remote_desktop_port,
        "remote_desktop_nla": remote_desktop_nla,
        "defender_status": defender_status,
        "defender_tamper_protection": defender_tamper_protection,
        "timeline_anchors": timeline_anchors,
        "active_hardware_profile": if active_hardware_profile.is_empty() {
            hardware_profiles
                .first()
                .and_then(|profile| profile.get("friendly_name").and_then(Value::as_str))
                .unwrap_or("")
                .to_string()
        } else {
            active_hardware_profile
        },
        "hardware_profiles": hardware_profiles,
        "network_interfaces": network_interfaces,
        "network_profiles": network_profiles,
        "storage_volumes": storage_volumes,
        "usb_storage_devices": usb_storage_devices,
        "usb_user_attribution": usb_user_attribution,
        "usb_supporting_evidence": usb_supporting_evidence,
        "connected_devices": connected_devices,
        "system_locale": system_locale,
        "keyboard_layouts": keyboard_layouts,
        "country_code": country_code,
        "user_locale_hints": user_locale_hints,
        "input_method_hints": input_method_hints,
        "bitlocker_status": bitlocker_status,
        "volume_shadow_copies_present": volume_shadow_copies_present,
        "third_party_encryption": third_party_encryption,
        "user_accounts": user_accounts,
        "installed_software_count": installed_software_count,
        "installed_software": installed_software,
        "forensic_note": if has_hardware_hive {
            "Identity derived from SOFTWARE, SYSTEM, SAM, the HARDWARE hive, parsed filesystem metadata, and optional per-user parsed artifacts. Hardware profile state is taken from IDConfigDB and CurrentControlSet hardware-profile branches, while USB evidence is separated into core enumeration, user attribution, and supporting policy signals."
        } else {
            "Identity derived from SOFTWARE, SYSTEM, SAM, parsed filesystem metadata, and optional per-user parsed artifacts. The HARDWARE hive was not available in this case, so CPU/BIOS inventory remains blank; hardware-profile state is still taken directly from SYSTEM\\CurrentControlSet\\Control\\IDConfigDB and SYSTEM\\CurrentControlSet\\Hardware Profiles."
        },
    })
}

fn srum_app_label(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "Unknown".to_string();
    }

    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(trimmed)
        .to_string()
}

fn srum_evidence_summary(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .take(2)
            .map(|item| item.chars().take(92).collect::<String>())
            .collect::<Vec<_>>()
            .join(" | "),
        Some(Value::Object(map)) => map
            .iter()
            .take(2)
            .map(|(key, value)| {
                let rendered = value
                    .as_str()
                    .map(|text| text.chars().take(72).collect::<String>())
                    .unwrap_or_else(|| value.to_string().chars().take(72).collect::<String>());
                format!("{}: {}", key, rendered)
            })
            .collect::<Vec<_>>()
            .join(" | "),
        Some(Value::String(text)) => text.chars().take(120).collect::<String>(),
        Some(other) => other.to_string().chars().take(120).collect::<String>(),
        None => String::new(),
    }
}

fn default_srum_quickview(source: String) -> Value {
    json!({
        "source": source,
        "total_usage_human": "0 B",
        "disk_read_human": "0 B",
        "disk_write_human": "0 B",
        "network_human": "0 B",
        "disk_read_percent": 0.0,
        "disk_write_percent": 0.0,
        "network_percent": 0.0,
        "critical_count": 0,
        "high_count": 0,
        "total_findings": 0,
        "monitored_apps": 0,
        "top_consumers": [],
        "critical_alerts": [],
    })
}

fn build_srum_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let Some(path) = resolve_configured_path(
        roots,
        &config.srum_report,
        &["srum_analysis/reports/srum_analysis_report.json"],
    ) else {
        return default_srum_quickview(String::new());
    };

    let Some(json) = read_json(&path) else {
        return default_srum_quickview(path.to_string_lossy().to_string());
    };

    let summary = json.get("summary");
    let critical_count = as_u64(summary.and_then(|v| v.get("critical")));
    let high_count = as_u64(summary.and_then(|v| v.get("high")));
    let total_findings = as_u64(summary.and_then(|v| v.get("total")));

    let mut disk_read_bytes = 0u64;
    let mut disk_write_bytes = 0u64;
    let mut network_bytes = 0u64;
    let mut top_consumers = Vec::new();

    if let Some(app_statistics) = json.get("app_statistics").and_then(Value::as_array) {
        for app in app_statistics {
            let foreground_read = as_u64(app.get("total_foreground_bytes_read"));
            let foreground_write = as_u64(app.get("total_foreground_bytes_written"));
            let background_read = as_u64(app.get("total_background_bytes_read"));
            let background_write = as_u64(app.get("total_background_bytes_written"));
            let bytes_sent = as_u64(app.get("total_bytes_sent"));
            let bytes_received = as_u64(app.get("total_bytes_received"));

            let total_usage_bytes = foreground_read
                .saturating_add(foreground_write)
                .saturating_add(background_read)
                .saturating_add(background_write)
                .saturating_add(bytes_sent)
                .saturating_add(bytes_received);

            disk_read_bytes = disk_read_bytes.saturating_add(foreground_read + background_read);
            disk_write_bytes = disk_write_bytes.saturating_add(foreground_write + background_write);
            network_bytes = network_bytes.saturating_add(bytes_sent + bytes_received);

            let app_path = app
                .get("app_path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            top_consumers.push(json!({
                "app_label": srum_app_label(&app_path),
                "app_path": app_path,
                "user": app.get("user").and_then(Value::as_str).unwrap_or("Unknown"),
                "total_usage_human": format_size(total_usage_bytes),
                "total_usage_bytes": total_usage_bytes,
                "percent_of_total": 0.0,
                "last_seen": app.get("last_seen").and_then(Value::as_str).unwrap_or("Unknown"),
                "record_count": as_u64(app.get("record_count")),
            }));
        }
    }

    let total_usage_bytes = disk_read_bytes
        .saturating_add(disk_write_bytes)
        .saturating_add(network_bytes);
    let total_usage_denominator = total_usage_bytes.max(1) as f64;

    top_consumers.sort_by(|a, b| {
        as_u64(b.get("total_usage_bytes"))
            .cmp(&as_u64(a.get("total_usage_bytes")))
            .then_with(|| {
                a.get("app_label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("app_label").and_then(Value::as_str).unwrap_or(""))
            })
    });
    for consumer in top_consumers.iter_mut().take(5) {
        let percent =
            ((as_u64(consumer.get("total_usage_bytes")) as f64 / total_usage_denominator) * 1000.0)
                .round()
                / 10.0;
        if let Some(object) = consumer.as_object_mut() {
            object.insert("percent_of_total".to_string(), json!(percent));
        }
    }
    top_consumers.truncate(5);

    let mut critical_alerts = Vec::new();
    for source_name in ["findings", "anomalies"] {
        if let Some(items) = json.get(source_name).and_then(Value::as_array) {
            for item in items {
                if !item
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .eq_ignore_ascii_case("critical")
                {
                    continue;
                }

                let app_path = item
                    .get("app_path")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();

                critical_alerts.push(json!({
                    "id": item.get("id").and_then(Value::as_str).unwrap_or(""),
                    "severity": item.get("severity").and_then(Value::as_str).unwrap_or("Critical"),
                    "category": item.get("category").and_then(Value::as_str).unwrap_or("Unknown"),
                    "title": item.get("title").and_then(Value::as_str).unwrap_or("SRUM alert"),
                    "description": item.get("description").and_then(Value::as_str).unwrap_or("").chars().take(180).collect::<String>(),
                    "timestamp": item.get("timestamp").and_then(Value::as_str).unwrap_or("Unknown"),
                    "app_label": srum_app_label(&app_path),
                    "app_path": app_path,
                    "user": item.get("user").and_then(Value::as_str).unwrap_or("Unknown"),
                    "evidence_summary": srum_evidence_summary(item.get("evidence")),
                }));
            }
        }
    }

    critical_alerts.sort_by(|a, b| {
        b.get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(a.get("timestamp").and_then(Value::as_str).unwrap_or(""))
            .then_with(|| {
                a.get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("title").and_then(Value::as_str).unwrap_or(""))
            })
    });
    critical_alerts.truncate(5);

    json!({
        "source": path.to_string_lossy().to_string(),
        "total_usage_human": format_size(total_usage_bytes),
        "disk_read_human": format_size(disk_read_bytes),
        "disk_write_human": format_size(disk_write_bytes),
        "network_human": format_size(network_bytes),
        "disk_read_percent": ((disk_read_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0,
        "disk_write_percent": ((disk_write_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0,
        "network_percent": ((network_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0,
        "critical_count": critical_count,
        "high_count": high_count,
        "total_findings": total_findings,
        "monitored_apps": json.get("app_statistics").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
        "top_consumers": top_consumers,
        "critical_alerts": critical_alerts,
    })
}

fn default_super_timeline(source: String) -> Value {
    json!({
        "source": source,
        "reference_timestamp": "",
        "total_events": 0,
        "events": [],
    })
}

fn build_super_timeline(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let mut source_paths = Vec::new();
    let mut events: Vec<Value> = Vec::new();

    if let Some(path) =
        resolve_configured_path(roots, &config.ntfs_mft, &["ntfs_analyzer/output/mft.json"])
    {
        source_paths.push(path.to_string_lossy().to_string());
        if let Ok(file) = fs::File::open(&path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let record: Value = match serde_json::from_str(line) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

                if record
                    .get("IsDirectory")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || record
                        .get("IsAds")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                {
                    continue;
                }

                let file_name = record
                    .get("FileName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if file_name.is_empty() {
                    continue;
                }

                let parent_path = record
                    .get("ParentPath")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let full_path = if parent_path.is_empty() || parent_path == "." {
                    file_name.to_string()
                } else {
                    format!(
                        "{}\\{}",
                        parent_path.trim_end_matches(['\\', '/']),
                        file_name
                    )
                };

                let mut timestamp_flags: HashMap<String, Vec<char>> = HashMap::new();
                for (field, flag) in [
                    ("LastModified0x10", 'M'),
                    ("LastAccess0x10", 'A'),
                    ("LastRecordChange0x10", 'C'),
                    ("Created0x10", 'B'),
                ] {
                    if let Some(parsed) = record
                        .get(field)
                        .and_then(Value::as_str)
                        .and_then(parse_event_timestamp)
                    {
                        timestamp_flags
                            .entry(parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                            .or_default()
                            .push(flag);
                    }
                }

                for (timestamp, flags) in timestamp_flags {
                    let Some(parsed) = parse_event_timestamp(&timestamp) else {
                        continue;
                    };
                    let size = as_u64(record.get("FileSize"));
                    events.push(json!({
                        "timestamp": timestamp,
                        "epoch_seconds": parsed.timestamp(),
                        "lane": "NTFS",
                        "source": "$MFT",
                        "event_type": "File MACB",
                        "macb": macb_signature(&flags),
                        "entity": full_path,
                        "detail": format!("{} | {} bytes", full_path, size),
                    }));
                }
            }
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.browser_report,
        &["browser_forensics/report.json"],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            let mut browser_events: Vec<Value> = Vec::new();

            if let Some(timeline) = json.get("timeline").and_then(Value::as_array) {
                for item in timeline {
                    let Some(parsed) = item
                        .get("timestamp")
                        .and_then(Value::as_str)
                        .and_then(parse_event_timestamp)
                    else {
                        continue;
                    };

                    let browser = item
                        .get("source_browser")
                        .and_then(Value::as_str)
                        .unwrap_or("Browser");
                    let profile = item
                        .get("profile")
                        .and_then(Value::as_str)
                        .unwrap_or("Default");
                    let title = item
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("Untitled");
                    browser_events.push(json!({
                        "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        "epoch_seconds": parsed.timestamp(),
                        "lane": "Browser",
                        "source": browser,
                        "event_type": item.get("event_type").and_then(Value::as_str).unwrap_or("Timeline Event"),
                        "macb": "",
                        "entity": format!("{} / {}", browser, profile),
                        "detail": truncate_chars(title, 180),
                    }));
                }
            }

            if browser_events.is_empty() {
                if let Some(artifacts) = json.get("artifacts").and_then(Value::as_array) {
                    for artifact in artifacts {
                        let browser = artifact
                            .get("browser")
                            .and_then(Value::as_str)
                            .unwrap_or("Browser");

                        if let Some(history_entries) =
                            artifact.get("history").and_then(Value::as_array)
                        {
                            for entry in history_entries {
                                let Some(parsed) = entry
                                    .get("last_visit_time")
                                    .and_then(Value::as_str)
                                    .and_then(parse_event_timestamp)
                                else {
                                    continue;
                                };

                                let url = entry.get("url").and_then(Value::as_str).unwrap_or("");
                                let title = entry
                                    .get("title")
                                    .and_then(Value::as_str)
                                    .unwrap_or("Untitled");
                                let domain = extract_domain(url);
                                let entity = if domain.is_empty() {
                                    let ip = extract_ipv4_tokens(url)
                                        .into_iter()
                                        .next()
                                        .unwrap_or_default();
                                    if ip.is_empty() { title.to_string() } else { ip }
                                } else {
                                    domain
                                };

                                browser_events.push(json!({
                                    "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                                    "epoch_seconds": parsed.timestamp(),
                                    "lane": "Browser",
                                    "source": browser,
                                    "event_type": "History Visit",
                                    "macb": "",
                                    "entity": entity,
                                    "detail": truncate_chars(url, 180),
                                }));
                            }
                        }
                    }
                }
            }

            sort_and_trim_timeline_events(&mut browser_events, 120);
            events.extend(browser_events);
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.prefetch_report,
        &[
            "prefetch_analyzer/report_improved.json",
            "prefetch_analyzer/report_fp_tuned.json",
        ],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            let mut prefetch_events: Vec<Value> = Vec::new();
            let mut entries = json
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            entries.sort_by(|a, b| {
                let a_ts = a
                    .get("LastRun")
                    .and_then(Value::as_str)
                    .and_then(parse_event_timestamp)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(0);
                let b_ts = b
                    .get("LastRun")
                    .and_then(Value::as_str)
                    .and_then(parse_event_timestamp)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(0);
                b_ts.cmp(&a_ts)
            });

            for entry in entries.into_iter().take(120) {
                let executable = entry
                    .get("ExecutableName")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown.exe");
                let source_file = entry
                    .get("SourceFilename")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let hash = entry.get("Hash").and_then(Value::as_str).unwrap_or("");

                for (field, label) in [
                    ("LastRun", "Last Run"),
                    ("PreviousRun0", "Previous Run"),
                    ("PreviousRun1", "Previous Run"),
                    ("PreviousRun2", "Previous Run"),
                ] {
                    let Some(parsed) = entry
                        .get(field)
                        .and_then(Value::as_str)
                        .and_then(parse_event_timestamp)
                    else {
                        continue;
                    };

                    prefetch_events.push(json!({
                        "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        "epoch_seconds": parsed.timestamp(),
                        "lane": "Prefetch",
                        "source": "Prefetch",
                        "event_type": label,
                        "macb": "EXEC",
                        "entity": executable,
                        "detail": truncate_chars(&format!("{} | {}", hash, source_file), 180),
                    }));
                }
            }

            sort_and_trim_timeline_events(&mut prefetch_events, 120);
            events.extend(prefetch_events);
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.network_events_csv,
        &[
            "network_forensics/output/live_ps_all_v1/forensic_events.csv",
            "network_forensics/output/forensic_events.csv",
        ],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Ok(file) = fs::File::open(&path) {
            let mut header_map = HashMap::new();
            let mut network_events: Vec<Value> = Vec::new();

            for (idx, line_result) in BufReader::new(file).lines().enumerate() {
                let Ok(line) = line_result else {
                    continue;
                };

                if idx == 0 {
                    for (col_idx, name) in parse_csv_line(&line).into_iter().enumerate() {
                        header_map.insert(name, col_idx);
                    }
                    continue;
                }

                let cols = parse_csv_line(&line);
                let field = |name: &str| -> String {
                    header_map
                        .get(name)
                        .and_then(|index| cols.get(*index))
                        .cloned()
                        .unwrap_or_default()
                };

                let Some(parsed) = parse_event_timestamp(&field("timestamp")) else {
                    continue;
                };

                let process_name = field("process_name");
                let remote_addr = field("remote_addr");
                let remote_port = field("remote_port");
                let local_addr = field("local_addr");
                let local_port = field("local_port");
                let direction = field("direction");
                let username = field("username");

                if process_name.is_empty() && remote_addr.is_empty() {
                    continue;
                }

                let detail = format!(
                    "{}:{} -> {}:{}",
                    if local_addr.is_empty() {
                        "n/a"
                    } else {
                        &local_addr
                    },
                    if local_port.is_empty() {
                        "n/a"
                    } else {
                        &local_port
                    },
                    if remote_addr.is_empty() {
                        "n/a"
                    } else {
                        &remote_addr
                    },
                    if remote_port.is_empty() {
                        "n/a"
                    } else {
                        &remote_port
                    }
                );

                network_events.push(json!({
                    "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    "epoch_seconds": parsed.timestamp(),
                    "lane": "Network",
                    "source": if process_name.is_empty() { "Network" } else { &process_name },
                    "event_type": if direction.is_empty() { "Connection" } else { &direction },
                    "macb": "",
                    "entity": if remote_addr.is_empty() {
                        if username.is_empty() { process_name.clone() } else { username.clone() }
                    } else {
                        remote_addr.clone()
                    },
                    "detail": truncate_chars(&detail, 180),
                }));
            }

            sort_and_trim_timeline_events(&mut network_events, 120);
            events.extend(network_events);
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.srum_report,
        &["srum_analysis/reports/srum_analysis_report.json"],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            let mut srum_events: Vec<Value> = Vec::new();

            for source_name in ["findings", "anomalies"] {
                if let Some(items) = json.get(source_name).and_then(Value::as_array) {
                    for item in items {
                        let severity = item.get("severity").and_then(Value::as_str).unwrap_or("");
                        if !severity.eq_ignore_ascii_case("critical")
                            && !severity.eq_ignore_ascii_case("high")
                        {
                            continue;
                        }

                        let Some(parsed) = item
                            .get("timestamp")
                            .and_then(Value::as_str)
                            .and_then(parse_event_timestamp)
                        else {
                            continue;
                        };

                        let app_path = item.get("app_path").and_then(Value::as_str).unwrap_or("");
                        let user = item
                            .get("user")
                            .and_then(Value::as_str)
                            .unwrap_or("Unknown");
                        let app_label = srum_app_label(app_path);
                        let title = item
                            .get("title")
                            .and_then(Value::as_str)
                            .unwrap_or("SRUM alert");
                        let evidence = srum_evidence_summary(item.get("evidence"));

                        srum_events.push(json!({
                            "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            "epoch_seconds": parsed.timestamp(),
                            "lane": "SRUM",
                            "source": app_label,
                            "event_type": if severity.eq_ignore_ascii_case("critical") { "Critical Alert" } else { "High Alert" },
                            "macb": "",
                            "entity": user,
                            "detail": truncate_chars(&format!("{} | {}", title, evidence), 180),
                        }));
                    }
                }
            }

            if let Some(app_statistics) = json.get("app_statistics").and_then(Value::as_array) {
                let mut consumers = app_statistics.to_vec();
                consumers.sort_by(|a, b| {
                    let a_total = as_u64(a.get("total_foreground_bytes_read"))
                        .saturating_add(as_u64(a.get("total_foreground_bytes_written")))
                        .saturating_add(as_u64(a.get("total_background_bytes_read")))
                        .saturating_add(as_u64(a.get("total_background_bytes_written")))
                        .saturating_add(as_u64(a.get("total_bytes_sent")))
                        .saturating_add(as_u64(a.get("total_bytes_received")));
                    let b_total = as_u64(b.get("total_foreground_bytes_read"))
                        .saturating_add(as_u64(b.get("total_foreground_bytes_written")))
                        .saturating_add(as_u64(b.get("total_background_bytes_read")))
                        .saturating_add(as_u64(b.get("total_background_bytes_written")))
                        .saturating_add(as_u64(b.get("total_bytes_sent")))
                        .saturating_add(as_u64(b.get("total_bytes_received")));
                    b_total.cmp(&a_total)
                });

                for app in consumers.into_iter().take(8) {
                    let Some(parsed) = app
                        .get("last_seen")
                        .and_then(Value::as_str)
                        .and_then(parse_event_timestamp)
                    else {
                        continue;
                    };

                    let app_path = app.get("app_path").and_then(Value::as_str).unwrap_or("");
                    let app_label = srum_app_label(app_path);
                    let user = app.get("user").and_then(Value::as_str).unwrap_or("Unknown");
                    let usage_bytes = as_u64(app.get("total_foreground_bytes_read"))
                        .saturating_add(as_u64(app.get("total_foreground_bytes_written")))
                        .saturating_add(as_u64(app.get("total_background_bytes_read")))
                        .saturating_add(as_u64(app.get("total_background_bytes_written")))
                        .saturating_add(as_u64(app.get("total_bytes_sent")))
                        .saturating_add(as_u64(app.get("total_bytes_received")));

                    srum_events.push(json!({
                        "timestamp": parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        "epoch_seconds": parsed.timestamp(),
                        "lane": "SRUM",
                        "source": app_label,
                        "event_type": "Usage Snapshot",
                        "macb": "",
                        "entity": user,
                        "detail": format!("{} | {}", app_path, format_size(usage_bytes)),
                    }));
                }
            }

            sort_and_trim_timeline_events(&mut srum_events, 80);
            events.extend(srum_events);
        }
    }

    sort_and_trim_timeline_events(&mut events, MAX_SUPERTIMELINE_EVENTS);

    if events.is_empty() {
        return default_super_timeline(source_paths.join(" | "));
    }

    let reference_timestamp = events
        .last()
        .and_then(|event| event.get("timestamp").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    json!({
        "source": source_paths.join(" | "),
        "reference_timestamp": reference_timestamp,
        "total_events": events.len() as u64,
        "events": events,
    })
}

fn default_connections_engine(source: String) -> Value {
    json!({
        "source": source,
        "default_focus": "",
        "nodes": [],
        "links": [],
        "focus_entities": [],
    })
}

fn build_connections_engine(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let mut source_paths = Vec::new();
    let mut nodes: HashMap<String, Value> = HashMap::new();
    let mut links: HashMap<(String, String, String), u64> = HashMap::new();

    if let Some(path) = resolve_configured_path(
        roots,
        &config.browser_report,
        &["browser_forensics/report.json"],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            if let Some(artifacts) = json.get("artifacts").and_then(Value::as_array) {
                for artifact in artifacts {
                    let browser = artifact
                        .get("browser")
                        .and_then(Value::as_str)
                        .unwrap_or("Browser");
                    let browser_id = upsert_connection_node(
                        &mut nodes,
                        "browser",
                        browser,
                        browser,
                        "browser",
                        "Browser profile evidence",
                    );

                    if let Some(history_entries) = artifact.get("history").and_then(Value::as_array)
                    {
                        for entry in history_entries {
                            let url = entry.get("url").and_then(Value::as_str).unwrap_or("");
                            let title = entry
                                .get("title")
                                .and_then(Value::as_str)
                                .filter(|value| !value.trim().is_empty())
                                .unwrap_or("Untitled");
                            let domain = extract_domain(url);
                            let ip_fallback = if domain.is_empty() {
                                extract_ipv4_tokens(url)
                                    .into_iter()
                                    .next()
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            let entity_key = if !domain.is_empty() {
                                domain.clone()
                            } else if !ip_fallback.is_empty() {
                                ip_fallback.clone()
                            } else {
                                title.to_string()
                            };
                            let entity_type = if !domain.is_empty() {
                                "domain"
                            } else if !ip_fallback.is_empty() {
                                "ip"
                            } else {
                                "file"
                            };

                            if let Some(entity_id) = upsert_connection_node(
                                &mut nodes,
                                entity_type,
                                &entity_key,
                                &entity_key,
                                entity_type,
                                url,
                            ) {
                                if let Some(browser_id) = &browser_id {
                                    record_connection_link(
                                        &mut links, browser_id, &entity_id, "visited",
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.network_events_csv,
        &[
            "network_forensics/output/live_ps_all_v1/forensic_events.csv",
            "network_forensics/output/forensic_events.csv",
        ],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Ok(file) = fs::File::open(&path) {
            let mut header_map = HashMap::new();

            for (idx, line_result) in BufReader::new(file).lines().enumerate() {
                let Ok(line) = line_result else {
                    continue;
                };

                if idx == 0 {
                    for (col_idx, name) in parse_csv_line(&line).into_iter().enumerate() {
                        header_map.insert(name, col_idx);
                    }
                    continue;
                }

                let cols = parse_csv_line(&line);
                let field = |name: &str| -> String {
                    header_map
                        .get(name)
                        .and_then(|index| cols.get(*index))
                        .cloned()
                        .unwrap_or_default()
                };

                let process_name = field("process_name");
                let username = field("username");
                let remote_addr = field("remote_addr");
                let local_addr = field("local_addr");
                let local_port = field("local_port");
                let remote_port = field("remote_port");

                if process_name.is_empty() && remote_addr.is_empty() {
                    continue;
                }

                let process_label = {
                    let normalized = normalize_process_name(&process_name);
                    if normalized.is_empty() {
                        if process_name.is_empty() {
                            "Unknown Process".to_string()
                        } else {
                            process_name.clone()
                        }
                    } else {
                        normalized
                    }
                };
                let process_id = upsert_connection_node(
                    &mut nodes,
                    "process",
                    &process_label,
                    &process_label,
                    "process",
                    &format!("{}:{}", field("source"), field("direction")),
                );

                if let Some(user_id) = upsert_connection_node(
                    &mut nodes,
                    "user",
                    &username,
                    &username,
                    "user",
                    "Observed network account",
                ) {
                    if let Some(process_id) = &process_id {
                        record_connection_link(
                            &mut links,
                            &user_id,
                            process_id,
                            "observed_process",
                        );
                    }
                }

                if let Some(process_id) = &process_id {
                    if !remote_addr.is_empty() {
                        if let Some(ip_id) = upsert_connection_node(
                            &mut nodes,
                            "ip",
                            &remote_addr,
                            &remote_addr,
                            "ip",
                            &format!(
                                "{}:{} -> {}:{}",
                                local_addr, local_port, remote_addr, remote_port
                            ),
                        ) {
                            record_connection_link(
                                &mut links,
                                process_id,
                                &ip_id,
                                "communicated_with",
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.prefetch_report,
        &[
            "prefetch_analyzer/report_improved.json",
            "prefetch_analyzer/report_fp_tuned.json",
        ],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            let mut entries = json
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            entries.sort_by(|a, b| {
                let a_ts = a
                    .get("LastRun")
                    .and_then(Value::as_str)
                    .and_then(parse_event_timestamp)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(0);
                let b_ts = b
                    .get("LastRun")
                    .and_then(Value::as_str)
                    .and_then(parse_event_timestamp)
                    .map(|dt| dt.timestamp())
                    .unwrap_or(0);
                b_ts.cmp(&a_ts)
            });

            for entry in entries.into_iter().take(120) {
                let executable = entry
                    .get("ExecutableName")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown.exe");
                let source_file = entry
                    .get("SourceFilename")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let hash = entry.get("Hash").and_then(Value::as_str).unwrap_or("");

                if let Some(process_id) = upsert_connection_node(
                    &mut nodes,
                    "process",
                    executable,
                    executable,
                    "process",
                    source_file,
                ) {
                    if let Some(file_id) = upsert_connection_node(
                        &mut nodes,
                        "file",
                        source_file,
                        executable,
                        "file",
                        source_file,
                    ) {
                        record_connection_link(
                            &mut links,
                            &process_id,
                            &file_id,
                            "prefetch_source",
                        );
                    }

                    if !hash.is_empty() {
                        if let Some(hash_id) = upsert_connection_node(
                            &mut nodes,
                            "hash",
                            hash,
                            hash,
                            "hash",
                            source_file,
                        ) {
                            record_connection_link(
                                &mut links,
                                &process_id,
                                &hash_id,
                                "prefetch_hash",
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(path) = resolve_configured_path(
        roots,
        &config.srum_report,
        &["srum_analysis/reports/srum_analysis_report.json"],
    ) {
        source_paths.push(path.to_string_lossy().to_string());
        if let Some(json) = read_json(&path) {
            if let Some(app_statistics) = json.get("app_statistics").and_then(Value::as_array) {
                let mut consumers = app_statistics.to_vec();
                consumers.sort_by(|a, b| {
                    let a_total = as_u64(a.get("total_foreground_bytes_read"))
                        .saturating_add(as_u64(a.get("total_foreground_bytes_written")))
                        .saturating_add(as_u64(a.get("total_background_bytes_read")))
                        .saturating_add(as_u64(a.get("total_background_bytes_written")))
                        .saturating_add(as_u64(a.get("total_bytes_sent")))
                        .saturating_add(as_u64(a.get("total_bytes_received")));
                    let b_total = as_u64(b.get("total_foreground_bytes_read"))
                        .saturating_add(as_u64(b.get("total_foreground_bytes_written")))
                        .saturating_add(as_u64(b.get("total_background_bytes_read")))
                        .saturating_add(as_u64(b.get("total_background_bytes_written")))
                        .saturating_add(as_u64(b.get("total_bytes_sent")))
                        .saturating_add(as_u64(b.get("total_bytes_received")));
                    b_total.cmp(&a_total)
                });

                for app in consumers.into_iter().take(12) {
                    let app_path = app.get("app_path").and_then(Value::as_str).unwrap_or("");
                    let app_label = srum_app_label(app_path);
                    let user = app.get("user").and_then(Value::as_str).unwrap_or("Unknown");

                    if let Some(process_id) = upsert_connection_node(
                        &mut nodes, "process", &app_label, &app_label, "process", app_path,
                    ) {
                        if let Some(user_id) = upsert_connection_node(
                            &mut nodes,
                            "user",
                            user,
                            user,
                            "user",
                            "SRUM consumer",
                        ) {
                            record_connection_link(&mut links, &user_id, &process_id, "utilized");
                        }

                        if !app_path.is_empty() {
                            if let Some(file_id) = upsert_connection_node(
                                &mut nodes, "file", app_path, &app_label, "file", app_path,
                            ) {
                                record_connection_link(
                                    &mut links,
                                    &process_id,
                                    &file_id,
                                    "resolved_path",
                                );
                            }
                        }
                    }
                }
            }

            for source_name in ["findings", "anomalies"] {
                if let Some(items) = json.get(source_name).and_then(Value::as_array) {
                    for item in items {
                        let severity = item.get("severity").and_then(Value::as_str).unwrap_or("");
                        if !severity.eq_ignore_ascii_case("critical") {
                            continue;
                        }

                        let app_path = item.get("app_path").and_then(Value::as_str).unwrap_or("");
                        let app_label = srum_app_label(app_path);
                        let user = item
                            .get("user")
                            .and_then(Value::as_str)
                            .unwrap_or("Unknown");

                        if let Some(process_id) = upsert_connection_node(
                            &mut nodes, "process", &app_label, &app_label, "process", app_path,
                        ) {
                            if let Some(user_id) = upsert_connection_node(
                                &mut nodes,
                                "user",
                                user,
                                user,
                                "user",
                                item.get("title")
                                    .and_then(Value::as_str)
                                    .unwrap_or("SRUM alert"),
                            ) {
                                record_connection_link(
                                    &mut links,
                                    &user_id,
                                    &process_id,
                                    "alerted_app",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    let mut nodes_vec: Vec<Value> = nodes.into_values().collect();
    nodes_vec.sort_by(|a, b| {
        as_u64(b.get("hits"))
            .cmp(&as_u64(a.get("hits")))
            .then_with(|| {
                a.get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("label").and_then(Value::as_str).unwrap_or(""))
            })
    });
    nodes_vec.truncate(MAX_CONNECTION_NODES);

    let allowed_ids: std::collections::HashSet<String> = nodes_vec
        .iter()
        .filter_map(|node| {
            node.get("id")
                .and_then(Value::as_str)
                .map(|value| value.to_string())
        })
        .collect();

    let mut links_vec: Vec<Value> = links
        .into_iter()
        .filter(|((source, target, _), _)| {
            allowed_ids.contains(source) && allowed_ids.contains(target)
        })
        .map(|((source, target, relationship), hits)| {
            json!({
                "source": source,
                "target": target,
                "relationship": relationship,
                "hits": hits,
            })
        })
        .collect();
    links_vec.sort_by(|a, b| {
        as_u64(b.get("hits"))
            .cmp(&as_u64(a.get("hits")))
            .then_with(|| {
                a.get("relationship")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(b.get("relationship").and_then(Value::as_str).unwrap_or(""))
            })
    });
    links_vec.truncate(MAX_CONNECTION_LINKS);

    let mut focus_entities: Vec<Value> = nodes_vec
        .iter()
        .filter(|node| {
            matches!(
                node.get("entity_type")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "user" | "ip" | "hash"
            )
        })
        .map(|node| {
            json!({
                "id": node.get("id").cloned().unwrap_or(Value::Null),
                "label": node.get("label").cloned().unwrap_or(Value::Null),
                "entity_type": node.get("entity_type").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    if focus_entities.is_empty() {
        focus_entities = nodes_vec
            .iter()
            .take(8)
            .map(|node| {
                json!({
                    "id": node.get("id").cloned().unwrap_or(Value::Null),
                    "label": node.get("label").cloned().unwrap_or(Value::Null),
                    "entity_type": node.get("entity_type").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
    }
    focus_entities.truncate(8);

    let default_focus = focus_entities
        .first()
        .and_then(|entity| entity.get("id").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    if nodes_vec.is_empty() && links_vec.is_empty() {
        return default_connections_engine(source_paths.join(" | "));
    }

    json!({
        "source": source_paths.join(" | "),
        "default_focus": default_focus,
        "nodes": nodes_vec,
        "links": links_vec,
        "focus_entities": focus_entities,
    })
}

fn is_non_external_address(address: &str) -> bool {
    let addr = address.trim().trim_start_matches('\u{feff}');
    if addr.is_empty() || addr == "0.0.0.0" || addr == "::" || addr == "*" {
        return true;
    }

    if let Ok(ip) = addr.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_multicast()
            }
        };
    }

    false
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                cells.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    cells.push(current);
    cells
}

fn default_network_quickview(source: String) -> Value {
    json!({
        "source": source,
        "total_connections": 0,
        "established_connections": 0,
        "external_established_connections": 0,
        "listening_ports": 0,
        "active_connections": [],
        "top_remote_hosts": [],
    })
}

fn normalize_extension(extension: &str, file_name: &str) -> String {
    let ext = extension.trim().trim_start_matches('.').to_lowercase();
    if !ext.is_empty() {
        return format!(".{}", ext);
    }

    if let Some((_, inferred_ext)) = file_name.rsplit_once('.') {
        let inferred_ext = inferred_ext.trim().to_lowercase();
        if !inferred_ext.is_empty() && !file_name.ends_with('.') {
            return format!(".{}", inferred_ext);
        }
    }

    "[no-ext]".to_string()
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut idx = 0usize;
    while size >= 1024.0 && idx < UNITS.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", size, UNITS[idx])
    }
}

fn default_ntfs_quickview(source: String) -> Value {
    json!({
        "source": source,
        "total_entries": 0,
        "active_entries": 0,
        "files": 0,
        "directories": 0,
        "ads_entries": 0,
        "total_file_size_human": "0 B",
        "top_extensions": [],
    })
}

fn build_ntfs_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let Some(path) =
        resolve_configured_path(roots, &config.ntfs_mft, &["ntfs_analyzer/output/mft.json"])
    else {
        return default_ntfs_quickview(String::new());
    };

    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(_) => return default_ntfs_quickview(path.to_string_lossy().to_string()),
    };

    let mut total_entries = 0u64;
    let mut active_entries = 0u64;
    let mut files = 0u64;
    let mut directories = 0u64;
    let mut ads_entries = 0u64;
    let mut extension_counts: HashMap<String, u64> = HashMap::new();

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let record: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        total_entries += 1;
        if record
            .get("InUse")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            active_entries += 1;
        }

        let is_directory = record
            .get("IsDirectory")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let is_ads = record
            .get("IsAds")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if is_directory {
            directories += 1;
            continue;
        }

        files += 1;

        if is_ads {
            ads_entries += 1;
        }

        if !is_ads {
            let extension = record
                .get("Extension")
                .and_then(Value::as_str)
                .unwrap_or("");
            let file_name = record.get("FileName").and_then(Value::as_str).unwrap_or("");
            let normalized = normalize_extension(extension, file_name);
            *extension_counts.entry(normalized).or_insert(0) += 1;
        }
    }

    let case_artifact_size_bytes = resolve_case_artifact_dir(roots)
        .map(|dir| collect_directory_size_bytes(&dir))
        .unwrap_or(0);

    json!({
        "source": path.to_string_lossy().to_string(),
        "total_entries": total_entries,
        "active_entries": active_entries,
        "files": files,
        "directories": directories,
        "ads_entries": ads_entries,
        "total_file_size_human": format_size(case_artifact_size_bytes),
        "top_extensions": sort_label_counts(extension_counts, 10),
    })
}

fn build_network_quickview(roots: &[PathBuf]) -> Value {
    let config = load_input_path_config(roots);
    let Some(report_path) = resolve_configured_path(
        roots,
        &config.network_report,
        &[
            "network_forensics/output/live_ps_all_v1/forensic_report.json",
            "network_forensics/output/forensic_report.json",
        ],
    ) else {
        return default_network_quickview(String::new());
    };

    let Some(events_path) = resolve_configured_path(
        roots,
        &config.network_events_csv,
        &[
            "network_forensics/output/live_ps_all_v1/forensic_events.csv",
            "network_forensics/output/forensic_events.csv",
        ],
    ) else {
        return default_network_quickview(report_path.to_string_lossy().to_string());
    };

    let Some(json) = read_json(&report_path) else {
        return default_network_quickview(report_path.to_string_lossy().to_string());
    };
    let summary = json.get("summary").cloned().unwrap_or(Value::Null);

    let file = match fs::File::open(&events_path) {
        Ok(file) => file,
        Err(_) => return default_network_quickview(report_path.to_string_lossy().to_string()),
    };

    let mut header_map = HashMap::new();
    let mut established_connections = 0u64;
    let mut external_established_connections = 0u64;
    let mut remote_counts = HashMap::new();
    let mut listening_ports = HashMap::new();
    let mut active_connections = Vec::new();
    let mut active_seen = std::collections::HashSet::new();

    for (idx, line_result) in BufReader::new(file).lines().enumerate() {
        let Ok(line) = line_result else {
            continue;
        };

        if idx == 0 {
            for (col_idx, name) in parse_csv_line(&line).into_iter().enumerate() {
                header_map.insert(name, col_idx);
            }
            continue;
        }

        let cols = parse_csv_line(&line);
        let field = |name: &str| -> String {
            header_map
                .get(name)
                .and_then(|index| cols.get(*index))
                .cloned()
                .unwrap_or_default()
        };

        let direction = field("direction");
        let local_addr = field("local_addr");
        let local_port = field("local_port");
        let remote_addr = field("remote_addr");
        let remote_port = field("remote_port");
        let process_name = field("process_name");
        let pid = field("pid");

        if !remote_addr.is_empty() {
            established_connections += 1;

            if !is_non_external_address(&remote_addr) {
                external_established_connections += 1;
                *remote_counts.entry(remote_addr.clone()).or_insert(0u64) += 1;
            }

            if !process_name.is_empty() {
                let key = format!(
                    "{}|{}|{}|{}|{}",
                    process_name.to_lowercase(),
                    pid,
                    local_addr,
                    local_port,
                    remote_addr
                );
                if active_seen.insert(key) {
                    let state = if direction.is_empty() {
                        "OBSERVED".to_string()
                    } else {
                        direction.to_uppercase()
                    };
                    let local_endpoint = if !local_addr.is_empty() || !local_port.is_empty() {
                        format!(
                            "{}:{}",
                            if local_addr.is_empty() {
                                "n/a"
                            } else {
                                &local_addr
                            },
                            if local_port.is_empty() {
                                "n/a"
                            } else {
                                &local_port
                            }
                        )
                    } else {
                        "n/a".to_string()
                    };
                    let remote_endpoint = if !remote_port.is_empty() {
                        format!("{}:{}", remote_addr, remote_port)
                    } else {
                        remote_addr.clone()
                    };

                    active_connections.push(json!({
                        "process": process_name,
                        "pid": pid.parse::<u64>().unwrap_or(0),
                        "local_endpoint": local_endpoint,
                        "remote_endpoint": remote_endpoint,
                        "state": state,
                    }));
                }
            }
        } else if direction == "Inbound" && !local_port.is_empty() && !process_name.is_empty() {
            let key = format!("{}|{}|{}", local_port, process_name.to_lowercase(), pid);
            listening_ports.entry(key).or_insert(());
        }
    }

    active_connections.sort_by(|a, b| {
        a.get("process")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(b.get("process").and_then(Value::as_str).unwrap_or(""))
            .then_with(|| {
                a.get("remote_endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(
                        b.get("remote_endpoint")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    )
            })
    });
    active_connections.truncate(8);

    json!({
        "source": report_path.to_string_lossy().to_string(),
        "total_connections": as_u64(summary.get("total_connections")),
        "established_connections": established_connections,
        "external_established_connections": external_established_connections,
        "listening_ports": listening_ports.len() as u64,
        "active_connections": active_connections,
        "top_remote_hosts": sort_label_counts(remote_counts, 6),
    })
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn sanitize_html_cell(value: &str) -> String {
    let tag_re = Regex::new(r"(?s)<[^>]*>").expect("valid html tag regex");
    let no_tags = tag_re.replace_all(value, " ");
    html_unescape(&no_tags)
        .replace('\u{a0}', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn extract_first_table_row(report_html: &str, section_title: &str) -> Option<Vec<String>> {
    let pattern = format!(
        r#"(?s)<div class="command-block">\s*<div class="command-title"><span>{}</span>.*?</div>\s*<div class="table-wrap">(.*?)</div>\s*</div>"#,
        regex::escape(section_title)
    );
    let block_re = Regex::new(&pattern).ok()?;
    let block_html = block_re.captures(report_html)?.get(1)?.as_str();

    if block_html.contains("empty-msg") {
        return None;
    }

    let row_re = Regex::new(r#"(?s)<tbody>\s*<tr>(.*?)</tr>"#).ok()?;
    let row_html = row_re.captures(block_html)?.get(1)?.as_str();

    let cell_re = Regex::new(r#"(?s)<td[^>]*>(.*?)</td>"#).ok()?;
    let mut cells = Vec::new();
    for capture in cell_re.captures_iter(row_html) {
        if let Some(cell) = capture.get(1) {
            cells.push(sanitize_html_cell(cell.as_str()));
        }
    }

    if cells.is_empty() { None } else { Some(cells) }
}

fn parse_count(value: &str) -> u64 {
    value.replace(',', "").trim().parse::<u64>().unwrap_or(0)
}

fn extract_event_id(text: &str) -> String {
    let event_re = Regex::new(r"\b\d{3,5}\b").expect("valid event id regex");
    event_re
        .find(text)
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "N/A".to_string())
}

fn resolve_windows_event_report(roots: &[PathBuf]) -> Option<PathBuf> {
    let input_config = load_input_path_config(roots);
    if let Some(path) = resolve_configured_path(roots, &input_config.windows_event_report_html, &[])
    {
        return Some(path);
    }

    if let Ok(from_env) = env::var(WINDOWS_EVENT_REPORT_HTML_ENV) {
        let direct = PathBuf::from(&from_env);
        if direct.exists() {
            return Some(direct);
        }

        for root in roots {
            let candidate = root.join(&from_env);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    let explicit = env::var("REPORT_PATHS_FILE").ok().map(PathBuf::from);
    let config_path =
        explicit.or_else(|| resolve_existing_path("portal_from_azure/report_paths.toml", roots));

    if let Some(path) = config_path {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(value) = raw.parse::<toml::Value>() {
                if let Some(report_path) = value
                    .get("reports")
                    .and_then(|reports| reports.get("windows-event"))
                    .and_then(|entry| entry.get("path"))
                    .and_then(toml::Value::as_str)
                {
                    let direct = PathBuf::from(report_path);
                    if direct.exists() {
                        return Some(direct);
                    }

                    if let Some(parent) = path.parent() {
                        let joined = parent.join(report_path);
                        if joined.exists() {
                            return Some(joined);
                        }
                    }
                }
            }
        }
    }

    resolve_existing_path(
        "portal_from_azure/tools/win_event_analysis/liberty.html",
        roots,
    )
    .or_else(|| resolve_existing_path("tools/win_event_analysis/liberty.html", roots))
    .or_else(|| {
        resolve_existing_path(
            "portal_from_azure/rust-backend/data/windows_event_report_sample.html",
            roots,
        )
    })
    .or_else(|| resolve_existing_path("rust-backend/data/windows_event_report_sample.html", roots))
    .or_else(|| {
        resolve_existing_path(
            "portal_from_azure/tools/win_event_analysis/forensic_report.html",
            roots,
        )
    })
    .or_else(|| resolve_existing_path("tools/win_event_analysis/forensic_report.html", roots))
}

fn default_windows_event_quickview(source: String) -> Value {
    json!({
        "source": source,
        "title": "Windows Event Log Alert",
        "timestamp": "Unknown",
        "event_id": "N/A",
        "host": "Unknown",
        "summary": "No suspicious Windows Event indicator could be parsed from available reports.",
        "priority": "MONITOR",
        "count": 0,
        "source_label": "windows-event",
        "category": "EVENT_LOG",
    })
}

fn build_windows_event_quickview(roots: &[PathBuf]) -> Value {
    let Some(path) = resolve_windows_event_report(roots) else {
        return default_windows_event_quickview(String::new());
    };

    let Some(raw_html) = read_text(&path) else {
        return default_windows_event_quickview(path.to_string_lossy().to_string());
    };

    if let Some(row) = extract_first_table_row(&raw_html, "Log Cleared") {
        let host = row
            .first()
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());
        let channel = row
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Security".to_string());
        let user = row.get(2).cloned().unwrap_or_else(|| "Unknown".to_string());
        let process = row.get(3).cloned().unwrap_or_else(|| "Unknown".to_string());
        let event_id = row.get(4).cloned().unwrap_or_else(|| "N/A".to_string());

        return json!({
            "source": path.to_string_lossy().to_string(),
            "title": format!("Windows Event Log Cleared on {}", host),
            "timestamp": "Unknown",
            "event_id": event_id,
            "host": host,
            "summary": format!("Channel '{}' was cleared by '{}' via '{}'.", channel, user, process),
            "priority": "HIGH PRIORITY",
            "count": 1,
            "source_label": channel,
            "category": "LOG_TAMPERING",
        });
    }

    if let Some(row) = extract_first_table_row(&raw_html, "Policy Tampering Summary") {
        let count = row.first().map(|v| parse_count(v)).unwrap_or(0);
        let action = row
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Policy Tampering".to_string());
        let target = row.get(2).cloned().unwrap_or_else(|| "Unknown".to_string());
        let changed_by = row.get(3).cloned().unwrap_or_else(|| "Unknown".to_string());
        let host = row.get(4).cloned().unwrap_or_else(|| "Unknown".to_string());
        let timestamp = row
            .get(6)
            .or_else(|| row.get(5))
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        return json!({
            "source": path.to_string_lossy().to_string(),
            "title": format!("Policy Tampering Detected on {}", host),
            "timestamp": timestamp,
            "event_id": "N/A",
            "host": host,
            "summary": format!("{} on '{}' by '{}'. Observed {} time(s).", action, target, changed_by, count),
            "priority": if count >= 3 { "HIGH PRIORITY" } else { "MEDIUM PRIORITY" },
            "count": count,
            "source_label": action,
            "category": "POLICY_TAMPERING",
        });
    }

    if let Some(row) = extract_first_table_row(&raw_html, "Suspicious Encoding Summary") {
        let count = row.first().map(|v| parse_count(v)).unwrap_or(0);
        let technique = row
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Suspicious Encoding".to_string());
        let source = row
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Windows Event".to_string());
        let preview = row.get(3).cloned().unwrap_or_default();
        let host = row.get(5).cloned().unwrap_or_else(|| "Unknown".to_string());
        let timestamp = row
            .get(7)
            .or_else(|| row.get(6))
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        return json!({
            "source": path.to_string_lossy().to_string(),
            "title": format!("Suspicious {} in Windows Event Logs", technique),
            "timestamp": timestamp,
            "event_id": extract_event_id(&source),
            "host": host,
            "summary": format!(
                "{}. Event log evidence indicates '{}' observed {} time(s).",
                preview,
                technique,
                count
            ),
            "priority": if count >= 10 { "HIGH PRIORITY" } else { "MEDIUM PRIORITY" },
            "count": count,
            "source_label": source,
            "category": "SCRIPTING/ENCODING",
        });
    }

    if let Some(row) = extract_first_table_row(&raw_html, "PowerShell Activity") {
        let count = row.first().map(|v| parse_count(v)).unwrap_or(0);
        let event_type = row
            .get(1)
            .cloned()
            .unwrap_or_else(|| "PowerShell Activity".to_string());
        let script_preview = row.get(2).cloned().unwrap_or_default();
        let host = row.get(4).cloned().unwrap_or_else(|| "Unknown".to_string());
        let timestamp = row
            .get(6)
            .or_else(|| row.get(5))
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        return json!({
            "source": path.to_string_lossy().to_string(),
            "title": format!("PowerShell {} in Windows Event Logs", event_type),
            "timestamp": timestamp,
            "event_id": extract_event_id(&script_preview),
            "host": host,
            "summary": format!(
                "{}. Event logs recorded {} occurrence(s) for '{}'.",
                script_preview,
                count,
                event_type
            ),
            "priority": if count >= 20 { "HIGH PRIORITY" } else { "MEDIUM PRIORITY" },
            "count": count,
            "source_label": "PowerShell Activity",
            "category": "POWERSHELL",
        });
    }

    if let Some(row) = extract_first_table_row(&raw_html, "Process Execution Summary") {
        let count = row.first().map(|v| parse_count(v)).unwrap_or(0);
        let process = row.get(1).cloned().unwrap_or_else(|| "Unknown".to_string());
        let command = row.get(2).cloned().unwrap_or_default();
        let parent = row.get(3).cloned().unwrap_or_else(|| "Unknown".to_string());
        let host = row.get(5).cloned().unwrap_or_else(|| "Unknown".to_string());
        let timestamp = row
            .get(7)
            .or_else(|| row.get(6))
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        return json!({
            "source": path.to_string_lossy().to_string(),
            "title": format!("Suspicious Process Execution: {}", process),
            "timestamp": timestamp,
            "event_id": extract_event_id(&command),
            "host": host,
            "summary": format!("Process '{}' launched from parent '{}'. Command: {}", process, parent, command),
            "priority": if count >= 10 { "HIGH PRIORITY" } else { "MEDIUM PRIORITY" },
            "count": count,
            "source_label": parent,
            "category": "PROCESS_EXECUTION",
        });
    }

    default_windows_event_quickview(path.to_string_lossy().to_string())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DashboardSetterCommand {
    Generate,
    Summary,
}

struct DashboardSetterCli {
    command: DashboardSetterCommand,
    root_override: Option<PathBuf>,
    output_override: Option<PathBuf>,
    config_override: Option<PathBuf>,
    print_summary: bool,
    quiet: bool,
}

fn print_usage() {
    println!(
        "Usage:
  dashboard_setter generate [--root PATH] [--output PATH] [--config PATH] [--summary] [--quiet]
  dashboard_setter summary  [--output PATH]

Commands:
  generate    Build portal_from_azure/rust-backend/data/dashboard_quick_view.json
  summary     Read an existing quick-view JSON file and print a source summary

Options:
  --root PATH      Workspace root override used for resolving module outputs
  --output PATH    Quick-view JSON output path
  --config PATH    Override portal_from_azure/json_files_path.json
  --summary        Print a post-generation summary
  --quiet          Suppress the final success line for generate
  -h, --help       Show this help

Environment:
  DASHBOARD_QUICK_VIEW_OUTPUT  Default output path override
  JSON_FILES_PATH_CONFIG       Default input-path config override
  FORENSICS_WORKSPACE_ROOT     Additional workspace root to search"
    );
}

fn parse_args() -> DashboardSetterCli {
    let mut command = DashboardSetterCommand::Generate;
    let mut output_override = None;
    let mut root_override = None;
    let mut config_override = None;
    let mut print_summary = false;
    let mut quiet = false;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "generate" => command = DashboardSetterCommand::Generate,
            "summary" => command = DashboardSetterCommand::Summary,
            "--output" => {
                if let Some(value) = args.next() {
                    output_override = Some(PathBuf::from(value));
                }
            }
            "--root" => {
                if let Some(value) = args.next() {
                    root_override = Some(PathBuf::from(value));
                }
            }
            "--config" => {
                if let Some(value) = args.next() {
                    config_override = Some(PathBuf::from(value));
                }
            }
            "--summary" => print_summary = true,
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            unknown => {
                eprintln!("Unknown argument: {unknown}");
                print_usage();
                std::process::exit(1);
            }
        }
    }

    DashboardSetterCli {
        command,
        root_override,
        output_override,
        config_override,
        print_summary,
        quiet,
    }
}

fn output_path_from_cli(cli: &DashboardSetterCli) -> PathBuf {
    cli.output_override
        .clone()
        .or_else(|| {
            env::var("DASHBOARD_QUICK_VIEW_OUTPUT")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT))
}

fn summary_value<'a>(payload: &'a Value, key: &str) -> &'a Value {
    payload.get(key).unwrap_or(&Value::Null)
}

fn summary_source(payload: &Value, key: &str) -> String {
    summary_value(payload, key)
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("not set")
        .to_string()
}

fn print_payload_summary(payload: &Value) {
    let metadata = payload.get("analysis_metadata").and_then(Value::as_object);
    println!("Dashboard Quick View Summary");
    println!(
        "  Generated At: {}",
        metadata
            .and_then(|map| map.get("generated_at"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "  Output Path: {}",
        metadata
            .and_then(|map| map.get("output_path"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "  Config Path: {}",
        metadata
            .and_then(|map| map.get("config_path"))
            .and_then(Value::as_str)
            .unwrap_or("default resolution")
    );
    println!(
        "  Workspace Roots: {}",
        metadata
            .and_then(|map| map.get("workspace_roots"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("  Sections:");
    for (label, key) in [
        ("Host Information", "host_information_quickview"),
        ("Network", "network_quickview"),
        ("Memory", "memory_quickview"),
        ("Browser", "browser_quickview"),
        ("Execution", "execution_quickview"),
        ("Windows Event", "windows_event_quickview"),
        ("NTFS", "ntfs_quickview"),
        ("SRUM", "srum_quickview"),
        ("Super Timeline", "super_timeline"),
        ("Connections Engine", "connections_engine"),
    ] {
        println!("    - {label}: {}", summary_source(payload, key));
    }
}

fn print_summary_from_path(output_path: &Path) {
    let Some(payload) = read_json(output_path) else {
        eprintln!(
            "Failed to read dashboard quick-view payload from {}",
            output_path.display()
        );
        std::process::exit(1);
    };
    print_payload_summary(&payload);
}

fn main() {
    let cli = parse_args();
    let output_path = output_path_from_cli(&cli);

    if cli.command == DashboardSetterCommand::Summary {
        print_summary_from_path(&output_path);
        return;
    }

    if let Some(config_override) = cli.config_override.as_ref() {
        // Safe here because this happens before any worker threads or library initialization
        // that reads the process environment.
        unsafe {
            env::set_var(JSON_FILES_PATH_CONFIG_ENV, config_override);
        }
    }

    let workspace_roots = workspace_roots(cli.root_override.clone());
    let resolved_config_path = resolve_json_path_config_file(&workspace_roots);

    let network_quickview = build_network_quickview(&workspace_roots);
    let memory_quickview = build_memory_quickview(&workspace_roots);
    let host_information_quickview = build_host_information_quickview(&workspace_roots);
    let ntfs_quickview = build_ntfs_quickview(&workspace_roots);
    let browser_quickview = build_browser_quickview(&workspace_roots);
    let execution_quickview = build_execution_quickview(&workspace_roots);
    let windows_event_quickview = build_windows_event_quickview(&workspace_roots);
    let srum_quickview = build_srum_quickview(&workspace_roots);
    let super_timeline = build_super_timeline(&workspace_roots);
    let connections_engine = build_connections_engine(&workspace_roots);
    let generated_at = Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

    let payload = json!({
        "analysis_metadata": {
            "generated_by": "dashboard_setter",
            "generated_at": generated_at,
            "output_path": output_path.to_string_lossy().to_string(),
            "config_path": resolved_config_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default(),
            "workspace_roots": workspace_roots
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            "modules_processed": ["host-information", "network", "memory", "ntfs", "browser", "execution", "windows-event", "srum", "prefetch", "super_timeline", "connections_engine"],
            "module_sources": {
                "host_information": host_information_quickview.get("source").cloned().unwrap_or(Value::Null),
                "network": network_quickview.get("source").cloned().unwrap_or(Value::Null),
                "memory": memory_quickview.get("source").cloned().unwrap_or(Value::Null),
                "ntfs": ntfs_quickview.get("source").cloned().unwrap_or(Value::Null),
                "browser": browser_quickview.get("source").cloned().unwrap_or(Value::Null),
                "execution": execution_quickview.get("source").cloned().unwrap_or(Value::Null),
                "windows_event": windows_event_quickview.get("source").cloned().unwrap_or(Value::Null),
                "srum": srum_quickview.get("source").cloned().unwrap_or(Value::Null),
                "super_timeline": super_timeline.get("source").cloned().unwrap_or(Value::Null),
                "connections_engine": connections_engine.get("source").cloned().unwrap_or(Value::Null),
            },
        },
        "host_information_quickview": host_information_quickview,
        "network_quickview": network_quickview,
        "memory_quickview": memory_quickview,
        "ntfs_quickview": ntfs_quickview,
        "browser_quickview": browser_quickview,
        "execution_quickview": execution_quickview,
        "windows_event_quickview": windows_event_quickview,
        "srum_quickview": srum_quickview,
        "super_timeline": super_timeline,
        "connections_engine": connections_engine,
    });

    if let Err(err) = write_json(&output_path, &payload) {
        eprintln!(
            "Failed to write dashboard payload to {}: {err}",
            output_path.display()
        );
        std::process::exit(1);
    }

    if !cli.quiet {
        println!("Wrote dashboard payload to {}", output_path.display());
    }

    if cli.print_summary {
        print_payload_summary(&payload);
    }
}
