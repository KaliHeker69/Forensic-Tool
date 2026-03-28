/// Dashboard route – mirrors app/routers/dashboard.py
use axum::{Router, extract::State, response::Html, routing::get};
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::auth::middleware::{AppState, AuthUser};
use crate::config::INACTIVITY_TIMEOUT_MINUTES;
use crate::template_utils;

const FETCHED_FILES_DIR: &str = "/srv/forensics/fetched_files";
const DASHBOARD_QUICK_VIEW_JSON_ENV: &str = "DASHBOARD_QUICK_VIEW_JSON";
const LEGACY_DASHBOARD_QUICKVIEW_JSON_ENV: &str = "DASHBOARD_QUICKVIEW_JSON";
const MAX_ARTIFACT_TYPES: usize = 10;
const MAX_LIST_ITEMS: usize = 8;
const MAX_TOP_VALUES: usize = 6;
const MAX_TIMELINE_NTFS_EVENTS: usize = 180;
const MAX_TIMELINE_BROWSER_EVENTS: usize = 80;
const MAX_TIMELINE_PREFETCH_EVENTS: usize = 80;
const MAX_TIMELINE_EXECUTION_EVENTS: usize = 40;
const MAX_CONNECTION_FOCUS_ITEMS: usize = 8;
const KNOWN_WINDOWS_EXECUTABLES: &[&str] = &[
    "audiodg.exe",
    "cmd.exe",
    "conhost.exe",
    "csrss.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "dwm.exe",
    "explorer.exe",
    "lsass.exe",
    "msiexec.exe",
    "powershell.exe",
    "pwsh.exe",
    "rundll32.exe",
    "searchindexer.exe",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "taskhostw.exe",
    "taskmgr.exe",
    "trustedinstaller.exe",
    "wininit.exe",
    "winlogon.exe",
    "wmiprvse.exe",
    "wuauclt.exe",
];

#[derive(Serialize, Deserialize, Default, Clone)]
struct ArtifactTypeStat {
    extension: String,
    count: u64,
    total_bytes: u64,
    total_size_human: String,
    percent_files: f64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ArtifactSummary {
    total_files: u64,
    total_folders: u64,
    total_size_bytes: u64,
    total_size_human: String,
    avg_file_size_human: String,
    largest_file_name: String,
    largest_file_size_human: String,
    dominant_extension: String,
    dominant_extension_count: u64,
    scanned_at: String,
    top_types: Vec<ArtifactTypeStat>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct LabelCount {
    label: String,
    count: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostTimelineAnchor {
    label: String,
    timestamp: String,
    accent: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostNetworkInterface {
    adapter: String,
    ip_address: String,
    gateway: String,
    dns: String,
    status: String,
    dhcp: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostNetworkProfile {
    profile_name: String,
    category: String,
    first_connected: String,
    last_connected: String,
    dns_suffix: String,
    gateway_mac: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostStorageVolume {
    drive_letter: String,
    volume_guid: String,
    volume_label: String,
    serial_number: String,
    partition_layout: String,
    bitlocker_status: String,
    shadow_copies: String,
    source: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostHardwareProfile {
    profile_id: String,
    friendly_name: String,
    profile_guid: String,
    preference_order: String,
    status: String,
    last_seen: String,
    source: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostConnectedDevice {
    name: String,
    identifier: String,
    category: String,
    first_seen: String,
    last_seen: String,
    source: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostUserAttribution {
    username: String,
    artifact: String,
    observed_item: String,
    detail: String,
    first_seen: String,
    last_seen: String,
    source: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostInstalledSoftware {
    name: String,
    version: String,
    publisher: String,
    install_date: String,
    architecture: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostUserAccount {
    username: String,
    sid: String,
    last_activity: String,
    last_logon: String,
    logon_count: u64,
    failed_logons: u64,
    password_last_set: String,
    profile_path: String,
    state: String,
    is_admin: bool,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct HostInformationQuickView {
    source: String,
    hostname: String,
    machine_guid: String,
    registered_owner: String,
    registered_organization: String,
    product_id: String,
    domain: String,
    time_zone: String,
    current_control_set: String,
    os_product_name: String,
    os_display_version: String,
    os_build: String,
    install_date: String,
    last_shutdown_time: String,
    system_root: String,
    os_architecture: String,
    installation_type: String,
    cpu_name: String,
    cpu_count: u64,
    bios_vendor: String,
    bios_version: String,
    system_manufacturer: String,
    system_model: String,
    physical_memory_human: String,
    firewall_domain: String,
    firewall_public: String,
    firewall_standard: String,
    uac_status: String,
    uac_level: String,
    remote_desktop_status: String,
    remote_desktop_port: String,
    remote_desktop_nla: String,
    defender_status: String,
    defender_tamper_protection: String,
    timeline_anchors: Vec<HostTimelineAnchor>,
    active_hardware_profile: String,
    hardware_profiles: Vec<HostHardwareProfile>,
    network_interfaces: Vec<HostNetworkInterface>,
    network_profiles: Vec<HostNetworkProfile>,
    storage_volumes: Vec<HostStorageVolume>,
    usb_storage_devices: Vec<HostConnectedDevice>,
    usb_user_attribution: Vec<HostUserAttribution>,
    usb_supporting_evidence: Vec<String>,
    connected_devices: Vec<HostConnectedDevice>,
    system_locale: String,
    keyboard_layouts: Vec<String>,
    country_code: String,
    user_locale_hints: Vec<String>,
    input_method_hints: Vec<String>,
    bitlocker_status: String,
    volume_shadow_copies_present: bool,
    third_party_encryption: Vec<String>,
    user_accounts: Vec<HostUserAccount>,
    installed_software_count: u64,
    installed_software: Vec<HostInstalledSoftware>,
    forensic_note: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct NetworkConnectionRow {
    process: String,
    pid: u64,
    local_endpoint: String,
    remote_endpoint: String,
    state: String,
}

#[derive(Serialize, Deserialize, Default)]
struct NetworkQuickView {
    source: String,
    total_connections: u64,
    established_connections: u64,
    external_established_connections: u64,
    listening_ports: u64,
    active_connections: Vec<NetworkConnectionRow>,
    top_remote_hosts: Vec<LabelCount>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct MemorySeveritySegment {
    label: String,
    count: u64,
    percent: f64,
    color: String,
}

#[derive(Serialize, Deserialize, Default)]
struct MemoryQuickView {
    source: String,
    risk_level: String,
    risk_score: u64,
    total_findings: u64,
    unique_pids: u64,
    unique_ips: u64,
    severity_segments: Vec<MemorySeveritySegment>,
    top_categories: Vec<LabelCount>,
}

#[derive(Serialize, Deserialize, Default)]
struct NtfsQuickView {
    source: String,
    total_entries: u64,
    active_entries: u64,
    files: u64,
    directories: u64,
    ads_entries: u64,
    total_file_size_human: String,
    top_extensions: Vec<LabelCount>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct BrowserHistoryItem {
    browser: String,
    title: String,
    url: String,
    domain: String,
    last_visit: String,
}

#[derive(Serialize, Deserialize, Default)]
struct BrowserQuickView {
    source: String,
    total_browsers: u64,
    total_history_entries: u64,
    total_downloads: u64,
    total_cookies: u64,
    total_sessions: u64,
    browsers_found: Vec<String>,
    top_domains: Vec<LabelCount>,
    recent_history: Vec<BrowserHistoryItem>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct SrumTopConsumer {
    app_label: String,
    app_path: String,
    user: String,
    total_usage_human: String,
    total_usage_bytes: u64,
    percent_of_total: f64,
    last_seen: String,
    record_count: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct SrumCriticalAlert {
    id: String,
    severity: String,
    category: String,
    title: String,
    description: String,
    timestamp: String,
    app_label: String,
    app_path: String,
    user: String,
    evidence_summary: String,
}

#[derive(Serialize, Deserialize, Default)]
struct SrumQuickView {
    source: String,
    total_usage_human: String,
    disk_read_human: String,
    disk_write_human: String,
    network_human: String,
    disk_read_percent: f64,
    disk_write_percent: f64,
    network_percent: f64,
    critical_count: u64,
    high_count: u64,
    total_findings: u64,
    monitored_apps: u64,
    top_consumers: Vec<SrumTopConsumer>,
    critical_alerts: Vec<SrumCriticalAlert>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ExecutionEvent {
    timestamp: String,
    process: String,
    command: String,
    pid: String,
    source: String,
}

#[derive(Serialize, Deserialize, Default)]
struct ExecutionQuickView {
    source: String,
    #[serde(default, alias = "powershell_events")]
    command_count: u64,
    #[serde(default, alias = "recent_powershell")]
    recent_commands: Vec<ExecutionEvent>,
}

#[derive(Serialize, Deserialize, Default)]
struct WindowsEventQuickView {
    source: String,
    title: String,
    timestamp: String,
    event_id: String,
    host: String,
    summary: String,
    priority: String,
    count: u64,
    source_label: String,
    category: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ProcessTreeNode {
    id: String,
    label: String,
    process: String,
    pid: String,
    status: String,
    depth: u64,
    first_seen: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ProcessTreeLink {
    source: String,
    target: String,
    relationship: String,
    weight: f64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ProcessTimelineEvent {
    timestamp: String,
    process: String,
    pid: String,
    event_type: String,
    command: String,
    status: String,
}

#[derive(Serialize, Deserialize, Default)]
struct MaliciousProcessQuickView {
    source: String,
    has_malicious: bool,
    suspicious_count: u64,
    suspicious_executables: Vec<String>,
    execution_timeline: Vec<ProcessTimelineEvent>,
    tree_nodes: Vec<ProcessTreeNode>,
    tree_links: Vec<ProcessTreeLink>,
    summary: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct SuperTimelineEvent {
    timestamp: String,
    epoch_seconds: i64,
    lane: String,
    source: String,
    event_type: String,
    macb: String,
    entity: String,
    detail: String,
}

#[derive(Serialize, Deserialize, Default)]
struct SuperTimelineData {
    source: String,
    reference_timestamp: String,
    total_events: u64,
    events: Vec<SuperTimelineEvent>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ConnectionNode {
    id: String,
    label: String,
    entity_type: String,
    group: String,
    detail: String,
    hits: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ConnectionLink {
    source: String,
    target: String,
    relationship: String,
    hits: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ConnectionFocusEntity {
    id: String,
    label: String,
    entity_type: String,
}

#[derive(Serialize, Deserialize, Default)]
struct ConnectionsEngineData {
    source: String,
    default_focus: String,
    nodes: Vec<ConnectionNode>,
    links: Vec<ConnectionLink>,
    focus_entities: Vec<ConnectionFocusEntity>,
}

#[derive(Deserialize, Default)]
struct DashboardQuickviewData {
    #[allow(dead_code)]
    #[serde(default)]
    artifact_summary: ArtifactSummary,
    #[serde(default)]
    host_information_quickview: HostInformationQuickView,
    #[serde(default)]
    network_quickview: NetworkQuickView,
    #[serde(default)]
    memory_quickview: MemoryQuickView,
    #[serde(default)]
    ntfs_quickview: NtfsQuickView,
    #[serde(default)]
    browser_quickview: BrowserQuickView,
    #[serde(default)]
    execution_quickview: ExecutionQuickView,
    #[serde(default)]
    windows_event_quickview: WindowsEventQuickView,
    #[allow(dead_code)]
    #[serde(default)]
    malicious_process_quickview: MaliciousProcessQuickView,
    #[serde(default)]
    srum_quickview: SrumQuickView,
    #[serde(default)]
    super_timeline: SuperTimelineData,
    #[serde(default)]
    connections_engine: ConnectionsEngineData,
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

fn collect_artifact_summary(path: &Path) -> ArtifactSummary {
    if !path.exists() {
        let _ = std::fs::create_dir_all(path);
    }

    let mut total_files = 0u64;
    let mut total_folders = 0u64;
    let mut total_size_bytes = 0u64;
    let mut extension_stats: HashMap<String, (u64, u64)> = HashMap::new();
    let mut largest_file_name = String::from("N/A");
    let mut largest_file_bytes = 0u64;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            if entry.depth() > 0 {
                total_folders += 1;
            }
            continue;
        }

        if !metadata.is_file() {
            continue;
        }

        total_files += 1;
        let size = metadata.len();
        total_size_bytes += size;

        let relative = entry
            .path()
            .strip_prefix(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| entry.path().to_string_lossy().into_owned());

        if size > largest_file_bytes {
            largest_file_bytes = size;
            largest_file_name = relative;
        }

        let ext = entry
            .path()
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_else(|| "[no-ext]".to_string());

        let item = extension_stats.entry(ext).or_insert((0, 0));
        item.0 += 1;
        item.1 += size;
    }

    let mut top_types: Vec<ArtifactTypeStat> = extension_stats
        .into_iter()
        .map(|(extension, (count, bytes))| ArtifactTypeStat {
            extension,
            count,
            total_bytes: bytes,
            total_size_human: format_size(bytes),
            percent_files: if total_files > 0 {
                ((count as f64 / total_files as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            },
        })
        .collect();

    top_types.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
            .then_with(|| a.extension.cmp(&b.extension))
    });
    top_types.truncate(MAX_ARTIFACT_TYPES);

    let (dominant_extension, dominant_extension_count) = top_types
        .first()
        .map(|x| (x.extension.clone(), x.count))
        .unwrap_or_else(|| ("N/A".to_string(), 0));

    ArtifactSummary {
        total_files,
        total_folders,
        total_size_bytes,
        total_size_human: format_size(total_size_bytes),
        avg_file_size_human: if total_files > 0 {
            format_size(total_size_bytes / total_files)
        } else {
            "0 B".to_string()
        },
        largest_file_name,
        largest_file_size_human: format_size(largest_file_bytes),
        dominant_extension,
        dominant_extension_count,
        scanned_at: chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string(),
        top_types,
    }
}

fn workspace_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(from_env) = std::env::var("FORENSICS_WORKSPACE_ROOT") {
        roots.push(PathBuf::from(from_env));
    }

    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd.clone());
        roots.push(cwd.join(".."));
        roots.push(cwd.join("../.."));
        roots.push(cwd.join("../../.."));
    }

    roots.push(PathBuf::from("/Users/kali/Codes/wsl"));

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        let key = root.to_string_lossy().into_owned();
        if seen.insert(key) {
            unique.push(root);
        }
    }
    unique
}

fn resolve_existing_path(relative_path: &str) -> Option<PathBuf> {
    for root in workspace_roots() {
        let candidate = root.join(relative_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn read_text_file(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let bytes = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes.as_slice()
    };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn resolve_dashboard_quickview_json() -> Option<PathBuf> {
    for env_key in [
        DASHBOARD_QUICK_VIEW_JSON_ENV,
        LEGACY_DASHBOARD_QUICKVIEW_JSON_ENV,
    ] {
        if let Ok(from_env) = std::env::var(env_key) {
            let direct = PathBuf::from(&from_env);
            if direct.exists() {
                return Some(direct);
            }

            for root in workspace_roots() {
                let joined = root.join(&from_env);
                if joined.exists() {
                    return Some(joined);
                }
            }
        }
    }

    resolve_existing_path("portal_from_azure/rust-backend/data/dashboard_quick_view.json")
        .or_else(|| {
            resolve_existing_path("portal_from_azure/rust-backend/data/dashboard_quickview.json")
        })
        .or_else(|| resolve_existing_path("rust-backend/data/dashboard_quick_view.json"))
        .or_else(|| resolve_existing_path("rust-backend/data/dashboard_quickview.json"))
        .or_else(|| resolve_existing_path("data/dashboard_quick_view.json"))
        .or_else(|| resolve_existing_path("data/dashboard_quickview.json"))
}

fn load_dashboard_quickview_data() -> Option<DashboardQuickviewData> {
    let path = resolve_dashboard_quickview_json()?;
    let raw = read_text_file(&path)?;
    serde_json::from_str::<DashboardQuickviewData>(&raw).ok()
}

fn load_report_route_links() -> HashMap<String, String> {
    let explicit = std::env::var("REPORT_PATHS_FILE").ok().map(PathBuf::from);
    let config_path = explicit
        .or_else(|| resolve_existing_path("portal_from_azure/report_paths.toml"))
        .or_else(|| resolve_existing_path("report_paths.toml"));

    let Some(path) = config_path else {
        return HashMap::new();
    };

    let Ok(raw) = fs::read_to_string(&path) else {
        return HashMap::new();
    };

    let Ok(value) = raw.parse::<toml::Value>() else {
        return HashMap::new();
    };

    value
        .get("reports")
        .and_then(toml::Value::as_table)
        .map(|reports| {
            reports
                .keys()
                .map(|report_id| (report_id.clone(), format!("/reports/{report_id}")))
                .collect()
        })
        .unwrap_or_default()
}

fn report_url(report_routes: &HashMap<String, String>, report_id: &str, fallback: &str) -> String {
    report_routes
        .get(report_id)
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}

fn parse_event_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        let utc = parsed.with_timezone(&Utc);
        return (2000..=2100).contains(&utc.year()).then_some(utc);
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
            if (2000..=2100).contains(&utc.year()) {
                return Some(utc);
            }
        }
    }

    None
}

fn normalize_event_timestamp(raw: &str) -> Option<String> {
    parse_event_timestamp(raw).map(|value| value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
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

fn push_recent_event(
    events: &mut Vec<SuperTimelineEvent>,
    event: SuperTimelineEvent,
    max_items: usize,
) {
    events.push(event);
    if events.len() > max_items * 3 {
        events.sort_by(|a, b| b.epoch_seconds.cmp(&a.epoch_seconds));
        events.truncate(max_items * 2);
    }
}

fn finalize_recent_events(events: &mut Vec<SuperTimelineEvent>, max_items: usize) {
    events.sort_by(|a, b| a.epoch_seconds.cmp(&b.epoch_seconds));
    if events.len() > max_items {
        let keep_from = events.len().saturating_sub(max_items);
        events.drain(0..keep_from);
    }
}

fn macb_signature(flags: &[char]) -> String {
    let ordered = [('M', 'M'), ('A', 'A'), ('C', 'C'), ('B', 'B')];
    ordered
        .iter()
        .map(|(flag, render)| if flags.contains(flag) { *render } else { '.' })
        .collect()
}

fn resolve_prefetch_report() -> Option<PathBuf> {
    resolve_existing_path("prefetch_analyzer/report_improved.json")
        .or_else(|| resolve_existing_path("prefetch_analyzer/report_fp_tuned.json"))
}

fn connection_node_id(entity_type: &str, raw: &str) -> String {
    format!("{}:{}", entity_type, raw.trim().to_lowercase())
}

fn upsert_connection_node(
    nodes: &mut HashMap<String, ConnectionNode>,
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
    let entry = nodes.entry(id.clone()).or_insert_with(|| ConnectionNode {
        id: id.clone(),
        label: trimmed_label.to_string(),
        entity_type: entity_type.to_string(),
        group: group.to_string(),
        detail: truncate_chars(detail, 160),
        hits: 0,
    });
    entry.hits = entry.hits.saturating_add(1);
    if entry.detail.is_empty() && !detail.trim().is_empty() {
        entry.detail = truncate_chars(detail, 160);
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

fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }

    let leaf = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    leaf.to_lowercase()
}

fn tree_node_id(prefix: &str, raw: &str) -> String {
    let slug = normalize_process_name(raw)
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    format!("{prefix}-{}", slug.trim_matches('-'))
}

fn extract_executable_tokens(text: &str) -> Vec<String> {
    let exe_re = Regex::new(r"(?i)\b[a-z0-9._-]+\.exe\b").expect("valid executable token regex");
    let mut tokens = Vec::new();
    for capture in exe_re.find_iter(text) {
        let normalized = normalize_process_name(capture.as_str());
        if !normalized.is_empty() {
            tokens.push(normalized);
        }
    }
    tokens
}

fn is_legit_windows_executable(process_name: &str) -> bool {
    let normalized = normalize_process_name(process_name);
    KNOWN_WINDOWS_EXECUTABLES
        .iter()
        .any(|known| *known == normalized)
}

fn collect_malicious_process_quickview(
    execution_quickview: &ExecutionQuickView,
    network_quickview: &NetworkQuickView,
    windows_event_quickview: &WindowsEventQuickView,
) -> MaliciousProcessQuickView {
    let mut view = MaliciousProcessQuickView {
        source: if !execution_quickview.source.is_empty() {
            execution_quickview.source.clone()
        } else if !network_quickview.source.is_empty() {
            network_quickview.source.clone()
        } else {
            windows_event_quickview.source.clone()
        },
        summary:
            "No suspicious non-system executable has been detected in current quick-view artifacts."
                .to_string(),
        ..MaliciousProcessQuickView::default()
    };

    let mut observed_executables: HashSet<String> = HashSet::new();

    for event in &execution_quickview.recent_commands {
        let process = normalize_process_name(&event.process);
        if process.ends_with(".exe") {
            observed_executables.insert(process);
        }

        for token in extract_executable_tokens(&event.command) {
            observed_executables.insert(token);
        }
    }

    for conn in &network_quickview.active_connections {
        let process = normalize_process_name(&conn.process);
        if process.ends_with(".exe") {
            observed_executables.insert(process);
        }
    }

    for token in extract_executable_tokens(&windows_event_quickview.title) {
        observed_executables.insert(token);
    }
    for token in extract_executable_tokens(&windows_event_quickview.summary) {
        observed_executables.insert(token);
    }

    let mut suspicious_executables: Vec<String> = observed_executables
        .iter()
        .filter(|name| !is_legit_windows_executable(name))
        .cloned()
        .collect();
    suspicious_executables.sort();
    suspicious_executables.dedup();

    if suspicious_executables.is_empty() {
        return view;
    }

    let suspicious_set: HashSet<String> = suspicious_executables.iter().cloned().collect();
    let mut verified_executables: Vec<String> = observed_executables
        .into_iter()
        .filter(|name| is_legit_windows_executable(name))
        .collect();
    verified_executables.sort();
    verified_executables.truncate(MAX_TOP_VALUES);

    let mut tree_nodes = vec![ProcessTreeNode {
        id: "node-system".to_string(),
        label: "system".to_string(),
        process: "system".to_string(),
        pid: "4".to_string(),
        status: "verified".to_string(),
        depth: 0,
        first_seen: "boot".to_string(),
    }];
    let mut tree_links = Vec::new();

    for process in &verified_executables {
        let node_id = tree_node_id("node-verified", process);
        tree_nodes.push(ProcessTreeNode {
            id: node_id.clone(),
            label: process.clone(),
            process: process.clone(),
            pid: "n/a".to_string(),
            status: "verified".to_string(),
            depth: 1,
            first_seen: "baseline".to_string(),
        });
        tree_links.push(ProcessTreeLink {
            source: "node-system".to_string(),
            target: node_id,
            relationship: "baseline".to_string(),
            weight: 1.0,
        });
    }

    let parent_id = verified_executables
        .first()
        .map(|process| tree_node_id("node-verified", process))
        .unwrap_or_else(|| "node-system".to_string());

    for process in &suspicious_executables {
        let node_id = tree_node_id("node-suspicious", process);
        tree_nodes.push(ProcessTreeNode {
            id: node_id.clone(),
            label: process.clone(),
            process: process.clone(),
            pid: "n/a".to_string(),
            status: "suspicious".to_string(),
            depth: 2,
            first_seen: windows_event_quickview.timestamp.clone(),
        });
        tree_links.push(ProcessTreeLink {
            source: parent_id.clone(),
            target: node_id,
            relationship: "spawned".to_string(),
            weight: 2.0,
        });
    }

    let mut timeline = Vec::new();

    for event in &execution_quickview.recent_commands {
        let process = normalize_process_name(&event.process);
        let mut matched = suspicious_set.contains(&process);
        let mut matched_process = process.clone();

        if !matched {
            for token in extract_executable_tokens(&event.command) {
                if suspicious_set.contains(&token) {
                    matched = true;
                    matched_process = token;
                    break;
                }
            }
        }

        if matched {
            timeline.push(ProcessTimelineEvent {
                timestamp: event.timestamp.clone(),
                process: matched_process,
                pid: event.pid.clone(),
                event_type: "Process Execution".to_string(),
                command: truncate_chars(&event.command, 220),
                status: "suspicious".to_string(),
            });
        }
    }

    for conn in &network_quickview.active_connections {
        let process = normalize_process_name(&conn.process);
        if !suspicious_set.contains(&process) {
            continue;
        }

        timeline.push(ProcessTimelineEvent {
            timestamp: "network-observed".to_string(),
            process,
            pid: if conn.pid > 0 {
                conn.pid.to_string()
            } else {
                "n/a".to_string()
            },
            event_type: "Network Connection".to_string(),
            command: format!("{} -> {}", conn.local_endpoint, conn.remote_endpoint),
            status: "suspicious".to_string(),
        });
    }

    if timeline.is_empty() {
        for process in &suspicious_executables {
            timeline.push(ProcessTimelineEvent {
                timestamp: windows_event_quickview.timestamp.clone(),
                process: process.clone(),
                pid: "n/a".to_string(),
                event_type: "Windows Event".to_string(),
                command: truncate_chars(&windows_event_quickview.summary, 220),
                status: "suspicious".to_string(),
            });
        }
    }

    timeline.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    timeline.truncate(MAX_LIST_ITEMS * 2);

    view.has_malicious = true;
    view.suspicious_count = suspicious_executables.len() as u64;
    view.suspicious_executables = suspicious_executables.clone();
    view.execution_timeline = timeline;
    view.tree_nodes = tree_nodes;
    view.tree_links = tree_links;
    view.summary = format!(
        "{} suspicious executable(s) outside known Windows baseline detected: {}.",
        view.suspicious_count,
        suspicious_executables.join(", ")
    );

    view
}

fn latest_prefixed_dir(base: &Path, prefix: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(base)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with(prefix))
                    .unwrap_or(false)
        })
        .collect();

    dirs.sort_by(|a, b| {
        b.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .cmp(
                a.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            )
    });

    dirs.into_iter().next()
}

fn value_to_u64(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn tcp_state_label(state_code: u64) -> &'static str {
    match state_code {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN-SENT",
        4 => "SYN-RECV",
        5 => "ESTABLISHED",
        6 => "FIN-WAIT-1",
        7 => "FIN-WAIT-2",
        8 => "CLOSE-WAIT",
        9 => "CLOSING",
        10 => "LAST-ACK",
        11 => "TIME-WAIT",
        12 => "DELETE-TCB",
        _ => "UNKNOWN",
    }
}

fn is_non_external_address(address: &str) -> bool {
    let addr = address.trim().trim_start_matches('\u{feff}');
    if addr.is_empty() || addr == "0.0.0.0" || addr == "::" || addr == "*" {
        return true;
    }

    if let Ok(ip) = addr.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.octets()[0] == 0
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        };
    }

    false
}

fn sort_label_counts(map: HashMap<String, u64>, limit: usize) -> Vec<LabelCount> {
    let mut items: Vec<LabelCount> = map
        .into_iter()
        .map(|(label, count)| LabelCount { label, count })
        .collect();

    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    items.truncate(limit);
    items
}

fn collect_network_quickview() -> NetworkQuickView {
    let mut view = NetworkQuickView::default();

    let artefacts_root = match resolve_existing_path("network_forensics/artefacts") {
        Some(path) => path,
        None => return view,
    };

    let capture_dir = latest_prefixed_dir(&artefacts_root, "live_").unwrap_or(artefacts_root);
    view.source = capture_dir.to_string_lossy().into_owned();

    let pid_correlation = capture_dir.join("pid_process_correlation.json");
    let raw = match read_text_file(&pid_correlation) {
        Some(text) => text,
        None => return view,
    };

    let connections: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
    let mut remote_counts: HashMap<String, u64> = HashMap::new();
    let mut dedupe = HashSet::new();

    for item in connections {
        view.total_connections += 1;

        let local_addr = item
            .get("LocalAddress")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0");
        let local_port = value_to_u64(item.get("LocalPort"));
        let remote_addr = item
            .get("RemoteAddress")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0");
        let remote_port = value_to_u64(item.get("RemotePort"));
        let state = tcp_state_label(value_to_u64(item.get("State")));
        let pid = value_to_u64(item.get("PID"));
        let process = item
            .get("ProcessName")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        if state == "LISTEN" {
            view.listening_ports += 1;
        }

        if state == "ESTABLISHED" {
            view.established_connections += 1;

            if !is_non_external_address(remote_addr) {
                view.external_established_connections += 1;
                *remote_counts.entry(remote_addr.to_string()).or_insert(0) += 1;

                let local_endpoint = format!("{}:{}", local_addr, local_port);
                let remote_endpoint = format!("{}:{}", remote_addr, remote_port);
                let key = format!(
                    "{}|{}|{}|{}",
                    process.to_lowercase(),
                    pid,
                    local_endpoint,
                    remote_endpoint
                );

                if dedupe.insert(key) {
                    view.active_connections.push(NetworkConnectionRow {
                        process,
                        pid,
                        local_endpoint,
                        remote_endpoint,
                        state: state.to_string(),
                    });
                }
            }
        }
    }

    view.active_connections.sort_by(|a, b| {
        a.process
            .cmp(&b.process)
            .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
    });
    view.active_connections.truncate(MAX_LIST_ITEMS);

    if view.active_connections.is_empty() {
        let active_txt = capture_dir.join("external_established_connections.txt");
        if let Some(raw_txt) = read_text_file(&active_txt) {
            for line in raw_txt.lines() {
                let trimmed = line.trim().trim_start_matches('\u{feff}');
                if trimmed.is_empty() || !trimmed.contains("->") {
                    continue;
                }

                let Some((left, right)) = trimmed.split_once("->") else {
                    continue;
                };
                let left = left.trim();
                let right = right.trim();

                let (process, pid) = if let Some((name, pid_block)) = left.rsplit_once('[') {
                    (
                        name.trim().to_string(),
                        pid_block
                            .trim_end_matches(']')
                            .trim()
                            .parse::<u64>()
                            .unwrap_or(0),
                    )
                } else {
                    (left.to_string(), 0)
                };

                let key = format!("{}|{}|{}", process.to_lowercase(), pid, right);
                if dedupe.insert(key) {
                    view.active_connections.push(NetworkConnectionRow {
                        process,
                        pid,
                        local_endpoint: "n/a".to_string(),
                        remote_endpoint: right.to_string(),
                        state: "ESTABLISHED".to_string(),
                    });
                }
            }
            view.active_connections.truncate(MAX_LIST_ITEMS);
        }
    }

    view.top_remote_hosts = sort_label_counts(remote_counts, MAX_TOP_VALUES);
    view
}

fn collect_memory_quickview() -> MemoryQuickView {
    let mut view = MemoryQuickView::default();

    let analysis_path = match resolve_existing_path("memory_corelation/analysis.json") {
        Some(path) => path,
        None => return view,
    };
    view.source = analysis_path.to_string_lossy().into_owned();

    let raw = match read_text_file(&analysis_path) {
        Some(text) => text,
        None => return view,
    };

    let json: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => return view,
    };

    let summary = json.get("summary").cloned().unwrap_or(Value::Null);

    view.risk_level = summary
        .get("risk_level")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();
    view.risk_score = value_to_u64(summary.get("risk_score"));
    view.total_findings = value_to_u64(summary.get("total_findings"));
    view.unique_pids = value_to_u64(summary.get("unique_pids"));
    view.unique_ips = value_to_u64(summary.get("unique_ips"));

    let critical_count = value_to_u64(summary.get("critical_count"));
    let high_count = value_to_u64(summary.get("high_count"));
    let medium_count = value_to_u64(summary.get("medium_count"));
    let low_count = value_to_u64(summary.get("low_count"));
    let info_count = value_to_u64(summary.get("info_count"));

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

    view.severity_segments = vec![
        ("Critical", critical_count, "#ff7351"),
        ("High", high_count, "#f6b73c"),
        ("Medium", medium_count, "#78b8ff"),
        ("Low", low_count, "#2ea043"),
        ("Info", info_count, "#7b8490"),
    ]
    .into_iter()
    .map(|(label, count, color)| MemorySeveritySegment {
        label: label.to_string(),
        count,
        percent: ((count as f64 / severity_total as f64) * 1000.0).round() / 10.0,
        color: color.to_string(),
    })
    .collect();

    if let Some(categories) = json.get("findings_by_category").and_then(Value::as_object) {
        let mut category_counts = HashMap::new();
        for (category, list) in categories {
            let count = list.as_array().map(|arr| arr.len() as u64).unwrap_or(0);
            category_counts.insert(category.clone(), count);
        }
        view.top_categories = sort_label_counts(category_counts, MAX_TOP_VALUES);
    }

    view
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

fn collect_ntfs_quickview() -> NtfsQuickView {
    let mut view = NtfsQuickView::default();

    let ntfs_path = match resolve_existing_path("ntfs_analyzer/output/mft.json") {
        Some(path) => path,
        None => return view,
    };
    view.source = ntfs_path.to_string_lossy().into_owned();

    let file = match fs::File::open(&ntfs_path) {
        Ok(file) => file,
        Err(_) => return view,
    };

    let mut extension_counts: HashMap<String, u64> = HashMap::new();
    let mut total_file_size_bytes = 0u64;

    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let record: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        view.total_entries += 1;
        if record
            .get("InUse")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            view.active_entries += 1;
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
            view.directories += 1;
            continue;
        }

        view.files += 1;

        if is_ads {
            view.ads_entries += 1;
        }

        let file_size = value_to_u64(record.get("FileSize"));
        total_file_size_bytes = total_file_size_bytes.saturating_add(file_size);

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

    view.total_file_size_human = format_size(total_file_size_bytes);
    view.top_extensions = sort_label_counts(extension_counts, 10);
    view
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

    let host = without_scheme
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
        .trim_start_matches("www.");

    host.to_string()
}

fn collect_browser_quickview() -> BrowserQuickView {
    let mut view = BrowserQuickView::default();

    let report_path = match resolve_existing_path("browser_forensics/report.json") {
        Some(path) => path,
        None => return view,
    };
    view.source = report_path.to_string_lossy().into_owned();

    let raw = match read_text_file(&report_path) {
        Some(text) => text,
        None => return view,
    };

    let json: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => return view,
    };

    let summary = json.get("summary").cloned().unwrap_or(Value::Null);
    view.total_browsers = value_to_u64(summary.get("total_browsers"));
    view.total_history_entries = value_to_u64(summary.get("total_history_entries"));
    view.total_downloads = value_to_u64(summary.get("total_downloads"));
    view.total_cookies = value_to_u64(summary.get("total_cookies"));
    view.total_sessions = value_to_u64(summary.get("total_sessions"));

    view.browsers_found = summary
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

                    recent_history.push(BrowserHistoryItem {
                        browser: browser.clone(),
                        title,
                        url,
                        domain,
                        last_visit,
                    });
                }
            }
        }
    }

    recent_history.sort_by(|a, b| {
        b.last_visit
            .cmp(&a.last_visit)
            .then_with(|| a.browser.cmp(&b.browser))
    });
    recent_history.truncate(MAX_LIST_ITEMS);

    view.top_domains = sort_label_counts(domain_counts, MAX_TOP_VALUES);
    view.recent_history = recent_history;
    view
}

fn collect_super_timeline(
    browser_quickview: &BrowserQuickView,
    execution_quickview: &ExecutionQuickView,
) -> SuperTimelineData {
    let mut view = SuperTimelineData::default();
    let mut sources = Vec::new();
    let mut combined_events = Vec::new();

    if let Some(ntfs_path) = resolve_existing_path("ntfs_analyzer/output/mft.json") {
        sources.push(ntfs_path.to_string_lossy().into_owned());

        if let Ok(file) = fs::File::open(&ntfs_path) {
            let reader = BufReader::new(file);
            let mut ntfs_events = Vec::new();

            for line in reader.lines().map_while(Result::ok) {
                let record: Value = match serde_json::from_str(&line) {
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
                if file_name.is_empty() || file_name.starts_with('$') {
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
                    let Some(raw_timestamp) = record.get(field).and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(normalized) = normalize_event_timestamp(raw_timestamp) else {
                        continue;
                    };
                    timestamp_flags.entry(normalized).or_default().push(flag);
                }

                for (timestamp, flags) in timestamp_flags {
                    let Some(parsed) = parse_event_timestamp(&timestamp) else {
                        continue;
                    };
                    push_recent_event(
                        &mut ntfs_events,
                        SuperTimelineEvent {
                            timestamp,
                            epoch_seconds: parsed.timestamp(),
                            lane: "NTFS".to_string(),
                            source: "$MFT".to_string(),
                            event_type: "File MACB".to_string(),
                            macb: macb_signature(&flags),
                            entity: full_path.clone(),
                            detail: truncate_chars(&full_path, 180),
                        },
                        MAX_TIMELINE_NTFS_EVENTS,
                    );
                }
            }

            finalize_recent_events(&mut ntfs_events, MAX_TIMELINE_NTFS_EVENTS);
            combined_events.extend(ntfs_events);
        }
    }

    let mut browser_events = Vec::new();
    if let Some(browser_path) = resolve_existing_path("browser_forensics/report.json") {
        sources.push(browser_path.to_string_lossy().into_owned());

        if let Some(raw) = read_text_file(&browser_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&raw) {
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
                                let Some(raw_timestamp) =
                                    entry.get("last_visit_time").and_then(Value::as_str)
                                else {
                                    continue;
                                };
                                let Some(parsed) = parse_event_timestamp(raw_timestamp) else {
                                    continue;
                                };
                                let url = entry
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                let domain = extract_domain(&url);
                                let title = entry
                                    .get("title")
                                    .and_then(Value::as_str)
                                    .unwrap_or("Untitled");
                                let entity = if !domain.is_empty() {
                                    domain
                                } else {
                                    title.to_string()
                                };

                                push_recent_event(
                                    &mut browser_events,
                                    SuperTimelineEvent {
                                        timestamp: parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                                        epoch_seconds: parsed.timestamp(),
                                        lane: "Browser".to_string(),
                                        source: browser.to_string(),
                                        event_type: "History Visit".to_string(),
                                        macb: String::new(),
                                        entity,
                                        detail: truncate_chars(
                                            if !url.is_empty() { &url } else { title },
                                            180,
                                        ),
                                    },
                                    MAX_TIMELINE_BROWSER_EVENTS,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    if browser_events.is_empty() {
        for item in &browser_quickview.recent_history {
            let Some(parsed) = parse_event_timestamp(&item.last_visit) else {
                continue;
            };
            let entity = if !item.domain.is_empty() {
                item.domain.clone()
            } else {
                item.title.clone()
            };
            push_recent_event(
                &mut browser_events,
                SuperTimelineEvent {
                    timestamp: parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    epoch_seconds: parsed.timestamp(),
                    lane: "Browser".to_string(),
                    source: item.browser.clone(),
                    event_type: "History Visit".to_string(),
                    macb: String::new(),
                    entity,
                    detail: truncate_chars(&item.url, 180),
                },
                MAX_TIMELINE_BROWSER_EVENTS,
            );
        }
    }
    finalize_recent_events(&mut browser_events, MAX_TIMELINE_BROWSER_EVENTS);
    combined_events.extend(browser_events);

    if let Some(prefetch_path) = resolve_prefetch_report() {
        sources.push(prefetch_path.to_string_lossy().into_owned());
        if let Some(raw) = read_text_file(&prefetch_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&raw) {
                let mut prefetch_events = Vec::new();

                if let Some(entries) = json.get("entries").and_then(Value::as_array) {
                    for entry in entries {
                        let executable = entry
                            .get("ExecutableName")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown.exe");
                        let hash = entry.get("Hash").and_then(Value::as_str).unwrap_or("");
                        let source_file = entry
                            .get("SourceFilename")
                            .and_then(Value::as_str)
                            .unwrap_or("");

                        for (field, label) in
                            [("LastRun", "Last Run"), ("PreviousRun0", "Prior Run")]
                        {
                            let Some(raw_timestamp) = entry.get(field).and_then(Value::as_str)
                            else {
                                continue;
                            };
                            let Some(parsed) = parse_event_timestamp(raw_timestamp) else {
                                continue;
                            };
                            let detail = if hash.is_empty() {
                                source_file.to_string()
                            } else {
                                format!("Hash {} | {}", hash, source_file)
                            };

                            push_recent_event(
                                &mut prefetch_events,
                                SuperTimelineEvent {
                                    timestamp: parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                                    epoch_seconds: parsed.timestamp(),
                                    lane: "Prefetch".to_string(),
                                    source: "Prefetch".to_string(),
                                    event_type: label.to_string(),
                                    macb: "EXEC".to_string(),
                                    entity: executable.to_string(),
                                    detail: truncate_chars(&detail, 180),
                                },
                                MAX_TIMELINE_PREFETCH_EVENTS,
                            );
                        }
                    }
                }

                finalize_recent_events(&mut prefetch_events, MAX_TIMELINE_PREFETCH_EVENTS);
                combined_events.extend(prefetch_events);
            }
        }
    }

    let mut execution_events = Vec::new();
    for event in &execution_quickview.recent_commands {
        let Some(parsed) = parse_event_timestamp(&event.timestamp) else {
            continue;
        };
        push_recent_event(
            &mut execution_events,
            SuperTimelineEvent {
                timestamp: parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                epoch_seconds: parsed.timestamp(),
                lane: "Execution".to_string(),
                source: event.source.clone(),
                event_type: "PowerShell Execution".to_string(),
                macb: "EXEC".to_string(),
                entity: event.process.clone(),
                detail: truncate_chars(&event.command, 180),
            },
            MAX_TIMELINE_EXECUTION_EVENTS,
        );
    }
    finalize_recent_events(&mut execution_events, MAX_TIMELINE_EXECUTION_EVENTS);
    combined_events.extend(execution_events);

    combined_events.sort_by(|a, b| a.epoch_seconds.cmp(&b.epoch_seconds));
    view.reference_timestamp = combined_events
        .last()
        .map(|event| event.timestamp.clone())
        .unwrap_or_default();
    view.total_events = combined_events.len() as u64;
    view.events = combined_events;
    view.source = sources.join(" | ");
    view
}

fn collect_connections_engine(
    browser_quickview: &BrowserQuickView,
    network_quickview: &NetworkQuickView,
    execution_quickview: &ExecutionQuickView,
    malicious_process_quickview: &MaliciousProcessQuickView,
    srum_quickview: &SrumQuickView,
) -> ConnectionsEngineData {
    let mut view = ConnectionsEngineData::default();
    let mut sources = Vec::new();
    let mut nodes_map: HashMap<String, ConnectionNode> = HashMap::new();
    let mut links_map: HashMap<(String, String, String), u64> = HashMap::new();

    if !browser_quickview.source.is_empty() {
        sources.push(browser_quickview.source.clone());
    }
    if !network_quickview.source.is_empty() {
        sources.push(network_quickview.source.clone());
    }
    if !execution_quickview.source.is_empty() {
        sources.push(execution_quickview.source.clone());
    }
    if !srum_quickview.source.is_empty() {
        sources.push(srum_quickview.source.clone());
    }

    let primary_user = srum_quickview
        .top_consumers
        .iter()
        .map(|consumer| consumer.user.trim())
        .find(|user| !user.is_empty() && !user.eq_ignore_ascii_case("unknown"))
        .map(|user| user.to_string())
        .or_else(|| {
            srum_quickview
                .critical_alerts
                .iter()
                .map(|alert| alert.user.trim())
                .find(|user| !user.is_empty() && !user.eq_ignore_ascii_case("unknown"))
                .map(|user| user.to_string())
        });

    for consumer in srum_quickview.top_consumers.iter().take(MAX_LIST_ITEMS) {
        let Some(process_id) = upsert_connection_node(
            &mut nodes_map,
            "process",
            &consumer.app_label,
            &consumer.app_label,
            "process",
            &consumer.app_path,
        ) else {
            continue;
        };

        if let Some(user_id) = upsert_connection_node(
            &mut nodes_map,
            "user",
            &consumer.user,
            &consumer.user,
            "user",
            &format!("SRUM monitored app for {}", consumer.user),
        ) {
            record_connection_link(&mut links_map, &user_id, &process_id, "utilized");
        }

        if let Some(file_id) = upsert_connection_node(
            &mut nodes_map,
            "file",
            &consumer.app_path,
            &consumer.app_label,
            "file",
            &consumer.app_path,
        ) {
            record_connection_link(&mut links_map, &process_id, &file_id, "binary_path");
        }
    }

    for alert in srum_quickview.critical_alerts.iter().take(MAX_LIST_ITEMS) {
        let Some(process_id) = upsert_connection_node(
            &mut nodes_map,
            "process",
            &alert.app_label,
            &alert.app_label,
            "process",
            &alert.app_path,
        ) else {
            continue;
        };

        if let Some(user_id) = upsert_connection_node(
            &mut nodes_map,
            "user",
            &alert.user,
            &alert.user,
            "user",
            &alert.description,
        ) {
            record_connection_link(&mut links_map, &user_id, &process_id, "alerted_app");
        }
    }

    for event in &execution_quickview.recent_commands {
        let Some(process_id) = upsert_connection_node(
            &mut nodes_map,
            "process",
            &event.process,
            &event.process,
            "process",
            &event.command,
        ) else {
            continue;
        };

        if let Some(user) = &primary_user {
            if let Some(user_id) = upsert_connection_node(
                &mut nodes_map,
                "user",
                user,
                user,
                "user",
                "Primary SRUM user context",
            ) {
                record_connection_link(&mut links_map, &user_id, &process_id, "executed");
            }
        }

        for executable in extract_executable_tokens(&event.command) {
            if let Some(file_id) = upsert_connection_node(
                &mut nodes_map,
                "file",
                &executable,
                &executable,
                "file",
                &event.command,
            ) {
                record_connection_link(
                    &mut links_map,
                    &process_id,
                    &file_id,
                    "referenced_executable",
                );
            }
        }

        for ip in extract_ipv4_tokens(&event.command) {
            if let Some(ip_id) =
                upsert_connection_node(&mut nodes_map, "ip", &ip, &ip, "ip", &event.command)
            {
                record_connection_link(&mut links_map, &process_id, &ip_id, "targeted_ip");
            }
        }
    }

    for connection in &network_quickview.active_connections {
        let Some(process_id) = upsert_connection_node(
            &mut nodes_map,
            "process",
            &connection.process,
            &connection.process,
            "process",
            &format!("PID {}", connection.pid),
        ) else {
            continue;
        };

        let remote_host = connection
            .remote_endpoint
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(connection.remote_endpoint.as_str());
        if let Some(ip_id) = upsert_connection_node(
            &mut nodes_map,
            "ip",
            remote_host,
            remote_host,
            "ip",
            &connection.remote_endpoint,
        ) {
            record_connection_link(&mut links_map, &process_id, &ip_id, "connected_to");
        }
    }

    for history in browser_quickview.recent_history.iter().take(MAX_LIST_ITEMS) {
        let Some(browser_id) = upsert_connection_node(
            &mut nodes_map,
            "browser",
            &history.browser,
            &history.browser,
            "browser",
            &history.url,
        ) else {
            continue;
        };

        if let Some(user) = &primary_user {
            if let Some(user_id) = upsert_connection_node(
                &mut nodes_map,
                "user",
                user,
                user,
                "user",
                "Primary SRUM user context",
            ) {
                record_connection_link(&mut links_map, &user_id, &browser_id, "used_browser");
            }
        }

        let domain = if !history.domain.is_empty() {
            history.domain.clone()
        } else {
            extract_domain(&history.url)
        };
        if let Some(domain_id) = upsert_connection_node(
            &mut nodes_map,
            "domain",
            &domain,
            &domain,
            "domain",
            &history.url,
        ) {
            record_connection_link(&mut links_map, &browser_id, &domain_id, "visited");
        }
    }

    if let Some(prefetch_path) = resolve_prefetch_report() {
        sources.push(prefetch_path.to_string_lossy().into_owned());
        if let Some(raw) = read_text_file(&prefetch_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&raw) {
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

                for entry in entries.into_iter().take(24) {
                    let executable = entry
                        .get("ExecutableName")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown.exe");
                    let Some(process_id) = upsert_connection_node(
                        &mut nodes_map,
                        "process",
                        executable,
                        executable,
                        "process",
                        entry
                            .get("SourceFilename")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ) else {
                        continue;
                    };

                    if let Some(hash) = entry.get("Hash").and_then(Value::as_str) {
                        if let Some(hash_id) = upsert_connection_node(
                            &mut nodes_map,
                            "hash",
                            hash,
                            hash,
                            "hash",
                            executable,
                        ) {
                            record_connection_link(
                                &mut links_map,
                                &process_id,
                                &hash_id,
                                "prefetch_hash",
                            );
                        }
                    }

                    if let Some(path) = entry.get("SourceFilename").and_then(Value::as_str) {
                        if let Some(file_id) = upsert_connection_node(
                            &mut nodes_map,
                            "file",
                            path,
                            executable,
                            "file",
                            path,
                        ) {
                            record_connection_link(
                                &mut links_map,
                                &process_id,
                                &file_id,
                                "prefetch_artifact",
                            );
                        }
                    }
                }
            }
        }
    }

    for node in &malicious_process_quickview.tree_nodes {
        let detail = format!("PID {} | {}", node.pid, node.first_seen);
        let _ = upsert_connection_node(
            &mut nodes_map,
            "process",
            &node.process,
            &node.label,
            "process",
            &detail,
        );
    }

    for link in &malicious_process_quickview.tree_links {
        let source_process = malicious_process_quickview
            .tree_nodes
            .iter()
            .find(|node| node.id == link.source)
            .map(|node| node.process.clone())
            .unwrap_or_default();
        let target_process = malicious_process_quickview
            .tree_nodes
            .iter()
            .find(|node| node.id == link.target)
            .map(|node| node.process.clone())
            .unwrap_or_default();

        if source_process.is_empty() || target_process.is_empty() {
            continue;
        }

        let source_id = connection_node_id("process", &source_process);
        let target_id = connection_node_id("process", &target_process);
        if nodes_map.contains_key(&source_id) && nodes_map.contains_key(&target_id) {
            record_connection_link(&mut links_map, &source_id, &target_id, &link.relationship);
        }
    }

    let mut links: Vec<ConnectionLink> = links_map
        .into_iter()
        .map(|((source, target, relationship), hits)| ConnectionLink {
            source,
            target,
            relationship,
            hits,
        })
        .collect();
    links.sort_by(|a, b| {
        b.hits
            .cmp(&a.hits)
            .then_with(|| a.relationship.cmp(&b.relationship))
    });

    let referenced_ids: HashSet<String> = links
        .iter()
        .flat_map(|link| [link.source.clone(), link.target.clone()])
        .collect();

    let mut nodes: Vec<ConnectionNode> = nodes_map
        .into_values()
        .filter(|node| referenced_ids.contains(&node.id))
        .collect();
    nodes.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.label.cmp(&b.label)));

    let mut focus_entities: Vec<ConnectionFocusEntity> = nodes
        .iter()
        .filter(|node| matches!(node.entity_type.as_str(), "user" | "ip" | "hash"))
        .map(|node| ConnectionFocusEntity {
            id: node.id.clone(),
            label: node.label.clone(),
            entity_type: node.entity_type.clone(),
        })
        .collect();
    focus_entities.truncate(MAX_CONNECTION_FOCUS_ITEMS);

    if focus_entities.is_empty() {
        focus_entities = nodes
            .iter()
            .take(MAX_CONNECTION_FOCUS_ITEMS)
            .map(|node| ConnectionFocusEntity {
                id: node.id.clone(),
                label: node.label.clone(),
                entity_type: node.entity_type.clone(),
            })
            .collect();
    }

    view.default_focus = focus_entities
        .first()
        .map(|entity| entity.id.clone())
        .unwrap_or_default();
    view.nodes = nodes;
    view.links = links;
    view.focus_entities = focus_entities;
    view.source = sources.join(" | ");
    view
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
            .map(|item| truncate_chars(item, 92))
            .collect::<Vec<_>>()
            .join(" | "),
        Some(Value::Object(map)) => map
            .iter()
            .take(2)
            .map(|(key, value)| {
                let rendered = value
                    .as_str()
                    .map(|text| truncate_chars(text, 72))
                    .unwrap_or_else(|| truncate_chars(&value.to_string(), 72));
                format!("{}: {}", key, rendered)
            })
            .collect::<Vec<_>>()
            .join(" | "),
        Some(Value::String(text)) => truncate_chars(text, 120),
        Some(other) => truncate_chars(&other.to_string(), 120),
        None => String::new(),
    }
}

fn collect_srum_quickview() -> SrumQuickView {
    let mut view = SrumQuickView::default();
    let srum_path = match resolve_existing_path("srum_analysis/reports/srum_analysis_report.json") {
        Some(path) => path,
        None => return view,
    };

    view.source = srum_path.to_string_lossy().to_string();

    let raw = match read_text_file(&srum_path) {
        Some(raw) => raw,
        None => return view,
    };
    let json: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => return view,
    };

    let summary = json.get("summary");
    view.critical_count = value_to_u64(summary.and_then(|v| v.get("critical")));
    view.high_count = value_to_u64(summary.and_then(|v| v.get("high")));
    view.total_findings = value_to_u64(summary.and_then(|v| v.get("total")));

    let mut disk_read_bytes = 0u64;
    let mut disk_write_bytes = 0u64;
    let mut network_bytes = 0u64;
    let mut consumers = Vec::new();

    if let Some(app_statistics) = json.get("app_statistics").and_then(Value::as_array) {
        view.monitored_apps = app_statistics.len() as u64;

        for app in app_statistics {
            let foreground_read = value_to_u64(app.get("total_foreground_bytes_read"));
            let foreground_write = value_to_u64(app.get("total_foreground_bytes_written"));
            let background_read = value_to_u64(app.get("total_background_bytes_read"));
            let background_write = value_to_u64(app.get("total_background_bytes_written"));
            let bytes_sent = value_to_u64(app.get("total_bytes_sent"));
            let bytes_received = value_to_u64(app.get("total_bytes_received"));

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

            consumers.push(SrumTopConsumer {
                app_label: srum_app_label(&app_path),
                app_path,
                user: app
                    .get("user")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown")
                    .to_string(),
                total_usage_human: format_size(total_usage_bytes),
                total_usage_bytes,
                percent_of_total: 0.0,
                last_seen: app
                    .get("last_seen")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown")
                    .to_string(),
                record_count: value_to_u64(app.get("record_count")),
            });
        }
    }

    let total_usage_bytes = disk_read_bytes
        .saturating_add(disk_write_bytes)
        .saturating_add(network_bytes);
    let total_usage_denominator = total_usage_bytes.max(1) as f64;

    view.total_usage_human = format_size(total_usage_bytes);
    view.disk_read_human = format_size(disk_read_bytes);
    view.disk_write_human = format_size(disk_write_bytes);
    view.network_human = format_size(network_bytes);
    view.disk_read_percent =
        ((disk_read_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0;
    view.disk_write_percent =
        ((disk_write_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0;
    view.network_percent =
        ((network_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0;

    consumers.sort_by(|a, b| {
        b.total_usage_bytes
            .cmp(&a.total_usage_bytes)
            .then_with(|| a.app_label.cmp(&b.app_label))
    });
    for consumer in &mut consumers {
        consumer.percent_of_total =
            ((consumer.total_usage_bytes as f64 / total_usage_denominator) * 1000.0).round() / 10.0;
    }
    consumers.truncate(5);
    view.top_consumers = consumers;

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

                critical_alerts.push(SrumCriticalAlert {
                    id: item
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    severity: item
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("Critical")
                        .to_string(),
                    category: item
                        .get("category")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string(),
                    title: item
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("SRUM alert")
                        .to_string(),
                    description: truncate_chars(
                        item.get("description")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        180,
                    ),
                    timestamp: item
                        .get("timestamp")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string(),
                    app_label: srum_app_label(&app_path),
                    app_path,
                    user: item
                        .get("user")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string(),
                    evidence_summary: srum_evidence_summary(item.get("evidence")),
                });
            }
        }
    }

    critical_alerts.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.title.cmp(&b.title))
    });
    critical_alerts.truncate(5);
    view.critical_alerts = critical_alerts;

    view
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let truncated: String = value.chars().take(max_chars).collect();
    format!("{}...", truncated.trim_end())
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

fn extract_event_id(text: &str) -> String {
    let event_re = Regex::new(r"\b\d{3,5}\b").expect("valid event id regex");
    event_re
        .find(text)
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "N/A".to_string())
}

fn parse_count(value: &str) -> u64 {
    value.replace(',', "").trim().parse::<u64>().unwrap_or(0)
}

fn resolve_windows_event_report() -> Option<PathBuf> {
    let explicit = std::env::var("REPORT_PATHS_FILE").ok().map(PathBuf::from);
    let config_path =
        explicit.or_else(|| resolve_existing_path("portal_from_azure/report_paths.toml"));

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

    resolve_existing_path("portal_from_azure/tools/win_event_analysis/mac-report.html")
        .or_else(|| resolve_existing_path("tools/win_event_analysis/mac-report.html"))
}

fn collect_windows_event_quickview() -> WindowsEventQuickView {
    let mut view = WindowsEventQuickView {
        title: "Windows Event Log Alert".to_string(),
        timestamp: "Unknown".to_string(),
        event_id: "N/A".to_string(),
        host: "Unknown".to_string(),
        summary: "No suspicious Windows Event indicator could be parsed from available reports."
            .to_string(),
        priority: "MONITOR".to_string(),
        count: 0,
        source_label: "windows-event".to_string(),
        category: "EVENT_LOG".to_string(),
        ..WindowsEventQuickView::default()
    };

    let report_path = match resolve_windows_event_report() {
        Some(path) => path,
        None => return view,
    };
    view.source = report_path.to_string_lossy().into_owned();

    let raw_html = match read_text_file(&report_path) {
        Some(raw) => raw,
        None => return view,
    };

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

        view.title = format!("Suspicious {} in Windows Event Logs", technique);
        view.timestamp = timestamp;
        view.event_id = extract_event_id(&source);
        view.host = host;
        view.count = count;
        view.source_label = source;
        view.category = "SCRIPTING/ENCODING".to_string();
        view.summary = format!(
            "{}. Event log evidence indicates '{}' observed {} time(s).",
            truncate_chars(&preview, 180),
            technique,
            count
        );
        view.priority = if count >= 10 {
            "HIGH PRIORITY"
        } else {
            "MEDIUM PRIORITY"
        }
        .to_string();
        return view;
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

        view.title = format!("PowerShell {} in Windows Event Logs", event_type);
        view.timestamp = timestamp;
        view.event_id = extract_event_id(&script_preview);
        view.host = host;
        view.count = count;
        view.source_label = "PowerShell Activity".to_string();
        view.category = "POWERSHELL".to_string();
        view.summary = format!(
            "{}. Event logs recorded {} occurrence(s) for '{}'.",
            truncate_chars(&script_preview, 180),
            count,
            event_type
        );
        view.priority = if count >= 20 {
            "HIGH PRIORITY"
        } else {
            "MEDIUM PRIORITY"
        }
        .to_string();
    }

    view
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
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

fn execution_value_to_string(value: &Value) -> Option<String> {
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
            .and_then(execution_value_to_string)
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

fn collect_runmru_commands(
    key: &Value,
    commands: &mut Vec<ExecutionEvent>,
    seen: &mut HashSet<String>,
) {
    let Some(path) = key.get("path").and_then(Value::as_str) else {
        return;
    };
    let path_lower = path.to_lowercase();
    let name = key.get("name").and_then(Value::as_str).unwrap_or("");
    let is_runmru = name.eq_ignore_ascii_case("runmru") || path_lower.contains("\\runmru");
    if !is_runmru {
        if let Some(subkeys) = key.get("subkeys").and_then(Value::as_array) {
            for subkey in subkeys {
                collect_runmru_commands(subkey, commands, seen);
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

            if let Some(command) = value.get("data").and_then(execution_value_to_string) {
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

        commands.push(ExecutionEvent {
            timestamp: timestamp.clone(),
            process: "RunMRU".to_string(),
            command,
            pid: "n/a".to_string(),
            source: path.to_string(),
        });
    }

    if let Some(subkeys) = key.get("subkeys").and_then(Value::as_array) {
        for subkey in subkeys {
            collect_runmru_commands(subkey, commands, seen);
        }
    }
}

fn collect_console_history_commands(
    path: &Path,
    commands: &mut Vec<ExecutionEvent>,
    seen: &mut HashSet<String>,
) {
    let Some(raw) = read_text_file(path) else {
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

        commands.push(ExecutionEvent {
            timestamp: timestamp.clone(),
            process: "ConsoleHost".to_string(),
            command,
            pid: "n/a".to_string(),
            source: path.to_string_lossy().to_string(),
        });

        if commands.len() >= MAX_LIST_ITEMS * 4 {
            break;
        }
    }
}

fn fallback_recent_commands_from_memory() -> Vec<ExecutionEvent> {
    let mut fallback = Vec::new();
    let cmdscan_path = match resolve_existing_path("memory_corelation/jsonl/cmdscan.jsonl") {
        Some(path) => path,
        None => return fallback,
    };

    let file = match fs::File::open(&cmdscan_path) {
        Ok(file) => file,
        Err(_) => return fallback,
    };

    let mut seen = HashSet::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let record: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let property = record.get("Property").and_then(Value::as_str).unwrap_or("");
        if !property.contains("CommandBucket_Command_")
            && property != "_COMMAND_HISTORY.CommandBucket"
        {
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

        let pid = value_to_u64(record.get("PID"));
        let process = record
            .get("Application")
            .and_then(Value::as_str)
            .or_else(|| record.get("Process").and_then(Value::as_str))
            .unwrap_or("conhost.exe")
            .to_string();
        let key_id = format!("cmdscan|{}|{}", pid, command.to_lowercase());
        if !seen.insert(key_id) {
            continue;
        }

        fallback.push(ExecutionEvent {
            timestamp: "memory cmdscan".to_string(),
            process,
            command,
            pid: if pid > 0 {
                pid.to_string()
            } else {
                "n/a".to_string()
            },
            source: "memory_corelation/jsonl/cmdscan.jsonl".to_string(),
        });

        if fallback.len() >= MAX_LIST_ITEMS * 4 {
            break;
        }
    }

    fallback
}

fn collect_execution_quickview() -> ExecutionQuickView {
    let mut commands = Vec::new();
    let mut sources = Vec::new();
    let mut seen = HashSet::new();

    let registry_path = resolve_existing_path("registry_parser/output/NTUSER.DAT.json")
        .or_else(|| resolve_existing_path("registry_parser/output/ntuser.dat.json"))
        .or_else(|| resolve_existing_path("registry_parser/output/combined.json"));
    if let Some(path) = registry_path.as_ref() {
        if let Some(raw) = read_text_file(path) {
            if let Ok(json) = serde_json::from_str::<Value>(&raw) {
                if let Some(root) = json.get("root") {
                    collect_runmru_commands(root, &mut commands, &mut seen);
                } else {
                    collect_runmru_commands(&json, &mut commands, &mut seen);
                }
            }
        }
        sources.push(path.to_string_lossy().to_string());
    }

    let console_history_path = resolve_existing_path("ConsoleHost_history.txt")
        .or_else(|| {
            resolve_existing_path(
                "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            )
        })
        .or_else(|| resolve_existing_path("PowerShell/ConsoleHost_history.txt"));
    if let Some(path) = console_history_path.as_ref() {
        collect_console_history_commands(path, &mut commands, &mut seen);
        sources.push(path.to_string_lossy().to_string());
    }

    if commands.is_empty() {
        commands = fallback_recent_commands_from_memory();
        if !commands.is_empty() {
            sources.push("memory_corelation/jsonl/cmdscan.jsonl".to_string());
        }
    }

    commands.sort_by(|a, b| {
        let a_unknown = a.timestamp.to_lowercase().contains("unknown");
        let b_unknown = b.timestamp.to_lowercase().contains("unknown");
        a_unknown
            .cmp(&b_unknown)
            .then_with(|| {
                parse_event_timestamp(&b.timestamp).cmp(&parse_event_timestamp(&a.timestamp))
            })
            .then_with(|| a.command.cmp(&b.command))
    });
    commands.truncate(MAX_LIST_ITEMS);

    ExecutionQuickView {
        source: sources.join(" | "),
        command_count: commands.len() as u64,
        recent_commands: commands,
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/host-information", get(host_information_page))
}

fn resolve_host_information_quickview() -> HostInformationQuickView {
    let Some(seed) = load_dashboard_quickview_data() else {
        return HostInformationQuickView::default();
    };

    if !seed.host_information_quickview.source.is_empty()
        || !seed.host_information_quickview.hostname.is_empty()
        || !seed.host_information_quickview.user_accounts.is_empty()
    {
        seed.host_information_quickview
    } else {
        HostInformationQuickView::default()
    }
}

async fn host_information_page(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Html<String> {
    let host_information_quickview = resolve_host_information_quickview();

    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        }),
    );
    ctx.insert(
        "avatar_letter",
        &template_utils::avatar_letter(&user.username),
    );
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    ctx.insert("host_information_quickview", &host_information_quickview);

    template_utils::render(&state.templates, "host_information.html", &ctx)
}

async fn dashboard(State(state): State<Arc<AppState>>, AuthUser(user): AuthUser) -> Html<String> {
    let dashboard_seed = load_dashboard_quickview_data();

    let artifact_summary = collect_artifact_summary(Path::new(FETCHED_FILES_DIR));
    let mut host_information_quickview = HostInformationQuickView::default();
    let mut network_quickview = collect_network_quickview();
    let mut memory_quickview = collect_memory_quickview();
    let mut ntfs_quickview = collect_ntfs_quickview();
    let mut browser_quickview = collect_browser_quickview();
    let mut execution_quickview = collect_execution_quickview();
    let mut windows_event_quickview = collect_windows_event_quickview();
    let mut srum_quickview = collect_srum_quickview();
    let mut super_timeline = SuperTimelineData::default();
    let mut connections_engine = ConnectionsEngineData::default();

    if let Some(seed) = dashboard_seed {
        if !seed.host_information_quickview.source.is_empty()
            || !seed.host_information_quickview.hostname.is_empty()
            || !seed.host_information_quickview.user_accounts.is_empty()
        {
            host_information_quickview = seed.host_information_quickview;
        }

        if !seed.network_quickview.source.is_empty()
            || seed.network_quickview.total_connections > 0
            || !seed.network_quickview.active_connections.is_empty()
        {
            network_quickview = seed.network_quickview;
        }

        memory_quickview = seed.memory_quickview;

        if !seed.ntfs_quickview.source.is_empty()
            || seed.ntfs_quickview.total_entries > 0
            || !seed.ntfs_quickview.top_extensions.is_empty()
        {
            ntfs_quickview = seed.ntfs_quickview;
        }

        if !seed.browser_quickview.source.is_empty()
            || seed.browser_quickview.total_browsers > 0
            || !seed.browser_quickview.recent_history.is_empty()
        {
            browser_quickview = seed.browser_quickview;
        }

        if !seed.windows_event_quickview.source.is_empty()
            || seed.windows_event_quickview.count > 0
            || !seed.windows_event_quickview.summary.is_empty()
        {
            windows_event_quickview = seed.windows_event_quickview;
        }

        if !seed.srum_quickview.source.is_empty()
            || seed.srum_quickview.total_findings > 0
            || !seed.srum_quickview.critical_alerts.is_empty()
        {
            srum_quickview = seed.srum_quickview;
        }

        if !seed.execution_quickview.source.is_empty()
            || seed.execution_quickview.command_count > 0
            || !seed.execution_quickview.recent_commands.is_empty()
        {
            execution_quickview = seed.execution_quickview;
        }

        if !seed.super_timeline.events.is_empty() {
            super_timeline = seed.super_timeline;
        }

        if !seed.connections_engine.nodes.is_empty() || !seed.connections_engine.links.is_empty() {
            connections_engine = seed.connections_engine;
        }
    }

    ntfs_quickview.total_file_size_human = artifact_summary.total_size_human.clone();

    let malicious_process_quickview = collect_malicious_process_quickview(
        &execution_quickview,
        &network_quickview,
        &windows_event_quickview,
    );

    if super_timeline.events.is_empty() {
        super_timeline = collect_super_timeline(&browser_quickview, &execution_quickview);
    }

    if connections_engine.nodes.is_empty() && connections_engine.links.is_empty() {
        connections_engine = collect_connections_engine(
            &browser_quickview,
            &network_quickview,
            &execution_quickview,
            &malicious_process_quickview,
            &srum_quickview,
        );
    }

    // Quick ipsum stats (non-blocking read)
    let (ioc_total, ioc_high, ioc_critical, ioc_updated) = {
        let ipsum = state.ipsum.read().await;
        (
            ipsum.total,
            ipsum.count_above(5),
            ipsum.count_above(8),
            ipsum
                .last_updated
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        )
    };

    let report_routes = load_report_route_links();

    let resources = serde_json::json!([
        {"id":"timeline","name":"Timeline Explorer","description":"View csv, json, and jsonl forensic outputs","icon":"fa-solid fa-chart-line","url":"/tools/timeline/","status":"active"},
        {"id":"registry","name":"Registry Viewer","description":"Windows Registry analysis and investigation","icon":"fa-solid fa-folder-open","url":"/tools/registry","status":"active"},
        {"id":"host-information","name":"Host Information","description":"Registry-backed host identity, interfaces, security posture, and user profiles","icon":"fa-solid fa-fingerprint","url":"/host-information","status":"active"},
        {"id":"memory","name":"Memory Analysis","description":"Volatile memory capture & analysis","icon":"fa-solid fa-brain","url":report_url(&report_routes, "memory", "#memory-section"),"status":"active"},
        {"id":"browser-forensics","name":"Browser Analysis","description":"Browser history, downloads, cookies & session analysis","icon":"fa-solid fa-globe","url":report_url(&report_routes, "browser-forensics", "#browser-section"),"status":"active"},
        {"id":"srum","name":"System Resource Utilization","description":"SRUM application activity, utilization totals, and critical alerts","icon":"fa-solid fa-gauge-high","url":report_url(&report_routes, "srum", "#srum-section"),"status":"active"},
        {"id":"windows-event","name":"Windows Event","description":"Windows Event Log viewer and analyzer","icon":"fa-solid fa-scroll","url":report_url(&report_routes, "windows-event", "/reports/windows-event"),"status":"active"},
        {"id":"prefetch-report","name":"Prefetch Viewer","description":"Open the latest prefetch analysis report","icon":"fa-solid fa-list-check","url":report_url(&report_routes, "prefetch", "/reports/prefetch"),"status":"active"},
        {"id":"timesketch","name":"Timesketch","description":"Collaborative forensic timeline analysis","icon":"fa-solid fa-clock","url":"/tools/timesketch/","status":"active"},        {"id":"ioc-hash-scan","name":"IOC/Hash Scan","description":"Cross-check IOCs and file hashes against known indicators","icon":"fa-solid fa-fingerprint","url":"/reports/ioc-scan","status":"active"},
        {"id":"network-forensics","name":"Network Forensics","description":"Investigate network artifacts, flows, and communication patterns","icon":"fa-solid fa-network-wired","url":report_url(&report_routes, "network-forensics", "#network-section"),"status":"active"},
        {"id":"iocs","name":"IOCs","description":"Indicators of Compromise tracker","icon":"fa-solid fa-bullseye","url":"/tools/iocs","status":"active","special":true},
        {"id":"server-terminal","name":"Server Terminal","description":"Interactive shell access to the analysis server","icon":"fa-solid fa-terminal","url":"/tools/terminal","status":"active"},
        {"id":"reports","name":"Reports","description":"Generate security reports","icon":"fa-solid fa-file-alt","url":"/tools/reporting","status":"active"},
        {"id":"settings","name":"Settings","description":"Portal configuration","icon":"fa-solid fa-gear","url":"#settings","status":"active"}
    ]);

    let metrics = serde_json::json!({
        "active_sessions": 1,
        "last_login": "Just now",
        "security_score": 95,
        "alerts": memory_quickview
            .severity_segments
            .iter()
            .find(|segment| segment.label == "Critical")
            .map(|segment| segment.count)
            .unwrap_or(0),
    });

    let mut ctx = tera::Context::new();
    ctx.insert(
        "user",
        &serde_json::json!({
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        }),
    );
    ctx.insert(
        "avatar_letter",
        &template_utils::avatar_letter(&user.username),
    );
    ctx.insert("resources", &resources);
    ctx.insert("metrics", &metrics);
    ctx.insert("inactivity_timeout", &INACTIVITY_TIMEOUT_MINUTES);
    ctx.insert("ioc_total", &ioc_total);
    ctx.insert("ioc_high", &ioc_high);
    ctx.insert("ioc_critical", &ioc_critical);
    ctx.insert("ioc_updated", &ioc_updated);
    ctx.insert("artifact_summary", &artifact_summary);
    ctx.insert("host_information_quickview", &host_information_quickview);
    ctx.insert("network_quickview", &network_quickview);
    ctx.insert("memory_quickview", &memory_quickview);
    ctx.insert("ntfs_quickview", &ntfs_quickview);
    ctx.insert("browser_quickview", &browser_quickview);
    ctx.insert("execution_quickview", &execution_quickview);
    ctx.insert("windows_event_quickview", &windows_event_quickview);
    ctx.insert("malicious_process_quickview", &malicious_process_quickview);
    ctx.insert("srum_quickview", &srum_quickview);
    ctx.insert("super_timeline", &super_timeline);
    ctx.insert("connections_engine", &connections_engine);
    ctx.insert(
        "artifact_type_data_json",
        &serde_json::to_string(&artifact_summary.top_types).unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "memory_map_data_json",
        &serde_json::to_string(&memory_quickview.severity_segments)
            .unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "browser_domain_data_json",
        &serde_json::to_string(&browser_quickview.top_domains).unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "process_tree_nodes_json",
        &serde_json::to_string(&malicious_process_quickview.tree_nodes)
            .unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "process_tree_links_json",
        &serde_json::to_string(&malicious_process_quickview.tree_links)
            .unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "super_timeline_events_json",
        &serde_json::to_string(&super_timeline.events).unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "connection_nodes_json",
        &serde_json::to_string(&connections_engine.nodes).unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "connection_links_json",
        &serde_json::to_string(&connections_engine.links).unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "connection_focus_entities_json",
        &serde_json::to_string(&connections_engine.focus_entities)
            .unwrap_or_else(|_| "[]".to_string()),
    );
    ctx.insert(
        "default_connection_focus_json",
        &serde_json::to_string(&connections_engine.default_focus)
            .unwrap_or_else(|_| "\"\"".to_string()),
    );

    template_utils::render(&state.templates, "dashboard.html", &ctx)
}
