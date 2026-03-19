/// Dashboard route – mirrors app/routers/dashboard.py
use axum::{Router, extract::State, response::Html, routing::get};
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
const DASHBOARD_QUICKVIEW_JSON_ENV: &str = "DASHBOARD_QUICKVIEW_JSON";
const MAX_ARTIFACT_TYPES: usize = 10;
const MAX_LIST_ITEMS: usize = 8;
const MAX_TOP_VALUES: usize = 6;
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
    powershell_events: u64,
    recent_powershell: Vec<ExecutionEvent>,
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

#[derive(Deserialize, Default)]
struct DashboardQuickviewData {
    #[serde(default)]
    artifact_summary: ArtifactSummary,
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
    #[serde(default)]
    malicious_process_quickview: MaliciousProcessQuickView,
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
    if let Ok(from_env) = std::env::var(DASHBOARD_QUICKVIEW_JSON_ENV) {
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

    resolve_existing_path("portal_from_azure/rust-backend/data/dashboard_quickview.json")
        .or_else(|| resolve_existing_path("rust-backend/data/dashboard_quickview.json"))
        .or_else(|| resolve_existing_path("data/dashboard_quickview.json"))
}

fn load_dashboard_quickview_data() -> Option<DashboardQuickviewData> {
    let path = resolve_dashboard_quickview_json()?;
    let raw = read_text_file(&path)?;
    serde_json::from_str::<DashboardQuickviewData>(&raw).ok()
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

    for event in &execution_quickview.recent_powershell {
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

    for event in &execution_quickview.recent_powershell {
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
    view.top_extensions = sort_label_counts(extension_counts, MAX_TOP_VALUES);
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
        r#"(?s)<div class="command-title"><span>{}</span>.*?<tbody>\s*<tr>(.*?)</tr>"#,
        regex::escape(section_title)
    );
    let row_re = Regex::new(&pattern).ok()?;
    let row_html = row_re.captures(report_html)?.get(1)?.as_str();

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

fn extract_between(text: &str, start: &str, end: &str) -> Option<String> {
    let start_idx = text.find(start)? + start.len();
    let rest = &text[start_idx..];
    let end_idx = rest.find(end)?;
    Some(rest[..end_idx].trim().to_string())
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

fn resolve_powershell_report() -> Option<PathBuf> {
    let output_root = resolve_existing_path("output")?;

    let mut reports: Vec<PathBuf> = fs::read_dir(&output_root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("live_ps_d3_"))
                    .unwrap_or(false)
        })
        .map(|path| path.join("forensic_report.html"))
        .filter(|path| path.exists())
        .collect();

    reports.sort_by(|a, b| {
        b.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .cmp(
                a.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or_default(),
            )
    });

    reports.into_iter().next()
}

fn fallback_powershell_from_memory() -> Vec<ExecutionEvent> {
    let mut fallback = Vec::new();
    let cmdline_path = match resolve_existing_path("memory_corelation/jsonl/cmdline.jsonl") {
        Some(path) => path,
        None => return fallback,
    };

    let file = match fs::File::open(&cmdline_path) {
        Ok(file) => file,
        Err(_) => return fallback,
    };

    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let record: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let process = record
            .get("Process")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let args = record
            .get("Args")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let pid = value_to_u64(record.get("PID"));

        let joined = format!("{} {}", process, args).to_lowercase();
        if !joined.contains("powershell") {
            continue;
        }

        fallback.push(ExecutionEvent {
            timestamp: "From memory cmdline".to_string(),
            process: process.to_string(),
            command: normalize_command(&args),
            pid: if pid > 0 {
                pid.to_string()
            } else {
                "n/a".to_string()
            },
            source: "memory_corelation/jsonl/cmdline.jsonl".to_string(),
        });

        if fallback.len() >= MAX_LIST_ITEMS {
            break;
        }
    }

    fallback
}

fn collect_execution_quickview() -> ExecutionQuickView {
    let mut view = ExecutionQuickView::default();

    let report_path = match resolve_powershell_report() {
        Some(path) => path,
        None => {
            view.recent_powershell = fallback_powershell_from_memory();
            view.powershell_events = view.recent_powershell.len() as u64;
            return view;
        }
    };

    view.source = report_path.to_string_lossy().into_owned();

    let html = match read_text_file(&report_path) {
        Some(text) => text,
        None => {
            view.recent_powershell = fallback_powershell_from_memory();
            view.powershell_events = view.recent_powershell.len() as u64;
            return view;
        }
    };

    let mut seen = HashSet::new();

    for line in html.lines() {
        let normalized = line.trim_start_matches('\u{feff}');
        if !normalized.to_lowercase().contains("powershell") || !normalized.contains("[Evidence]") {
            continue;
        }

        let timestamp = extract_between(normalized, "[Timestamp]</span>", "</div>")
            .unwrap_or_else(|| "Unknown".to_string());
        let process = extract_between(normalized, "[Process]</span>", "</div>")
            .unwrap_or_else(|| "powershell.exe".to_string());
        let evidence_encoded =
            extract_between(normalized, "[Evidence]</span>", "</div>").unwrap_or_default();
        let evidence_json = html_unescape(&evidence_encoded);

        let evidence_value: Option<Value> = serde_json::from_str(&evidence_json).ok();
        let command = evidence_value
            .as_ref()
            .and_then(|value| value.get("CommandLine"))
            .and_then(Value::as_str)
            .map(normalize_command)
            .unwrap_or_else(|| normalize_command(&evidence_json));
        let pid = evidence_value
            .as_ref()
            .and_then(|value| value.get("ProcessId"))
            .map(|value| value_to_u64(Some(value)))
            .filter(|value| *value > 0)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string());

        let pow_hint = format!("{} {}", process, command).to_lowercase();
        if !pow_hint.contains("powershell") {
            continue;
        }

        let key = format!("{}|{}|{}", timestamp, process, command);
        if !seen.insert(key) {
            continue;
        }

        view.recent_powershell.push(ExecutionEvent {
            timestamp,
            process,
            command,
            pid,
            source: "live_ps_d3".to_string(),
        });
    }

    if view.recent_powershell.is_empty() {
        view.recent_powershell = fallback_powershell_from_memory();
    }

    view.recent_powershell.sort_by(|a, b| {
        let a_unknown = a.timestamp.to_lowercase().contains("unknown");
        let b_unknown = b.timestamp.to_lowercase().contains("unknown");
        a_unknown
            .cmp(&b_unknown)
            .then_with(|| b.timestamp.cmp(&a.timestamp))
    });
    view.recent_powershell.truncate(MAX_LIST_ITEMS);
    view.powershell_events = view.recent_powershell.len() as u64;

    view
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/dashboard", get(dashboard))
}

async fn dashboard(State(state): State<Arc<AppState>>, AuthUser(user): AuthUser) -> Html<String> {
    let (
        artifact_summary,
        network_quickview,
        memory_quickview,
        ntfs_quickview,
        browser_quickview,
        execution_quickview,
        windows_event_quickview,
        malicious_process_quickview,
    ) = if let Some(seed) = load_dashboard_quickview_data() {
        (
            seed.artifact_summary,
            seed.network_quickview,
            seed.memory_quickview,
            seed.ntfs_quickview,
            seed.browser_quickview,
            seed.execution_quickview,
            seed.windows_event_quickview,
            seed.malicious_process_quickview,
        )
    } else {
        let artifact_summary = collect_artifact_summary(Path::new(FETCHED_FILES_DIR));
        let network_quickview = collect_network_quickview();
        let memory_quickview = collect_memory_quickview();
        let ntfs_quickview = collect_ntfs_quickview();
        let browser_quickview = collect_browser_quickview();
        let execution_quickview = collect_execution_quickview();
        let windows_event_quickview = collect_windows_event_quickview();
        let malicious_process_quickview = collect_malicious_process_quickview(
            &execution_quickview,
            &network_quickview,
            &windows_event_quickview,
        );

        (
            artifact_summary,
            network_quickview,
            memory_quickview,
            ntfs_quickview,
            browser_quickview,
            execution_quickview,
            windows_event_quickview,
            malicious_process_quickview,
        )
    };

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

    let resources = serde_json::json!([
        {"id":"timeline","name":"Timeline Explorer","description":"View csv exported forensic outputs","icon":"fa-solid fa-chart-line","url":"/tools/timeline/","status":"active"},
        {"id":"registry","name":"Registry","description":"Windows Registry analysis and investigation","icon":"fa-solid fa-folder-open","url":"#registry","status":"active"},
        {"id":"ntfs","name":"NTFS Data","description":"NTFS file system and metadata analysis","icon":"fa-solid fa-hdd","url":"#ntfs-section","status":"active"},
        {"id":"memory","name":"Memory Analysis","description":"Volatile memory capture & analysis","icon":"fa-solid fa-brain","url":"#memory-section","status":"active"},
        {"id":"windows-event","name":"Windows Event","description":"Windows Event Log viewer and analyzer","icon":"fa-solid fa-scroll","url":"/reports/windows-event","status":"active"},
        {"id":"shimcache-amcache-report","name":"Shimcache Amcache Report","description":"Open the latest shimcache/amcache report","icon":"fa-solid fa-clipboard-check","url":"/reports/shimcache-amcache","status":"active"},
        {"id":"prefetch-report","name":"Prefetch Report","description":"Open the latest prefetch analysis report","icon":"fa-solid fa-list-check","url":"/reports/prefetch","status":"active"},
        {"id":"timesketch","name":"Timesketch","description":"Collaborative forensic timeline analysis","icon":"fa-solid fa-clock","url":"/tools/timesketch/","status":"active"},
        {"id":"ioc-scan","name":"IOC Scan","description":"Scan results for indicators of compromise","icon":"fa-solid fa-magnifying-glass","url":"/reports/ioc-scan","status":"active"},
        {"id":"ioc-hash-scan","name":"IOC/Hash Scan","description":"Cross-check IOCs and file hashes against known indicators","icon":"fa-solid fa-fingerprint","url":"/reports/ioc-scan","status":"active"},
        {"id":"network-forensics","name":"Network Forensics","description":"Investigate network artifacts, flows, and communication patterns","icon":"fa-solid fa-network-wired","url":"#network-section","status":"active"},
        {"id":"data-theft","name":"Data Theft","description":"Review exfiltration indicators and data theft investigation findings","icon":"fa-solid fa-file-export","url":"/reports/data-theft","status":"active"},
        {"id":"browser-forensics","name":"Browser Forensics","description":"Browser history, downloads, cookies & session analysis","icon":"fa-solid fa-globe","url":"#browser-section","status":"active"},
        {"id":"fetched-files","name":"Fetched Files","description":"Browse and download files fetched from the share","icon":"fa-solid fa-file-arrow-down","url":"/fetched-files","status":"active"},
        {"id":"pe-entropy","name":"PE Entropy","description":"Analyze selected PE files from fetched files using entropy scoring","icon":"fa-solid fa-file-shield","url":"/fetched-files?tool=pe-entropy","status":"active"},
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
    ctx.insert("network_quickview", &network_quickview);
    ctx.insert("memory_quickview", &memory_quickview);
    ctx.insert("ntfs_quickview", &ntfs_quickview);
    ctx.insert("browser_quickview", &browser_quickview);
    ctx.insert("execution_quickview", &execution_quickview);
    ctx.insert("windows_event_quickview", &windows_event_quickview);
    ctx.insert("malicious_process_quickview", &malicious_process_quickview);

    template_utils::render(&state.templates, "dashboard.html", &ctx)
}
