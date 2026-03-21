use chrono::Local;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DEFAULT_OUTPUT: &str = "portal_from_azure/rust-backend/data/dashboard_quick_view.json";
const WINDOWS_EVENT_REPORT_HTML_ENV: &str = "WINDOWS_EVENT_REPORT_HTML";
const FETCHED_FILES_DIR: &str = "/srv/forensics/fetched_files";

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
        _ => 0,
    }
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
    resolve_existing_path("memory_corelation/reports/analysis.json", roots)
        .or_else(|| resolve_existing_path("memory_corelation/analysis.json", roots))
        .or_else(|| {
            resolve_existing_path(
                "portal_from_azure/rust-backend/data/memory_analysis.json",
                roots,
            )
        })
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
    let Some(path) = resolve_existing_path("browser_forensics/report.json", roots) else {
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
    let Some(path) =
        resolve_existing_path("srum_analysis/reports/srum_analysis_report.json", roots)
    else {
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
    let Some(path) = resolve_existing_path("ntfs_analyzer/output/mft.json", roots) else {
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
    let Some(report_path) = resolve_existing_path(
        "network_forensics/output/live_ps_all_v1/forensic_report.json",
        roots,
    )
    .or_else(|| resolve_existing_path("network_forensics/output/forensic_report.json", roots)) else {
        return default_network_quickview(String::new());
    };

    let Some(events_path) = resolve_existing_path(
        "network_forensics/output/live_ps_all_v1/forensic_events.csv",
        roots,
    )
    .or_else(|| resolve_existing_path("network_forensics/output/forensic_events.csv", roots)) else {
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

fn parse_args() -> (Option<PathBuf>, Option<PathBuf>) {
    let mut output = None;
    let mut root = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                if let Some(value) = args.next() {
                    output = Some(PathBuf::from(value));
                }
            }
            "--root" => {
                if let Some(value) = args.next() {
                    root = Some(PathBuf::from(value));
                }
            }
            "--help" | "-h" => {
                println!("Usage: dashboard_setter [--root PATH] [--output PATH]");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    (root, output)
}

fn main() {
    let (root_override, output_override) = parse_args();
    let workspace_roots = workspace_roots(root_override);

    let output_path = output_override
        .or_else(|| {
            env::var("DASHBOARD_QUICK_VIEW_OUTPUT")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT));

    let network_quickview = build_network_quickview(&workspace_roots);
    let memory_quickview = build_memory_quickview(&workspace_roots);
    let ntfs_quickview = build_ntfs_quickview(&workspace_roots);
    let browser_quickview = build_browser_quickview(&workspace_roots);
    let windows_event_quickview = build_windows_event_quickview(&workspace_roots);
    let srum_quickview = build_srum_quickview(&workspace_roots);
    let generated_at = Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

    let payload = json!({
        "analysis_metadata": {
            "generated_by": "dashboard_setter",
            "generated_at": generated_at,
            "output_path": output_path.to_string_lossy().to_string(),
            "modules_processed": ["network", "memory", "ntfs", "browser", "windows-event", "srum"],
        },
        "network_quickview": network_quickview,
        "memory_quickview": memory_quickview,
        "ntfs_quickview": ntfs_quickview,
        "browser_quickview": browser_quickview,
        "windows_event_quickview": windows_event_quickview,
        "srum_quickview": srum_quickview,
    });

    if let Err(err) = write_json(&output_path, &payload) {
        eprintln!(
            "Failed to write dashboard payload to {}: {err}",
            output_path.display()
        );
        std::process::exit(1);
    }

    println!("Wrote dashboard payload to {}", output_path.display());
}
