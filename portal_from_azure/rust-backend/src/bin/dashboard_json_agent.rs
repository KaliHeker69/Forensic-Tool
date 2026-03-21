use chrono::Local;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_OUTPUT: &str = "portal_from_azure/rust-backend/data/dashboard_quickview.json";

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

fn sort_label_counts(map: HashMap<String, u64>, limit: usize) -> Vec<Value> {
    let mut items: Vec<(String, u64)> = map.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
        .into_iter()
        .take(limit)
        .map(|(label, count)| json!({ "label": label, "count": count }))
        .collect()
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

fn build_memory_quickview(roots: &[PathBuf]) -> Option<Value> {
    let path = resolve_memory_source(roots)?;
    let json = read_json(&path)?;
    let summary = json.get("summary")?;

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

    Some(json!({
        "source": path.to_string_lossy().to_string(),
        "risk_level": summary.get("risk_level").and_then(Value::as_str).unwrap_or("UNKNOWN"),
        "risk_score": as_u64(summary.get("risk_score")),
        "total_findings": as_u64(summary.get("total_findings")),
        "unique_pids": as_u64(summary.get("unique_pids")),
        "unique_ips": as_u64(summary.get("unique_ips")),
        "severity_segments": severity_segments,
        "top_categories": sort_label_counts(category_counts, 6),
        "analysis_metadata": json.get("metadata").cloned().unwrap_or(Value::Null),
        "suspicious_processes": json.get("suspicious_processes").cloned().unwrap_or(Value::Null),
        "correlated_artifacts": json.get("correlated_artifacts").cloned().unwrap_or(Value::Null),
    }))
}

fn build_browser_quickview(roots: &[PathBuf]) -> Option<Value> {
    let path = resolve_existing_path("browser_forensics/report.json", roots)?;
    let json = read_json(&path)?;
    let summary = json.get("summary")?;

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
                b.get("browser")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(a.get("browser").and_then(Value::as_str).unwrap_or(""))
            })
    });
    recent_history.truncate(8);

    Some(json!({
        "source": path.to_string_lossy().to_string(),
        "total_browsers": as_u64(summary.get("total_browsers")),
        "total_history_entries": as_u64(summary.get("total_history_entries")),
        "total_downloads": as_u64(summary.get("total_downloads")),
        "total_cookies": as_u64(summary.get("total_cookies")),
        "total_sessions": as_u64(summary.get("total_sessions")),
        "browsers_found": summary.get("browsers_found").cloned().unwrap_or_else(|| json!([])),
        "top_domains": sort_label_counts(domain_counts, 6),
        "recent_history": recent_history,
        "report_generated": json.get("report_generated").cloned().unwrap_or(Value::Null),
        "tool_version": json.get("tool_version").cloned().unwrap_or(Value::Null),
    }))
}

fn load_base_dashboard_payload(roots: &[PathBuf]) -> Value {
    resolve_existing_path(DEFAULT_OUTPUT, roots)
        .and_then(|path| read_json(&path))
        .unwrap_or_else(|| {
            json!({
                "artifact_summary": {
                    "total_files": 0,
                    "total_folders": 0,
                    "total_size_bytes": 0,
                    "total_size_human": "0 B",
                    "avg_file_size_human": "0 B",
                    "largest_file_name": "N/A",
                    "largest_file_size_human": "0 B",
                    "dominant_extension": "N/A",
                    "dominant_extension_count": 0,
                    "scanned_at": "Never",
                    "top_types": []
                },
                "network_quickview": {
                    "source": "",
                    "total_connections": 0,
                    "established_connections": 0,
                    "external_established_connections": 0,
                    "listening_ports": 0,
                    "active_connections": [],
                    "top_remote_hosts": []
                },
                "memory_quickview": {
                    "source": "",
                    "risk_level": "UNKNOWN",
                    "risk_score": 0,
                    "total_findings": 0,
                    "unique_pids": 0,
                    "unique_ips": 0,
                    "severity_segments": [],
                    "top_categories": []
                },
                "ntfs_quickview": {
                    "source": "",
                    "total_entries": 0,
                    "active_entries": 0,
                    "files": 0,
                    "directories": 0,
                    "ads_entries": 0,
                    "total_file_size_human": "0 B",
                    "top_extensions": []
                },
                "browser_quickview": {
                    "source": "",
                    "total_browsers": 0,
                    "total_history_entries": 0,
                    "total_downloads": 0,
                    "total_cookies": 0,
                    "total_sessions": 0,
                    "browsers_found": [],
                    "top_domains": [],
                    "recent_history": []
                },
                "execution_quickview": {
                    "source": "",
                    "powershell_events": 0,
                    "recent_powershell": []
                },
                "windows_event_quickview": {
                    "source": "",
                    "title": "Windows Event Log Alert",
                    "timestamp": "Unknown",
                    "event_id": "N/A",
                    "host": "Unknown",
                    "summary": "",
                    "priority": "MONITOR",
                    "count": 0,
                    "source_label": "windows-event",
                    "category": "EVENT_LOG"
                },
                "malicious_process_quickview": {
                    "source": "",
                    "has_malicious": false,
                    "suspicious_count": 0,
                    "suspicious_executables": [],
                    "execution_timeline": [],
                    "tree_nodes": [],
                    "tree_links": [],
                    "summary": ""
                }
            })
        })
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
                println!("Usage: dashboard_json_agent [--root PATH] [--output PATH]");
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
            env::var("DASHBOARD_QUICKVIEW_OUTPUT")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT));

    let mut dashboard = load_base_dashboard_payload(&workspace_roots);
    let generated_at = Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

    if let Some(memory) = build_memory_quickview(&workspace_roots) {
        dashboard["memory_quickview"] = memory;
    }

    if let Some(browser) = build_browser_quickview(&workspace_roots) {
        dashboard["browser_quickview"] = browser;
    }

    dashboard["analysis_metadata"] = json!({
        "generated_by": "dashboard_json_agent",
        "generated_at": generated_at,
        "output_path": output_path.to_string_lossy().to_string(),
        "modules_processed": ["memory", "browser"],
    });

    if let Err(err) = write_json(&output_path, &dashboard) {
        eprintln!(
            "Failed to write dashboard payload to {}: {err}",
            output_path.display()
        );
        std::process::exit(1);
    }

    println!("Wrote dashboard payload to {}", output_path.display());
}
