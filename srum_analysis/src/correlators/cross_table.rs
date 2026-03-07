use crate::models::common::{Finding, FindingCategory, Severity, parse_timestamp};
use crate::models::app_resource::AppResourceUsage;
use crate::models::network_usage::NetworkUsage;
use crate::analyzers::app_analyzer::format_bytes;

/// Cross-table correlation window (in seconds) - ±1 hour to account for SRUM granularity
const CORRELATION_WINDOW_SECS: i64 = 3600;

/// Perform cross-table correlations between AppResourceUsage and NetworkUsages
pub fn correlate(
    app_records: &[AppResourceUsage],
    net_records: &[NetworkUsage],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut finding_id = 0;

    // Pre-parse timestamps for efficiency
    let app_parsed: Vec<(&AppResourceUsage, Option<chrono::NaiveDateTime>)> = app_records
        .iter()
        .map(|r| (r, r.timestamp.as_deref().and_then(parse_timestamp)))
        .collect();

    let net_parsed: Vec<(&NetworkUsage, Option<chrono::NaiveDateTime>)> = net_records
        .iter()
        .map(|r| (r, r.timestamp.as_deref().and_then(parse_timestamp)))
        .collect();

    // Build a set of first-seen timestamps per app (for "new app" detection)
    let mut first_seen: std::collections::HashMap<String, chrono::NaiveDateTime> = std::collections::HashMap::new();
    for (record, ts) in &app_parsed {
        if let (Some(ref path), Some(dt)) = (&record.exe_info, ts) {
            let key = path.to_lowercase();
            first_seen
                .entry(key)
                .and_modify(|existing| {
                    if dt < existing {
                        *existing = *dt;
                    }
                })
                .or_insert(*dt);
        }
    }

    for (app_record, app_ts) in &app_parsed {
        let app_ts = match app_ts {
            Some(ts) => ts,
            None => continue,
        };

        let app_path = match &app_record.exe_info {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };

        let app_name_lower = app_record.app_name().to_lowercase();
        let user = app_record.user_name.clone().or_else(|| app_record.user_sid.clone());

        // Find correlated network records (same app, within time window)
        let correlated_net: Vec<&NetworkUsage> = net_parsed
            .iter()
            .filter(|(net_record, net_ts)| {
                if let (Some(ref net_path), Some(net_dt)) = (&net_record.exe_info, net_ts) {
                    let same_app = net_path.to_lowercase() == app_path.to_lowercase()
                        || net_record.app_name().to_lowercase() == app_name_lower;
                    let within_window = (app_ts.and_utc().timestamp() - net_dt.and_utc().timestamp()).abs() <= CORRELATION_WINDOW_SECS;
                    same_app && within_window
                } else {
                    false
                }
            })
            .map(|(r, _)| *r)
            .collect();

        if correlated_net.is_empty() {
            continue;
        }

        let total_sent: u64 = correlated_net.iter().map(|n| n.bytes_sent.unwrap_or(0)).sum();
        let total_recv: u64 = correlated_net.iter().map(|n| n.bytes_recvd.unwrap_or(0)).sum();

        // Correlation 1: Execution + Network Activity
        if total_sent > 1_048_576 || total_recv > 1_048_576 {
            // > 1MB
            finding_id += 1;
            findings.push(Finding {
                id: format!("CORR-EXEC-NET-{:04}", finding_id),
                severity: Severity::Medium,
                category: FindingCategory::CrossTableCorrelation,
                title: "Execution with Network Activity".to_string(),
                description: format!(
                    "Application '{}' was executed AND transferred data within the same time window (Sent: {}, Recv: {})",
                    app_record.app_name(),
                    format_bytes(total_sent),
                    format_bytes(total_recv),
                ),
                evidence: vec![
                    format!("Application: {}", app_path),
                    format!("Execution Time: {}", app_record.timestamp.as_deref().unwrap_or("N/A")),
                    format!("Network Sent: {}", format_bytes(total_sent)),
                    format!("Network Received: {}", format_bytes(total_recv)),
                    format!("Bytes Written (Disk): {}", format_bytes(app_record.total_bytes_written())),
                    format!("Correlated Network Records: {}", correlated_net.len()),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                ],
                timestamp: app_record.timestamp.clone(),
                app_path: Some(app_path.clone()),
                user: user.clone(),
            });
        }

        // Correlation 2: Short execution + large transfer (quick exfil)
        let cycle_time = app_record.total_cycle_time();
        if cycle_time > 0 && cycle_time < 1_000_000_000 && total_sent > 52_428_800 {
            // Short CPU + > 50MB sent
            finding_id += 1;
            findings.push(Finding {
                id: format!("CORR-QUICK-EXFIL-{:04}", finding_id),
                severity: Severity::Critical,
                category: FindingCategory::CrossTableCorrelation,
                title: "Quick Execution with Large Data Transfer".to_string(),
                description: format!(
                    "Application '{}' had short execution time but sent {} — possible rapid exfiltration",
                    app_record.app_name(),
                    format_bytes(total_sent),
                ),
                evidence: vec![
                    format!("Application: {}", app_path),
                    format!("CPU Cycle Time: {}", cycle_time),
                    format!("Data Sent: {}", format_bytes(total_sent)),
                    format!("Execution Time: {}", app_record.timestamp.as_deref().unwrap_or("N/A")),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                ],
                timestamp: app_record.timestamp.clone(),
                app_path: Some(app_path.clone()),
                user: user.clone(),
            });
        }

        // Correlation 3: First-ever execution + immediate network
        let app_key = app_path.to_lowercase();
        if let Some(first_ts) = first_seen.get(&app_key) {
            let is_first_run = (app_ts.and_utc().timestamp() - first_ts.and_utc().timestamp()).abs() < 3600;
            if is_first_run && (total_sent > 1_048_576 || total_recv > 1_048_576) {
                finding_id += 1;
                findings.push(Finding {
                    id: format!("CORR-FIRSTRUN-NET-{:04}", finding_id),
                    severity: Severity::High,
                    category: FindingCategory::CrossTableCorrelation,
                    title: "First Execution with Immediate Network Activity".to_string(),
                    description: format!(
                        "Application '{}' appears to be executed for the first time and immediately made network connections (Sent: {}, Recv: {})",
                        app_record.app_name(),
                        format_bytes(total_sent),
                        format_bytes(total_recv),
                    ),
                    evidence: vec![
                        format!("Application: {}", app_path),
                        format!("First Seen: {}", first_ts),
                        format!("Network Sent: {}", format_bytes(total_sent)),
                        format!("Network Received: {}", format_bytes(total_recv)),
                        format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    ],
                    timestamp: app_record.timestamp.clone(),
                    app_path: Some(app_path.clone()),
                    user: user.clone(),
                });
            }
        }

        // Correlation 4: High disk write + network upload (staging → exfil)
        if app_record.total_bytes_written() > 104_857_600 && total_sent > 52_428_800 {
            // >100MB written + >50MB sent
            finding_id += 1;
            findings.push(Finding {
                id: format!("CORR-STAGE-EXFIL-{:04}", finding_id),
                severity: Severity::Critical,
                category: FindingCategory::CrossTableCorrelation,
                title: "Data Staging with Network Upload".to_string(),
                description: format!(
                    "Application '{}' wrote {} to disk AND sent {} over network — potential data staging and exfiltration",
                    app_record.app_name(),
                    format_bytes(app_record.total_bytes_written()),
                    format_bytes(total_sent),
                ),
                evidence: vec![
                    format!("Application: {}", app_path),
                    format!("Disk Written: {}", format_bytes(app_record.total_bytes_written())),
                    format!("Network Sent: {}", format_bytes(total_sent)),
                    format!("Timestamp: {}", app_record.timestamp.as_deref().unwrap_or("N/A")),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                ],
                timestamp: app_record.timestamp.clone(),
                app_path: Some(app_path.clone()),
                user: user.clone(),
            });
        }
    }

    // Deduplicate findings by app_path + title combination
    findings.sort_by(|a, b| {
        let key_a = format!("{:?}{}", a.app_path, a.title);
        let key_b = format!("{:?}{}", b.app_path, b.title);
        key_a.cmp(&key_b)
    });
    findings.dedup_by(|a, b| {
        a.app_path == b.app_path && a.title == b.title
    });

    findings
}
