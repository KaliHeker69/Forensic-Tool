use crate::models::common::{Finding, FindingCategory, Severity};
use crate::models::app_resource::AppResourceUsage;
use crate::models::network_usage::NetworkUsage;
use crate::analyzers::app_analyzer::format_bytes;

/// Detect statistical anomalies in SRUM data
pub fn detect_anomalies(
    app_records: &[AppResourceUsage],
    net_records: &[NetworkUsage],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Anomaly detection on AppResourceUsage: bytes written
    let app_write_anomalies = detect_numeric_anomalies(
        app_records,
        |r| r.total_bytes_written(),
        |r| r.exe_info.clone().unwrap_or_default(),
        |r| r.timestamp.clone(),
        |r| r.user_name.clone().or_else(|| r.user_sid.clone()),
        "ForegroundBytesWritten",
        "AppResourceUsage",
        FindingCategory::AnomalousActivity,
    );
    findings.extend(app_write_anomalies);

    // Anomaly detection on AppResourceUsage: bytes read
    let app_read_anomalies = detect_numeric_anomalies(
        app_records,
        |r| r.total_bytes_read(),
        |r| r.exe_info.clone().unwrap_or_default(),
        |r| r.timestamp.clone(),
        |r| r.user_name.clone().or_else(|| r.user_sid.clone()),
        "ForegroundBytesRead",
        "AppResourceUsage",
        FindingCategory::AnomalousActivity,
    );
    findings.extend(app_read_anomalies);

    // Anomaly detection on AppResourceUsage: CPU cycle time
    let cpu_anomalies = detect_numeric_anomalies(
        app_records,
        |r| r.total_cycle_time(),
        |r| r.exe_info.clone().unwrap_or_default(),
        |r| r.timestamp.clone(),
        |r| r.user_name.clone().or_else(|| r.user_sid.clone()),
        "TotalCycleTime",
        "AppResourceUsage",
        FindingCategory::AnomalousActivity,
    );
    findings.extend(cpu_anomalies);

    // Anomaly detection on NetworkUsages: bytes sent
    let net_sent_anomalies = detect_numeric_anomalies(
        net_records,
        |r| r.bytes_sent.unwrap_or(0),
        |r| r.exe_info.clone().unwrap_or_default(),
        |r| r.timestamp.clone(),
        |r| r.user_name.clone().or_else(|| r.user_sid.clone()),
        "BytesSent",
        "NetworkUsages",
        FindingCategory::AnomalousActivity,
    );
    findings.extend(net_sent_anomalies);

    // Anomaly detection on NetworkUsages: bytes received
    let net_recv_anomalies = detect_numeric_anomalies(
        net_records,
        |r| r.bytes_recvd.unwrap_or(0),
        |r| r.exe_info.clone().unwrap_or_default(),
        |r| r.timestamp.clone(),
        |r| r.user_name.clone().or_else(|| r.user_sid.clone()),
        "BytesRecvd",
        "NetworkUsages",
        FindingCategory::AnomalousActivity,
    );
    findings.extend(net_recv_anomalies);

    findings
}

/// Generic anomaly detection using z-score (values > 2 standard deviations from mean)
fn detect_numeric_anomalies<T>(
    records: &[T],
    value_fn: impl Fn(&T) -> u64,
    name_fn: impl Fn(&T) -> String,
    ts_fn: impl Fn(&T) -> Option<String>,
    user_fn: impl Fn(&T) -> Option<String>,
    metric_name: &str,
    source_table: &str,
    category: FindingCategory,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Filter out zero values for statistics
    let values: Vec<u64> = records.iter().map(&value_fn).filter(|v| *v > 0).collect();

    if values.len() < 5 {
        return findings; // Not enough data for meaningful statistics
    }

    let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
    let variance = values.iter().map(|v| {
        let diff = *v as f64 - mean;
        diff * diff
    }).sum::<f64>() / values.len() as f64;
    let std_dev = variance.sqrt();

    if std_dev == 0.0 {
        return findings; // All values are the same
    }

    let threshold = mean + 2.0 * std_dev;
    let mut finding_id = 0;

    for record in records {
        let value = value_fn(record);
        if value as f64 > threshold && value > 0 {
            let z_score = (value as f64 - mean) / std_dev;
            finding_id += 1;

            let severity = if z_score > 4.0 {
                Severity::High
            } else if z_score > 3.0 {
                Severity::Medium
            } else {
                Severity::Low
            };

            findings.push(Finding {
                id: format!("ANOMALY-{}-{}-{:04}", source_table.to_uppercase(), metric_name.to_uppercase(), finding_id),
                severity,
                category: category.clone(),
                title: format!("Statistical Anomaly: {} in {}", metric_name, source_table),
                description: format!(
                    "Application '{}' has anomalous {} value: {} (z-score: {:.2}, mean: {}, stddev: {})",
                    name_fn(record).rsplit(&['\\', '/']).next().unwrap_or("Unknown"),
                    metric_name,
                    format_bytes(value),
                    z_score,
                    format_bytes(mean as u64),
                    format_bytes(std_dev as u64),
                ),
                evidence: vec![
                    format!("Application: {}", name_fn(record)),
                    format!("{}: {}", metric_name, format_bytes(value)),
                    format!("Z-Score: {:.2}", z_score),
                    format!("Mean: {}", format_bytes(mean as u64)),
                    format!("Std Dev: {}", format_bytes(std_dev as u64)),
                    format!("Threshold (2σ): {}", format_bytes(threshold as u64)),
                    format!("Timestamp: {}", ts_fn(record).as_deref().unwrap_or("N/A")),
                    format!("User: {}", user_fn(record).as_deref().unwrap_or("Unknown")),
                ],
                timestamp: ts_fn(record),
                app_path: Some(name_fn(record)),
                user: user_fn(record),
            });
        }
    }

    // Sort by severity (most severe first), limit to top 20
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings.truncate(20);

    findings
}
