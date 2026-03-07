use crate::models::common::{Finding, FindingCategory, Severity, parse_timestamp};
use crate::models::network_usage::NetworkUsage;
use crate::analyzers::app_analyzer::format_bytes;
use crate::rules::RuleSet;

/// Configurable thresholds for network analysis
pub struct NetworkAnalyzerConfig {
    /// Bytes sent threshold for exfiltration detection (default: 100MB)
    pub exfiltration_threshold: u64,
    /// Bytes received threshold for large download detection (default: 500MB)
    pub large_download_threshold: u64,
    /// Business hours start (default: 8)
    pub business_hours_start: u32,
    /// Business hours end (default: 18)
    pub business_hours_end: u32,
}

impl Default for NetworkAnalyzerConfig {
    fn default() -> Self {
        Self {
            exfiltration_threshold: 104_857_600,  // 100 MB
            large_download_threshold: 524_288_000, // 500 MB
            business_hours_start: 8,
            business_hours_end: 18,
        }
    }
}

/// Analyze NetworkUsages records for suspicious activity using externalized rules
pub fn analyze(records: &[NetworkUsage], config: &NetworkAnalyzerConfig, rules: Option<&RuleSet>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut finding_id = 0;

    for record in records {
        let exe_info = match &record.exe_info {
            Some(path) if !path.is_empty() => path.clone(),
            _ => continue,
        };

        let app_name = record.app_name().to_lowercase();
        let user = record.user_name.clone().or_else(|| record.user_sid.clone());
        let bytes_sent = record.bytes_sent.unwrap_or(0);
        let bytes_recvd = record.bytes_recvd.unwrap_or(0);

        // Resolve lists from RuleSet only (externalized JSON rules)
        let is_browser = rules
            .map(|r| r.browsers.iter().any(|b| app_name == b.to_lowercase()))
            .unwrap_or(false);

        let is_suspicious_app = rules
            .map(|r| r.non_browser_suspicious.iter().any(|s| app_name == s.to_lowercase()))
            .unwrap_or(false);

        let is_archive = rules
            .map(|r| r.archive_tools.iter().any(|a| app_name == a.to_lowercase()))
            .unwrap_or(false);

        // 1. Data exfiltration detection (high BytesSent)
        if bytes_sent > config.exfiltration_threshold {
            finding_id += 1;
            let severity = if bytes_sent > config.exfiltration_threshold * 5 {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(Finding {
                id: format!("NET-EXFIL-{:04}", finding_id),
                severity,
                category: FindingCategory::DataExfiltration,
                title: "Potential Data Exfiltration".to_string(),
                description: format!(
                    "Application '{}' sent {} (exceeds {} threshold)",
                    record.app_name(),
                    format_bytes(bytes_sent),
                    format_bytes(config.exfiltration_threshold),
                ),
                evidence: vec![
                    format!("Application: {}", exe_info),
                    format!("Bytes Sent: {}", format_bytes(bytes_sent)),
                    format!("Bytes Received: {}", format_bytes(bytes_recvd)),
                    format!("Interface: {}", record.interface_type.as_deref().unwrap_or("Unknown")),
                    format!("Network: {}", record.l2_profile_id.as_deref().unwrap_or("Unknown")),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_info.clone()),
                user: user.clone(),
            });
        }

        // 2. Large download detection
        if bytes_recvd > config.large_download_threshold {
            finding_id += 1;
            findings.push(Finding {
                id: format!("NET-DOWNLOAD-{:04}", finding_id),
                severity: Severity::Medium,
                category: FindingCategory::NetworkAnomaly,
                title: "Large Download Detected".to_string(),
                description: format!(
                    "Application '{}' received {} (exceeds {} threshold)",
                    record.app_name(),
                    format_bytes(bytes_recvd),
                    format_bytes(config.large_download_threshold),
                ),
                evidence: vec![
                    format!("Application: {}", exe_info),
                    format!("Bytes Received: {}", format_bytes(bytes_recvd)),
                    format!("Interface: {}", record.interface_type.as_deref().unwrap_or("Unknown")),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_info.clone()),
                user: user.clone(),
            });
        }

        // 3. Non-browser with significant network activity
        if is_suspicious_app && (bytes_sent > 1_048_576 || bytes_recvd > 1_048_576) {
            finding_id += 1;
            findings.push(Finding {
                id: format!("NET-NONBROWSER-{:04}", finding_id),
                severity: Severity::High,
                category: FindingCategory::NetworkAnomaly,
                title: "System Utility with Network Activity".to_string(),
                description: format!(
                    "System utility '{}' has significant network activity (Sent: {}, Recv: {})",
                    record.app_name(),
                    format_bytes(bytes_sent),
                    format_bytes(bytes_recvd),
                ),
                evidence: vec![
                    format!("Application: {}", exe_info),
                    format!("Bytes Sent: {}", format_bytes(bytes_sent)),
                    format!("Bytes Received: {}", format_bytes(bytes_recvd)),
                    format!("Interface: {}", record.interface_type.as_deref().unwrap_or("Unknown")),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_info.clone()),
                user: user.clone(),
            });
        }

        // 4. Archive tools with network activity (staging for exfil)
        if is_archive && bytes_sent > 1_048_576 {
            finding_id += 1;
            findings.push(Finding {
                id: format!("NET-ARCHIVE-UPLOAD-{:04}", finding_id),
                severity: Severity::High,
                category: FindingCategory::DataExfiltration,
                title: "Archive Tool with Network Upload".to_string(),
                description: format!(
                    "Archive/compression tool '{}' sent {} over the network — possible staged exfiltration",
                    record.app_name(),
                    format_bytes(bytes_sent),
                ),
                evidence: vec![
                    format!("Application: {}", exe_info),
                    format!("Bytes Sent: {}", format_bytes(bytes_sent)),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_info.clone()),
                user: user.clone(),
            });
        }

        // 5. After-hours network activity
        if let Some(ts) = record.timestamp.as_deref() {
            if let Some(dt) = parse_timestamp(ts) {
                let hour = dt.time().hour() as u32;
                if hour < config.business_hours_start || hour >= config.business_hours_end {
                    if bytes_sent > 10_485_760 || bytes_recvd > 10_485_760 {
                        finding_id += 1;
                        findings.push(Finding {
                            id: format!("NET-AFTERHOURS-{:04}", finding_id),
                            severity: Severity::Medium,
                            category: FindingCategory::NetworkAnomaly,
                            title: "After-Hours Network Activity".to_string(),
                            description: format!(
                                "Significant network activity by '{}' outside business hours ({:02}:{:02})",
                                record.app_name(),
                                dt.time().hour(),
                                dt.time().minute(),
                            ),
                            evidence: vec![
                                format!("Application: {}", exe_info),
                                format!("Time: {:02}:{:02} (outside {}-{} business hours)", dt.time().hour(), dt.time().minute(), config.business_hours_start, config.business_hours_end),
                                format!("Bytes Sent: {}", format_bytes(bytes_sent)),
                                format!("Bytes Received: {}", format_bytes(bytes_recvd)),
                                format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                            ],
                            timestamp: record.timestamp.clone(),
                            app_path: Some(exe_info.clone()),
                            user: user.clone(),
                        });
                    }
                }
            }
        }

        // 6. Unknown/unusual application with network activity from suspicious paths
        if !is_browser && !is_suspicious_app && !is_archive {
            let from_suspicious = rules
                .map(|ruleset| ruleset.is_suspicious_path(&exe_info).is_some())
                .unwrap_or(false);

            if from_suspicious && (bytes_sent > 1_048_576 || bytes_recvd > 1_048_576) {
                finding_id += 1;
                findings.push(Finding {
                    id: format!("NET-SUSPICIOUS-ORIGIN-{:04}", finding_id),
                    severity: Severity::High,
                    category: FindingCategory::NetworkAnomaly,
                    title: "Network Activity from Suspicious Location".to_string(),
                    description: format!(
                        "Application '{}' from suspicious path has network activity (Sent: {}, Recv: {})",
                        record.app_name(),
                        format_bytes(bytes_sent),
                        format_bytes(bytes_recvd),
                    ),
                    evidence: vec![
                        format!("Application: {}", exe_info),
                        format!("Bytes Sent: {}", format_bytes(bytes_sent)),
                        format!("Bytes Received: {}", format_bytes(bytes_recvd)),
                        format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                        format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                    ],
                    timestamp: record.timestamp.clone(),
                    app_path: Some(exe_info.clone()),
                    user: user.clone(),
                });
            }
        }
    }

    findings
}

use chrono::Timelike;
