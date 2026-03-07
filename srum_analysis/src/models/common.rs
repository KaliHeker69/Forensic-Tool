use serde::{Deserialize, Serialize};
use chrono::NaiveDateTime;
use std::fmt;

/// Deserialize optional u64 values from SrumECmd CSV fields.
///
/// Handles common export quirks:
/// - empty string => None
/// - sentinel negative values (e.g. -1) => None
/// - valid positive integers => Some(value)
pub fn de_opt_u64_srum<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    let value = match raw {
        Some(v) => v.trim().to_string(),
        None => return Ok(None),
    };

    if value.is_empty() {
        return Ok(None);
    }

    if let Ok(parsed_i64) = value.parse::<i64>() {
        if parsed_i64 < 0 {
            return Ok(None);
        }
        return Ok(Some(parsed_i64 as u64));
    }

    if let Ok(parsed_u64) = value.parse::<u64>() {
        return Ok(Some(parsed_u64));
    }

    Err(serde::de::Error::custom(format!(
        "invalid integer value '{}': expected empty, non-negative integer, or -1 sentinel",
        value
    )))
}

/// Severity levels for forensic findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    pub fn color_class(&self) -> &str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// Categories for forensic findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingCategory {
    SuspiciousExecution,
    DataExfiltration,
    LateralMovement,
    CredentialTheft,
    AntiForensics,
    Ransomware,
    CryptoMining,
    CommandAndControl,
    AnomalousActivity,
    LOLBin,
    NetworkAnomaly,
    ConnectionAnomaly,
    CrossTableCorrelation,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::SuspiciousExecution => write!(f, "Suspicious Execution"),
            FindingCategory::DataExfiltration => write!(f, "Data Exfiltration"),
            FindingCategory::LateralMovement => write!(f, "Lateral Movement"),
            FindingCategory::CredentialTheft => write!(f, "Credential Theft"),
            FindingCategory::AntiForensics => write!(f, "Anti-Forensics"),
            FindingCategory::Ransomware => write!(f, "Ransomware"),
            FindingCategory::CryptoMining => write!(f, "Crypto Mining"),
            FindingCategory::CommandAndControl => write!(f, "Command & Control"),
            FindingCategory::AnomalousActivity => write!(f, "Anomalous Activity"),
            FindingCategory::LOLBin => write!(f, "Living off the Land"),
            FindingCategory::NetworkAnomaly => write!(f, "Network Anomaly"),
            FindingCategory::ConnectionAnomaly => write!(f, "Connection Anomaly"),
            FindingCategory::CrossTableCorrelation => write!(f, "Cross-Table Correlation"),
        }
    }
}

/// A single forensic finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: Option<String>,
    pub app_path: Option<String>,
    pub user: Option<String>,
}

/// A single event in the unified timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub source_table: String,
    pub application: Option<String>,
    pub user: Option<String>,
    pub details: String,
}

/// Statistics summary per application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatistics {
    pub app_path: String,
    pub user: Option<String>,
    pub total_foreground_bytes_read: u64,
    pub total_foreground_bytes_written: u64,
    pub total_background_bytes_read: u64,
    pub total_background_bytes_written: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub record_count: u64,
}

/// Summary counts by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl FindingSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = findings.iter().filter(|f| f.severity == Severity::Info).count();
        Self {
            critical,
            high,
            medium,
            low,
            info,
            total: findings.len(),
        }
    }
}

/// Top-level analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub metadata: ReportMetadata,
    pub summary: FindingSummary,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub app_statistics: Vec<AppStatistics>,
    pub anomalies: Vec<Finding>,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub tool_name: String,
    pub tool_version: String,
    pub analysis_time: String,
    pub input_directory: String,
    pub files_parsed: Vec<String>,
    pub total_records: usize,
    pub data_time_range: Option<(String, String)>,
}

/// Parsed timestamp helper
pub fn parse_timestamp(ts: &str) -> Option<NaiveDateTime> {
    // SrumECmd outputs timestamps in various formats
    let formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ];

    for fmt in &formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(ts.trim(), fmt) {
            return Some(dt);
        }
    }
    None
}
