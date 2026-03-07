//! vol3-correlate - Volatility3 Output Correlation & Analysis Tool
//!
//! This library provides functionality to parse, correlate, and analyze
//! outputs from Volatility3 memory forensics plugins.

pub mod config;
pub mod correlation;
pub mod detection;
pub mod error;
pub mod models;
pub mod output;
pub mod parsers;
pub mod pipeline;
pub mod scoring;
pub mod threat_intel;

pub use error::{Result, Vol3Error};
pub use threat_intel::{ThreatIntelConfig, ThreatIntelResult, ThreatIntelService};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Finding category for grouping related findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    #[default]
    Process,
    Network,
    Dll,
    Service,
    Registry,
    Injection,
    Credential,
    Persistence,
    Rootkit,
    Chain,
    Thread,
    Privilege,
    Certificate,
    Filesystem,
    Integrity,
    Other,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::Process => write!(f, "Process"),
            FindingCategory::Network => write!(f, "Network"),
            FindingCategory::Dll => write!(f, "DLL"),
            FindingCategory::Service => write!(f, "Service"),
            FindingCategory::Registry => write!(f, "Registry"),
            FindingCategory::Injection => write!(f, "Injection"),
            FindingCategory::Credential => write!(f, "Credential"),
            FindingCategory::Persistence => write!(f, "Persistence"),
            FindingCategory::Rootkit => write!(f, "Rootkit"),
            FindingCategory::Chain => write!(f, "Attack Chain"),
            FindingCategory::Thread => write!(f, "Thread"),
            FindingCategory::Privilege => write!(f, "Privilege"),
            FindingCategory::Certificate => write!(f, "Certificate"),
            FindingCategory::Filesystem => write!(f, "Filesystem"),
            FindingCategory::Integrity => write!(f, "Integrity"),
            FindingCategory::Other => write!(f, "Other"),
        }
    }
}

/// A forensic finding from the analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub mitre_attack: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub related_pids: Vec<u32>,
    pub related_ips: Vec<String>,
    pub related_files: Vec<String>,
    pub confidence: f32,
    /// Threat intelligence data (if available)
    pub threat_intel: Option<ThreatIntelData>,
}

/// Threat intelligence data from external sources
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelData {
    /// AbuseIPDB confidence score (0-100)
    pub abuseipdb_score: Option<u32>,
    /// AbuseIPDB country code
    pub abuseipdb_country: Option<String>,
    /// AbuseIPDB ISP
    pub abuseipdb_isp: Option<String>,
    /// AbuseIPDB total reports
    pub abuseipdb_reports: Option<u32>,
    /// VirusTotal detection ratio (e.g., "5/70")
    pub virustotal_detections: Option<String>,
    /// VirusTotal scan date
    pub virustotal_scan_date: Option<String>,
    /// urlscan.io verdict
    pub urlscan_verdict: Option<String>,
    /// urlscan.io malicious score (0-100)
    pub urlscan_score: Option<u32>,
    /// urlscan.io scan result URL
    pub urlscan_result_url: Option<String>,
    /// Whether the IP/URL is known malicious
    pub is_malicious: bool,
    /// Lookup status message
    pub lookup_status: String,
}

/// Evidence supporting a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source_plugin: String,
    pub source_file: String,
    pub line_number: Option<usize>,
    pub data: String,
}

/// Analysis configuration options
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Time window in seconds for temporal correlation
    pub time_window_secs: i64,
    /// Minimum severity to report
    pub min_severity: Severity,
    /// Enable verbose output
    pub verbose: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            time_window_secs: 5,
            min_severity: Severity::Low,
            verbose: false,
        }
    }
}
