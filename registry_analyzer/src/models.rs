use serde::Deserialize;
use std::fmt;

// ─────────────────────────────────────────────────────────────
// Input Models — Parsed Windows Registry in JSON
// ─────────────────────────────────────────────────────────────

/// Top-level registry dump containing one or more hives.
#[derive(Debug, Deserialize)]
pub struct RegistryDump {
    /// Optional hostname / computer name
    #[serde(default)]
    pub system_name: Option<String>,

    /// ISO-8601 date when the registry was exported
    #[serde(default)]
    pub export_date: Option<String>,

    /// Registry hives included in the dump
    pub hives: Vec<RegistryHive>,
}

/// A single registry hive (SYSTEM, SOFTWARE, NTUSER.DAT, SAM, SECURITY, …).
#[derive(Debug, Deserialize)]
pub struct RegistryHive {
    /// Hive identifier: SYSTEM, SOFTWARE, NTUSER.DAT, SAM, SECURITY, etc.
    pub name: String,

    /// Top-level keys inside this hive
    #[serde(default)]
    pub keys: Vec<RegistryKey>,
}

/// A registry key with its path, optional timestamp, values, and sub-keys.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistryKey {
    /// Registry key path relative to the hive root
    pub path: String,

    /// Last write / modification time (ISO-8601)
    #[serde(default)]
    pub last_write_time: Option<String>,

    /// Values stored under this key
    #[serde(default)]
    pub values: Vec<RegistryValue>,

    /// Optional nested sub-keys
    #[serde(default)]
    pub subkeys: Option<Vec<RegistryKey>>,
}

/// A single named value inside a registry key.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistryValue {
    /// Value name (empty string = default value)
    pub name: String,

    /// Data type: REG_SZ, REG_DWORD, REG_BINARY, etc.
    #[serde(default, rename = "type")]
    #[allow(dead_code)]
    pub value_type: Option<String>,

    /// String representation of the data
    #[serde(default)]
    pub data: String,
}

// ─────────────────────────────────────────────────────────────
// Output Models — Analysis findings and report
// ─────────────────────────────────────────────────────────────

/// Severity level for a finding, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4,
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
    pub fn css_class(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// A single evidence line displayed inside a finding card.
#[derive(Debug, Clone)]
pub struct EvidenceLine {
    pub label: String,
    pub value: String,
}

/// A forensic finding produced by the analysis engine.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub category: String,
    pub description: String,
    pub evidence: Vec<EvidenceLine>,
    pub mitre_id: Option<String>,
    pub mitre_url: Option<String>,
    pub tags: Vec<(String, String)>,
}

/// Complete analysis report ready for rendering.
#[derive(Debug)]
pub struct AnalysisReport {
    pub system_name: String,
    pub export_date: String,
    pub report_date: String,
    pub total_keys: usize,
    pub total_values: usize,
    pub total_hives: usize,
    pub findings: Vec<Finding>,
}

impl AnalysisReport {
    pub fn count_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}
