use serde::{Deserialize, Serialize};
use std::fmt;
use std::collections::HashMap;

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
    /// Key name (present in per-hive JSON format)
    #[serde(default)]
    pub name: Option<String>,

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
#[derive(Debug, Deserialize, Clone, Serialize)]
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
// Per-Hive JSON Format (output by the registry parser)
// ─────────────────────────────────────────────────────────────

/// Top-level structure of a per-hive JSON file.
#[derive(Debug, Deserialize)]
pub struct PerHiveFile {
    /// Hive identifier: SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, etc.
    pub hive_name: String,

    /// Original path to the hive file on disk
    #[serde(default)]
    pub hive_path: Option<String>,

    /// Size of the hive file in bytes
    #[serde(default)]
    pub hive_size_bytes: Option<u64>,

    /// ISO-8601 timestamp when the hive was parsed
    #[serde(default)]
    pub parsed_at: Option<String>,

    /// Total number of keys in the hive
    #[serde(default)]
    pub total_keys: Option<usize>,

    /// Root key containing the full tree
    pub root: RegistryKey,
}

impl PerHiveFile {
    /// Flatten the tree-based root into a flat list of RegistryKey entries
    /// and convert to the internal RegistryHive model.
    pub fn into_registry_hive(self) -> RegistryHive {
        let mut flat_keys: Vec<RegistryKey> = Vec::new();
        flatten_tree(&self.root, &mut flat_keys);
        RegistryHive {
            name: self.hive_name,
            keys: flat_keys,
        }
    }
}

/// Strip the "ROOT\\" prefix from paths produced by the per-hive parser,
/// so they match the patterns the analyzer expects (e.g. "ControlSet001\\Services\\...").
fn normalize_path(path: &str) -> String {
    if path.eq_ignore_ascii_case("ROOT") {
        return String::new();
    }
    // Strip leading "ROOT\\" (case-insensitive)
    if path.len() > 5 && path[..5].eq_ignore_ascii_case("ROOT\\") {
        return path[5..].to_string();
    }
    path.to_string()
}

/// Recursively walk the key tree and collect every key into a flat Vec.
fn flatten_tree(key: &RegistryKey, out: &mut Vec<RegistryKey>) {
    let normalized = normalize_path(&key.path);
    // Push a clone of this key with normalized path (no subkeys, to avoid redundant nesting)
    out.push(RegistryKey {
        name: key.name.clone(),
        path: normalized,
        last_write_time: key.last_write_time.clone(),
        values: key.values.clone(),
        subkeys: None, // flattened — no nested subkeys
    });
    if let Some(ref subs) = key.subkeys {
        for sub in subs {
            flatten_tree(sub, out);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Output Models — Analysis findings and report
// ─────────────────────────────────────────────────────────────

/// Severity level for a finding, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceLine {
    pub label: String,
    pub value: String,
}

/// A forensic finding produced by the analysis engine.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub category: String,
    pub description: String,
    pub evidence: Vec<EvidenceLine>,
    pub key_values: Vec<RegistryValue>,
    pub mitre_id: Option<String>,
    pub mitre_url: Option<String>,
    pub tags: Vec<(String, String)>,
}

/// Per-hive statistics for the report.
#[derive(Debug, Clone, Serialize)]
pub struct HiveStat {
    pub name: String,
    pub key_count: usize,
    pub finding_count: usize,
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
    pub hive_stats: Vec<HiveStat>,
    pub findings: Vec<Finding>,
}

impl AnalysisReport {
    pub fn count_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

// ─────────────────────────────────────────────────────────────
// JSON Report Output
// ─────────────────────────────────────────────────────────────

/// Serializable JSON report structure.
#[derive(Serialize)]
pub struct JsonReport {
    pub meta: JsonMeta,
    pub summary: JsonSummary,
    pub hive_stats: Vec<HiveStat>,
    pub findings: Vec<Finding>,
}

#[derive(Serialize)]
pub struct JsonMeta {
    pub system_name: String,
    pub export_date: String,
    pub report_date: String,
    pub total_keys: usize,
    pub total_values: usize,
    pub total_hives: usize,
}

#[derive(Serialize)]
pub struct JsonSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub categories: HashMap<String, usize>,
}

/// Generate a structured JSON string from the analysis report.
pub fn generate_json(report: &AnalysisReport) -> String {
    let mut categories: HashMap<String, usize> = HashMap::new();
    for f in &report.findings {
        *categories.entry(f.category.clone()).or_insert(0) += 1;
    }

    let json_report = JsonReport {
        meta: JsonMeta {
            system_name: report.system_name.clone(),
            export_date: report.export_date.clone(),
            report_date: report.report_date.clone(),
            total_keys: report.total_keys,
            total_values: report.total_values,
            total_hives: report.total_hives,
        },
        summary: JsonSummary {
            total: report.findings.len(),
            critical: report.count_severity(Severity::Critical),
            high: report.count_severity(Severity::High),
            medium: report.count_severity(Severity::Medium),
            low: report.count_severity(Severity::Low),
            info: report.count_severity(Severity::Info),
            categories,
        },
        hive_stats: report.hive_stats.clone(),
        findings: report.findings.clone(),
    };

    serde_json::to_string_pretty(&json_report).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize: {}\"}}", e)
    })
}
