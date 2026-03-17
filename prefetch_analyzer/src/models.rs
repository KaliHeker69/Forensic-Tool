//! Windows Prefetch Analyzer - Data Models
//!
//! Structures for parsing PECmd JSON output and storing analysis results.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Represents a single prefetch entry from PECmd JSON output
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrefetchEntry {
    /// Source prefetch file path
    #[serde(rename = "SourceFilename")]
    pub filename: String,

    #[serde(rename = "SourceCreated")]
    pub source_created: String,

    #[serde(rename = "SourceModified")]
    pub source_modified: String,

    #[serde(rename = "SourceAccessed")]
    pub source_accessed: String,

    /// Name of the executed program
    #[serde(rename = "ExecutableName")]
    pub executable_name: String,

    #[serde(rename = "Hash")]
    pub hash: String,

    #[serde(rename = "Size")]
    pub size: String,

    #[serde(rename = "RunCount")]
    pub run_count_raw: String,

    #[serde(rename = "LastRun")]
    pub last_run_raw: String,

    #[serde(rename = "Volume0Name")]
    pub volume0_name: String,

    #[serde(rename = "Volume0Serial")]
    pub volume0_serial: String,

    #[serde(rename = "Volume0Created")]
    pub volume0_created: String,

    #[serde(rename = "Directories")]
    pub directories: String,

    #[serde(rename = "FilesLoaded")]
    pub files_loaded: String,

    #[serde(rename = "ParsingError")]
    pub parsing_error: bool,

    /// Captures optional fields such as PreviousRun0..N from PECmd.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl PrefetchEntry {
    fn parse_dt(ts: &str) -> Option<NaiveDateTime> {
        NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
            .or_else(|_| NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S%.f"))
            .ok()
    }

    /// Get all run times as sorted DateTime values
    pub fn get_run_times(&self) -> Vec<NaiveDateTime> {
        let mut times: Vec<NaiveDateTime> = Vec::new();

        if let Some(ts) = Self::parse_dt(&self.last_run_raw) {
            times.push(ts);
        }

        for (k, v) in &self.extra {
            if k.starts_with("PreviousRun") {
                if let Some(raw) = v.as_str() {
                    if let Some(ts) = Self::parse_dt(raw) {
                        times.push(ts);
                    }
                }
            }
        }

        times.sort();
        times
    }

    /// Get the most recent run time
    pub fn last_run(&self) -> Option<NaiveDateTime> {
        self.get_run_times().into_iter().last()
    }

    /// Get the earliest run time
    pub fn first_run(&self) -> Option<NaiveDateTime> {
        self.get_run_times().into_iter().next()
    }

    /// Get run count
    pub fn run_count(&self) -> usize {
        self.run_count_raw
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or_else(|| self.get_run_times().len())
    }

    /// Get all loaded files as an ordered vector.
    pub fn get_files(&self) -> Vec<&String> {
        // Kept for compatibility with existing report/analyzer calls.
        // This returns references to internal temporary strings by leaking boxed
        // strings, which is acceptable for one-shot CLI report generation.
        self.files_loaded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Box::leak(Box::new(s.to_string())) as &String)
            .collect()
    }

    /// Extract the executable path from files loaded (usually the 2nd entry)
    pub fn get_executable_path(&self) -> Option<String> {
        let files: Vec<String> = self
            .files_loaded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let exe_base = self.executable_name.trim_end_matches('.').to_uppercase();

        for file in &files {
            let upper = file.to_uppercase();
            let leaf = upper.rsplit('\\').next().unwrap_or(&upper);
            if leaf == exe_base || leaf == format!("{}.EXE", exe_base) || leaf.starts_with(&exe_base) {
                return Some(file.clone());
            }
        }

        for file in &files {
            let upper = file.to_uppercase();
            if upper.ends_with(".EXE") {
                return Some(file.clone());
            }
        }
        None
    }
    /// Extract the 8-character hex hash from the prefetch filename.
    /// e.g. "DWM.EXE-314E93C5.pf" → "314E93C5"
    pub fn extract_prefetch_hash(&self) -> Option<String> {
        if self.hash.len() == 8 && self.hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(self.hash.to_uppercase());
        }

        let basename = std::path::Path::new(&self.filename)
            .file_name()
            .and_then(|n| n.to_str())?;
        let without_ext = basename
            .strip_suffix(".pf")
            .or_else(|| basename.strip_suffix(".PF"))?;
        let last_hyphen = without_ext.rfind('-')?;
        let hash = &without_ext[last_hyphen + 1..];
        if hash.len() == 8 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(hash.to_uppercase())
        } else {
            None
        }
    }

    /// Returns true when this entry's path matches the classic VCREDIST / VC_REDIST
    /// installer extraction pattern: `\WINDOWS\TEMP\{GUID}\{.CR|.BE}\` —
    /// standard Microsoft packaging behaviour, almost always benign.
    pub fn is_vcredist_temp_path(&self) -> bool {
        if let Some(path) = self.get_executable_path() {
            let upper = path.to_uppercase();
            // Must be under \WINDOWS\TEMP\ or any \TEMP\
            if !upper.contains("\\WINDOWS\\TEMP\\") && !upper.contains("\\TEMP\\") {
                return false;
            }
            // Scan every '{' in the path for a valid GUID pattern:
            // {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}  (8-4-4-4-12 hex digits)
            let bytes = upper.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'{' {
                    let rest = &upper[i..];
                    // A GUID is 38 chars: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
                    if rest.len() >= 38 {
                        let candidate = &rest[1..37]; // 36 chars inside braces
                        let parts: Vec<&str> = candidate.splitn(5, '-').collect();
                        if parts.len() == 5
                            && parts[0].len() == 8
                            && parts[1].len() == 4
                            && parts[2].len() == 4
                            && parts[3].len() == 4
                            && parts[4].len() == 12
                            && rest.as_bytes().get(37) == Some(&b'}')
                            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Low => "🔵",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    SuspiciousPath,
    MaliciousTool,
    LolBin,
    SuspiciousDll,
    RansomwareIndicator,
    FrequencyAnomaly,
    Masquerading,
    TimelineAnomaly,
    SingleExecution,
    RemoteAccess,
    AntiForensics,
    DataExfiltration,
    CredentialTheft,
    C2Framework,
    NetworkScanning,
    LateralMovement,
    /// Same executable name, different prefetch hashes (different execution paths)
    MultiPathExecution,
}

impl FindingCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingCategory::SuspiciousPath => "Suspicious Path",
            FindingCategory::MaliciousTool => "Malicious Tool",
            FindingCategory::LolBin => "LOLBin",
            FindingCategory::SuspiciousDll => "Suspicious DLL",
            FindingCategory::RansomwareIndicator => "Ransomware Indicator",
            FindingCategory::FrequencyAnomaly => "Frequency Anomaly",
            FindingCategory::Masquerading => "Masquerading",
            FindingCategory::TimelineAnomaly => "Timeline Anomaly",
            FindingCategory::SingleExecution => "Single Execution",
            FindingCategory::RemoteAccess => "Remote Access",
            FindingCategory::AntiForensics => "Anti-Forensics",
            FindingCategory::DataExfiltration => "Data Exfiltration",
            FindingCategory::CredentialTheft => "Credential Theft",
            FindingCategory::C2Framework => "C2 Framework",
            FindingCategory::NetworkScanning => "Network Scanning",
            FindingCategory::LateralMovement => "Lateral Movement",
            FindingCategory::MultiPathExecution => "Multi-Path Execution",
        }
    }
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A security finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier
    pub id: String,

    /// Finding category
    pub category: FindingCategory,

    /// Severity level
    pub severity: Severity,

    /// Executable name
    pub executable: String,

    /// Description of the finding
    pub description: String,

    /// MITRE ATT&CK technique ID (if applicable)
    pub mitre_attack: Option<String>,

    /// MITRE ATT&CK technique name
    pub mitre_name: Option<String>,

    /// File path (if applicable)
    pub path: Option<String>,

    /// Run count at time of finding
    pub run_count: usize,

    /// Last execution time
    pub last_run: Option<NaiveDateTime>,

    /// Additional context/evidence
    pub context: Option<String>,

    /// Reference to the source prefetch entry
    pub source_file: String,

    /// Full list of loaded files/DLLs captured for evidence disclosure
    #[serde(default)]
    pub loaded_files: Vec<String>,

    /// True when the finding has been annotated as likely-benign installer noise
    #[serde(default)]
    pub likely_benign_installer: bool,
}

impl Finding {
    pub fn new(
        category: FindingCategory,
        severity: Severity,
        executable: &str,
        description: &str,
        source_file: &str,
    ) -> Self {
        Self {
            id: uuid_v4(),
            category,
            severity,
            executable: executable.to_string(),
            description: description.to_string(),
            mitre_attack: None,
            mitre_name: None,
            path: None,
            run_count: 0,
            last_run: None,
            context: None,
            source_file: source_file.to_string(),
            loaded_files: Vec::new(),
            likely_benign_installer: false,
        }
    }

    pub fn with_mitre(mut self, attack_id: &str, name: &str) -> Self {
        self.mitre_attack = Some(attack_id.to_string());
        self.mitre_name = Some(name.to_string());
        self
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    pub fn with_run_info(mut self, count: usize, last: Option<NaiveDateTime>) -> Self {
        self.run_count = count;
        self.last_run = last;
        self
    }

    pub fn with_context(mut self, context: &str) -> Self {
        self.context = Some(context.to_string());
        self
    }

    /// Attach a snapshot of loaded files/DLLs for evidence disclosure
    pub fn with_loaded_files(mut self, files: Vec<String>) -> Self {
        self.loaded_files = files;
        self
    }

    /// Mark this finding as a known-good installer pattern to reduce analyst noise
    pub fn mark_likely_benign_installer(mut self) -> Self {
        self.likely_benign_installer = true;
        self
    }
}

/// Analysis report containing all findings
#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,

    /// Total prefetch entries analyzed
    pub total_entries: usize,

    /// Unique executables found
    pub unique_executables: usize,

    /// Date range of executions
    pub date_range: Option<(NaiveDateTime, NaiveDateTime)>,

    /// All findings grouped by severity
    pub findings: Vec<Finding>,

    /// Summary counts
    pub summary: ReportSummary,

    /// Raw prefetch entries (excluded from serialised JSON output to keep size sane;
    /// used exclusively by the HTML/Markdown report generators for the new timeline
    /// and complete-entry-table sections).
    #[serde(skip)]
    pub raw_entries: Vec<PrefetchEntry>,
}

#[derive(Debug, Default, Serialize)]
pub struct ReportSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Simple UUID v4 generator (good enough for our purposes)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_run_time() {
        assert!(PrefetchEntry::parse_dt("2023-03-08 11:04:34").is_some());
        assert!(PrefetchEntry::parse_dt("2023-03-08 11:04:34.692143").is_some());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
