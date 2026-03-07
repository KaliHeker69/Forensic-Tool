pub mod registry;
pub mod eventlog;
pub mod lnk;
pub mod jumplist;
pub mod prefetch;
pub mod shellbags;
pub mod mft;
pub mod usnjrnl;
pub mod setupapi;
pub mod timeline;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a USB device identified from forensic artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor: String,
    pub product: String,
    pub serial_number: String,
    pub device_class: Option<String>,
    pub first_connected: Option<DateTime<Utc>>,
    pub last_connected: Option<DateTime<Utc>>,
    pub last_disconnected: Option<DateTime<Utc>>,
    pub drive_letter: Option<String>,
    pub volume_guid: Option<String>,
    pub volume_serial: Option<String>,
    pub volume_label: Option<String>,
    pub friendly_name: Option<String>,
    pub associated_user: Option<String>,
    // Enriched fields
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub connection_count: u32,
    pub suspicious_serial: bool,
    pub serial_flags: Vec<String>,
}

impl Default for UsbDevice {
    fn default() -> Self {
        Self {
            vendor: String::new(),
            product: String::new(),
            serial_number: String::new(),
            device_class: None,
            first_connected: None,
            last_connected: None,
            last_disconnected: None,
            drive_letter: None,
            volume_guid: None,
            volume_serial: None,
            volume_label: None,
            friendly_name: None,
            associated_user: None,
            vendor_id: None,
            product_id: None,
            connection_count: 1,
            suspicious_serial: false,
            serial_flags: Vec::new(),
        }
    }
}

impl UsbDevice {
    #[allow(dead_code)]
    pub fn device_id(&self) -> String {
        format!("{}_{}_{}",
            self.vendor.trim(),
            self.product.trim(),
            self.serial_number.trim()
        )
    }

    /// Check if the serial number looks suspicious/spoofed
    pub fn check_serial_suspicious(&mut self) {
        let sn = self.serial_number.trim();
        if sn.is_empty() || sn == "0" {
            self.suspicious_serial = true;
            self.serial_flags.push("Empty/zero serial".to_string());
            return;
        }
        // All same character
        if sn.len() > 2 && sn.chars().all(|c| c == sn.chars().next().unwrap()) {
            self.suspicious_serial = true;
            self.serial_flags.push(format!("All same digit: '{}'", &sn[..1]));
        }
        // Sequential digits (123456...)
        let digits: Vec<u8> = sn.bytes().filter(|b| b.is_ascii_digit()).collect();
        if digits.len() >= 4 {
            let is_sequential = digits.windows(2).all(|w| w[1] == w[0] + 1);
            if is_sequential {
                self.suspicious_serial = true;
                self.serial_flags.push("Sequential digits".to_string());
            }
        }
        // All zeros
        if sn.chars().all(|c| c == '0') {
            self.suspicious_serial = true;
            self.serial_flags.push("All zeros".to_string());
        }
        // Very short serial
        if sn.len() <= 3 {
            self.suspicious_serial = true;
            self.serial_flags.push("Unusually short serial".to_string());
        }
    }

    /// Try to parse VID/PID from device path strings
    pub fn parse_vid_pid_from_path(path: &str) -> (Option<String>, Option<String>) {
        let upper = path.to_uppercase();
        let vid = if let Some(idx) = upper.find("VID_") {
            let start = idx + 4;
            let end = upper[start..].find(|c: char| !c.is_ascii_hexdigit()).map(|e| start + e).unwrap_or(start + 4);
            Some(upper[start..end.min(upper.len())].to_string())
        } else {
            None
        };
        let pid = if let Some(idx) = upper.find("PID_") {
            let start = idx + 4;
            let end = upper[start..].find(|c: char| !c.is_ascii_hexdigit()).map(|e| start + e).unwrap_or(start + 4);
            Some(upper[start..end.min(upper.len())].to_string())
        } else {
            None
        };
        (vid, pid)
    }
}

/// Represents a file access event from any artifact source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub file_path: String,
    pub file_name: String,
    pub access_type: FileAccessType,
    pub source_artifact: String,
    pub drive_letter: Option<String>,
    pub volume_serial: Option<String>,
    pub user: Option<String>,
    pub details: Option<String>,
    pub file_size: Option<u64>,
    pub user_sid: Option<String>,
}

impl Default for FileAccessEvent {
    fn default() -> Self {
        Self {
            timestamp: None,
            file_path: String::new(),
            file_name: String::new(),
            access_type: FileAccessType::Unknown,
            source_artifact: String::new(),
            drive_letter: None,
            volume_serial: None,
            user: None,
            details: None,
            file_size: None,
            user_sid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileAccessType {
    Created,
    Modified,
    Accessed,
    Deleted,
    Renamed,
    Copied,
    Executed,
    Browsed,
    Unknown,
}

impl std::fmt::Display for FileAccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileAccessType::Created => write!(f, "Created"),
            FileAccessType::Modified => write!(f, "Modified"),
            FileAccessType::Accessed => write!(f, "Accessed"),
            FileAccessType::Deleted => write!(f, "Deleted"),
            FileAccessType::Renamed => write!(f, "Renamed"),
            FileAccessType::Copied => write!(f, "Copied"),
            FileAccessType::Executed => write!(f, "Executed"),
            FileAccessType::Browsed => write!(f, "Browsed"),
            FileAccessType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Represents a correlated finding linking USB device to file activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub usb_device: Option<UsbDevice>,
    pub file_events: Vec<FileAccessEvent>,
    pub supporting_artifacts: Vec<String>,
    pub confidence: f64,
    pub corroboration_count: u32,
    pub finding_type: FindingType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    UsbFileActivity,
    MassFileOperation,
    SensitiveFileAccess,
    Timestomping,
    AntiForensics,
    UsbSession,
    OffHoursActivity,
    FirstTimeDevice,
    ExecutableFromUsb,
    AntiForensicTool,
    MultipleDevicesSession,
    Other,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::UsbFileActivity => write!(f, "USB File Activity"),
            FindingType::MassFileOperation => write!(f, "Mass File Operation"),
            FindingType::SensitiveFileAccess => write!(f, "Sensitive File Access"),
            FindingType::Timestomping => write!(f, "Timestomping"),
            FindingType::AntiForensics => write!(f, "Anti-Forensics"),
            FindingType::UsbSession => write!(f, "USB Session"),
            FindingType::OffHoursActivity => write!(f, "Off-Hours Activity"),
            FindingType::FirstTimeDevice => write!(f, "First-Time Device"),
            FindingType::ExecutableFromUsb => write!(f, "Executable from USB"),
            FindingType::AntiForensicTool => write!(f, "Anti-Forensic Tool"),
            FindingType::MultipleDevicesSession => write!(f, "Multiple Devices in Session"),
            FindingType::Other => write!(f, "Other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Evidence integrity: hash of a parsed artifact file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHash {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub artifact_type: String,
}

/// Tracks which artifact categories were searched and found/not-found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactStatus {
    pub category: String,
    pub searched_patterns: Vec<String>,
    pub files_found: usize,
    pub found: bool,
}

/// Analysis context passed to report generators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub artifact_hashes: Vec<ArtifactHash>,
    pub artifact_statuses: Vec<ArtifactStatus>,
    pub total_file_events: usize,
    pub unique_files_accessed: usize,
    pub data_volume_estimate: u64,
    pub suspect_users: Vec<String>,
    pub executive_narrative: String,
    pub recommended_next_steps: Vec<String>,
    pub confidence_drivers: Vec<String>,
    pub investigation_confidence: f64,
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self {
            artifact_hashes: Vec::new(),
            artifact_statuses: Vec::new(),
            total_file_events: 0,
            unique_files_accessed: 0,
            data_volume_estimate: 0,
            suspect_users: Vec::new(),
            executive_narrative: String::new(),
            recommended_next_steps: Vec::new(),
            confidence_drivers: Vec::new(),
            investigation_confidence: 0.0,
        }
    }
}

/// File type sensitivity scoring
pub fn file_sensitivity_score(filename: &str) -> u32 {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        // Credentials & crypto - highest
        "pfx" | "p12" | "pem" | "key" | "cer" | "crt" | "kdbx" | "keychain" => 100,
        // Database files
        "accdb" | "mdb" | "sql" | "db" | "sqlite" | "sqlite3" => 90,
        // Email archives
        "pst" | "ost" | "eml" | "msg" | "mbox" => 85,
        // Financial / spreadsheet
        "xlsx" | "xls" | "xlsm" | "xlsb" => 80,
        // Documents
        "docx" | "doc" | "docm" | "pdf" | "rtf" => 75,
        // Presentations
        "pptx" | "ppt" | "pptm" => 70,
        // Compressed archives
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "cab" => 65,
        // Config / secrets
        "env" | "conf" | "config" | "yaml" | "yml" | "json" | "xml" | "ini" | "toml" => 55,
        // Source code
        "py" | "java" | "cs" | "cpp" | "c" | "h" | "rs" | "go" | "rb" | "js" | "ts"
        | "php" | "swift" | "kt" => 50,
        // Backups
        "bak" | "backup" | "dump" | "dmp" => 60,
        // CAD / engineering
        "dwg" | "dxf" | "vsd" | "vsdx" | "step" | "stl" => 70,
        // Image
        "jpg" | "jpeg" | "png" | "bmp" | "tiff" | "gif" | "svg" => 30,
        // Video / audio
        "mp4" | "avi" | "mov" | "mkv" | "mp3" | "wav" => 25,
        // Plain text / logs
        "txt" | "log" | "csv" => 20,
        // Temp files
        "tmp" | "temp" | "cache" => 10,
        // LibreOffice
        "odt" | "ods" | "odp" => 70,
        _ => 15,
    }
}

/// Check if a timestamp is during off-hours (before 7AM, after 7PM, or weekends)
pub fn is_off_hours(ts: &DateTime<Utc>) -> bool {
    let hour = ts.format("%H").to_string().parse::<u32>().unwrap_or(12);
    let weekday = ts.format("%u").to_string().parse::<u32>().unwrap_or(1); // 1=Mon, 7=Sun
    // Off-hours: before 7AM, after 7PM, or weekends (Sat=6, Sun=7)
    hour < 7 || hour >= 19 || weekday >= 6
}

/// Format bytes to human-readable
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Build the executive narrative from analysis results
pub fn build_executive_narrative(
    devices: &[UsbDevice],
    findings: &[CorrelatedFinding],
    context: &AnalysisContext,
) -> String {
    if findings.is_empty() && devices.is_empty() {
        return "No USB storage devices or suspicious file activity were detected in the analyzed artifacts. \
                The absence of findings may indicate either no exfiltration occurred, or that evidence \
                has been removed or was not captured by the collected artifacts.".to_string();
    }

    let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();

    let mut narrative = String::new();

    // Opening
    narrative.push_str(&format!(
        "Analysis of {} forensic artifact categories identified {} USB storage device(s) and generated {} finding(s). ",
        context.artifact_statuses.iter().filter(|s| s.found).count(),
        devices.len(),
        findings.len()
    ));

    // Severity summary
    if critical_count > 0 || high_count > 0 {
        narrative.push_str(&format!(
            "Of these, {} are rated CRITICAL and {} are HIGH severity, indicating significant indicators of data exfiltration. ",
            critical_count, high_count
        ));
    }

    // Suspect user
    if !context.suspect_users.is_empty() {
        narrative.push_str(&format!(
            "The primary suspect account is \"{}\". ",
            context.suspect_users[0]
        ));
    }

    // Data volume
    if context.data_volume_estimate > 0 {
        narrative.push_str(&format!(
            "Approximately {} of data across {} unique files ({} total access events) were observed on removable media. ",
            format_bytes(context.data_volume_estimate),
            context.unique_files_accessed,
            context.total_file_events
        ));
    }

    // Off-hours check
    let off_hours_findings: Vec<_> = findings.iter()
        .filter(|f| f.finding_type == FindingType::OffHoursActivity)
        .collect();
    if !off_hours_findings.is_empty() {
        narrative.push_str("Notably, USB activity was detected during off-hours (outside 7AM-7PM or on weekends), which increases the suspicion level. ");
    }

    // Anti-forensics
    let af_findings: Vec<_> = findings.iter()
        .filter(|f| f.finding_type == FindingType::AntiForensics || f.finding_type == FindingType::AntiForensicTool || f.finding_type == FindingType::Timestomping)
        .collect();
    if !af_findings.is_empty() {
        narrative.push_str("Evidence of anti-forensic activity was detected, suggesting deliberate attempts to conceal evidence. ");
    }

    // Missing artifacts
    let missing: Vec<_> = context.artifact_statuses.iter().filter(|s| !s.found).collect();
    if !missing.is_empty() {
        narrative.push_str(&format!(
            "{} artifact category(ies) were not found in the provided data, which may represent collection gaps. ",
            missing.len()
        ));
    }

    narrative
}

/// Build recommended next steps
pub fn build_next_steps(
    devices: &[UsbDevice],
    findings: &[CorrelatedFinding],
    context: &AnalysisContext,
) -> Vec<String> {
    let mut steps = Vec::new();

    if !devices.is_empty() {
        steps.push("Attempt to locate and forensically image the identified USB device(s) for content verification.".to_string());
    }

    let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    if critical_count > 0 {
        steps.push("Preserve Volume Shadow Copy (VSS) snapshots from the source system for timeline corroboration.".to_string());
        steps.push("Issue a legal hold on all relevant systems and accounts to prevent evidence spoliation.".to_string());
    }

    if !context.suspect_users.is_empty() {
        steps.push(format!(
            "Schedule a forensic interview with user account \"{}\" regarding the identified USB activity.",
            context.suspect_users[0]
        ));
    }

    let af_findings: Vec<_> = findings.iter()
        .filter(|f| f.finding_type == FindingType::AntiForensics || f.finding_type == FindingType::AntiForensicTool)
        .collect();
    if !af_findings.is_empty() {
        steps.push("Investigate anti-forensic tool usage — check browser history, PowerShell logs, and Recycle Bin for additional evidence.".to_string());
    }

    let missing: Vec<_> = context.artifact_statuses.iter().filter(|s| !s.found).collect();
    if !missing.is_empty() {
        let names: Vec<_> = missing.iter().map(|m| m.category.as_str()).collect();
        steps.push(format!(
            "Collect missing artifact categories ({}) to strengthen the forensic timeline.",
            names.join(", ")
        ));
    }

    steps.push("Cross-reference findings with DLP (Data Loss Prevention) logs if available.".to_string());
    steps.push("Document chain of custody for all evidence items and prepare a formal forensic report.".to_string());

    if context.data_volume_estimate > 10_485_760 {
        steps.push("Conduct a data classification review of the accessed files to assess potential regulatory impact (PII, PHI, PCI-DSS).".to_string());
    }

    steps
}

/// Compute investigation confidence score and drivers
pub fn compute_investigation_confidence(
    findings: &[CorrelatedFinding],
    context: &AnalysisContext,
) -> (f64, Vec<String>) {
    let mut score = 0.0_f64;
    let mut drivers = Vec::new();
    let mut max_score = 0.0_f64;

    // Factor 1: Number of artifact categories found (0-20 points)
    let found_count = context.artifact_statuses.iter().filter(|s| s.found).count();
    let total_categories = context.artifact_statuses.len().max(1);
    let category_score = (found_count as f64 / total_categories as f64) * 20.0;
    score += category_score;
    max_score += 20.0;
    drivers.push(format!("{}/{} artifact categories present (+{:.0})", found_count, total_categories, category_score));

    // Factor 2: Corroboration across findings (0-25 points)
    let max_corrob = findings.iter().map(|f| f.corroboration_count).max().unwrap_or(0);
    let corrob_score = (max_corrob as f64 / 5.0).min(1.0) * 25.0;
    score += corrob_score;
    max_score += 25.0;
    drivers.push(format!("Max corroboration: {} sources (+{:.0})", max_corrob, corrob_score));

    // Factor 3: Finding confidence average (0-25 points)
    if !findings.is_empty() {
        let avg_conf = findings.iter().map(|f| f.confidence).sum::<f64>() / findings.len() as f64;
        let conf_score = avg_conf * 25.0;
        score += conf_score;
        drivers.push(format!("Average finding confidence: {:.0}% (+{:.0})", avg_conf * 100.0, conf_score));
    }
    max_score += 25.0;

    // Factor 4: Timeline completeness (0-15 points)
    if context.total_file_events > 0 {
        let tl_score = (context.total_file_events as f64 / 100.0).min(1.0) * 15.0;
        score += tl_score;
        drivers.push(format!("{} total file events (+{:.0})", context.total_file_events, tl_score));
    }
    max_score += 15.0;

    // Factor 5: Severity of findings (0-15 points)
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let sev_score = ((critical as f64 * 5.0 + high as f64 * 3.0) / 15.0).min(1.0) * 15.0;
    score += sev_score;
    max_score += 15.0;
    drivers.push(format!("{} critical + {} high findings (+{:.0})", critical, high, sev_score));

    let normalized = (score / max_score * 100.0).min(100.0);
    (normalized, drivers)
}

/// Compute suspect users from device and event data
pub fn compute_suspect_users(
    devices: &[UsbDevice],
    events: &[FileAccessEvent],
) -> Vec<String> {
    let mut user_counts: HashMap<String, usize> = HashMap::new();
    for dev in devices {
        if let Some(ref user) = dev.associated_user {
            if !user.is_empty() && user != "N/A" {
                *user_counts.entry(user.clone()).or_insert(0) += 10;
            }
        }
    }
    for event in events {
        if let Some(ref user) = event.user {
            if !user.is_empty() && user != "N/A" && user != "SYSTEM" {
                *user_counts.entry(user.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut users: Vec<_> = user_counts.into_iter().collect();
    users.sort_by(|a, b| b.1.cmp(&a.1));
    users.into_iter().map(|(u, _)| u).collect()
}
