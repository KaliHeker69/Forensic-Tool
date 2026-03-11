//! MFT Analyzer - Analyze MFTECmd CSV output for forensic indicators
//! Detects: Timestomping, deleted files, suspicious locations, ADS, credential access

use chrono::{DateTime, NaiveDateTime, Utc};
use csv::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use super::config::{
    get_mitre_technique, is_credential_file, is_lolbin, is_suspicious_path,
    is_windows_system_file, Severity, DATA_STAGING_EXTENSIONS, DATA_STAGING_SIZE_THRESHOLD,
};

// =============================================================================
// DETECTION TYPES
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionType {
    Timestomping,
    TimestompingUsecZeros,
    DeletedFile,
    SuspiciousLocation,
    AlternateDataStream,
    CredentialAccess,
    LateralMovement,
    LolbinExecution,
    DataStaging,
    InternetDownload,
    Masquerading,
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionType::Timestomping => write!(f, "Timestomping"),
            DetectionType::TimestompingUsecZeros => write!(f, "Timestomping (Subsecond Zeros)"),
            DetectionType::DeletedFile => write!(f, "Deleted File"),
            DetectionType::SuspiciousLocation => write!(f, "Suspicious Location"),
            DetectionType::AlternateDataStream => write!(f, "Alternate Data Stream"),
            DetectionType::CredentialAccess => write!(f, "Credential Access"),
            DetectionType::LateralMovement => write!(f, "Lateral Movement"),
            DetectionType::LolbinExecution => write!(f, "LOLBin Execution"),
            DetectionType::DataStaging => write!(f, "Data Staging"),
            DetectionType::InternetDownload => write!(f, "Internet Download"),
            DetectionType::Masquerading => write!(f, "Masquerading"),
        }
    }
}

// =============================================================================
// MFT RECORD
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MftRecord {
    pub entry_number: u64,
    pub sequence_number: u64,
    pub in_use: String,
    pub parent_entry_number: Option<u64>,
    pub parent_sequence_number: Option<u64>,
    pub parent_path: String,
    pub file_name: String,
    pub extension: String,
    pub file_size: Option<u64>,
    pub reference_count: Option<u64>,
    pub reparse_target: Option<String>,
    pub is_directory: String,
    pub has_ads: String,
    pub is_ads: String,
    #[serde(rename = "SI<FN")]
    pub si_less_than_fn: String,
    #[serde(rename = "uSecZeros")]
    pub usec_zeros: String,
    pub copied: String,
    pub si_flags: String,
    pub name_type: String,
    #[serde(rename = "Created0x10")]
    pub created_si: Option<String>,
    #[serde(rename = "Created0x30")]
    pub created_fn: Option<String>,
    #[serde(rename = "LastModified0x10")]
    pub modified_si: Option<String>,
    #[serde(rename = "LastModified0x30")]
    pub modified_fn: Option<String>,
    #[serde(rename = "LastRecordChange0x10")]
    pub mft_modified_si: Option<String>,
    #[serde(rename = "LastRecordChange0x30")]
    pub mft_modified_fn: Option<String>,
    #[serde(rename = "LastAccess0x10")]
    pub accessed_si: Option<String>,
    #[serde(rename = "LastAccess0x30")]
    pub accessed_fn: Option<String>,
    pub update_sequence_number: Option<u64>,
    pub logfile_sequence_number: Option<u64>,
    pub security_id: Option<u64>,
    pub object_id_file_droid: Option<String>,
    pub logged_util_stream: Option<String>,
    pub zone_id_contents: Option<String>,
    pub source_file: Option<String>,
}

impl MftRecord {
    /// Get full file path
    pub fn full_path(&self) -> String {
        if !self.parent_path.is_empty() {
            format!("{}\\{}", self.parent_path, self.file_name)
        } else {
            self.file_name.clone()
        }
    }

    /// Check if record is in use (not deleted)
    pub fn is_in_use(&self) -> bool {
        self.in_use.to_lowercase() == "true"
    }

    /// Check if SI<FN (timestomping indicator)
    pub fn has_si_less_than_fn(&self) -> bool {
        self.si_less_than_fn.to_lowercase() == "true"
    }

    /// Check if subsecond zeros present
    pub fn has_usec_zeros(&self) -> bool {
        self.usec_zeros.to_lowercase() == "true"
    }

    /// Check if has Alternate Data Streams
    pub fn has_alternate_data_stream(&self) -> bool {
        self.has_ads.to_lowercase() == "true"
    }

    /// Check if is an ADS
    pub fn is_alternate_data_stream(&self) -> bool {
        self.is_ads.to_lowercase() == "true"
    }

    /// Get file size
    pub fn get_file_size(&self) -> u64 {
        self.file_size.unwrap_or(0)
    }
}

// =============================================================================
// DETECTION
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub timestamp: String,
    pub detection_type: String,
    pub severity: String,
    pub file_path: String,
    pub file_name: String,
    pub description: String,
    pub mitre_technique: String,
    pub details: String,
}

impl Detection {
    pub fn new(
        timestamp: Option<&str>,
        detection_type: DetectionType,
        severity: Severity,
        file_path: &str,
        file_name: &str,
        description: &str,
        mitre_technique: &str,
        details: HashMap<String, String>,
    ) -> Self {
        Detection {
            timestamp: timestamp.unwrap_or("").to_string(),
            detection_type: detection_type.to_string(),
            severity: severity.to_string(),
            file_path: file_path.to_string(),
            file_name: file_name.to_string(),
            description: description.to_string(),
            mitre_technique: mitre_technique.to_string(),
            details: format!("{:?}", details),
        }
    }
}

// =============================================================================
// MFT ANALYZER
// =============================================================================

pub struct MftAnalyzer {
    records: Vec<MftRecord>,
    detections: Vec<Detection>,
    stats: AnalysisStats,
}

#[derive(Debug, Default)]
pub struct AnalysisStats {
    pub total_records: usize,
    pub active_records: usize,
    pub deleted_records: usize,
    pub timestomped_files: usize,
    pub suspicious_locations: usize,
    pub ads_detected: usize,
    pub credential_access: usize,
}

impl MftAnalyzer {
    pub fn new() -> Self {
        MftAnalyzer {
            records: Vec::new(),
            detections: Vec::new(),
            stats: AnalysisStats::default(),
        }
    }

    /// Parse MFTECmd CSV output
    pub fn parse_csv(&mut self, csv_path: &str) -> Result<(), Box<dyn Error>> {
        let file = File::open(csv_path)?;
        let mut reader = Reader::from_reader(file);

        for result in reader.deserialize() {
            let record: MftRecord = result?;
            
            if record.is_in_use() {
                self.stats.active_records += 1;
            } else {
                self.stats.deleted_records += 1;
            }
            self.stats.total_records += 1;
            
            self.records.push(record);
        }

        Ok(())
    }

    /// Run all detection analyses
    pub fn analyze(&mut self) -> &Vec<Detection> {
        self.detections.clear();

        // Use index-based iteration to avoid borrow conflict
        let record_count = self.records.len();
        for i in 0..record_count {
            // Clone the record for each detection method to avoid borrow issues
            let record = self.records[i].clone();
            self.detect_timestomping(&record);
            self.detect_deleted_suspicious(&record);
            self.detect_suspicious_location(&record);
            self.detect_ads(&record);
            self.detect_credential_access(&record);
            self.detect_lolbin(&record);
            self.detect_data_staging(&record);
            self.detect_internet_download(&record);
            self.detect_masquerading(&record);
        }

        &self.detections
    }

    /// Detect timestomping via SI<FN comparison and subsecond zeros
    fn detect_timestomping(&mut self, record: &MftRecord) {
        // Primary indicator: SI<FN field from MFTECmd
        if record.has_si_less_than_fn() {
            self.stats.timestomped_files += 1;

            let mut details = HashMap::new();
            details.insert("SI_Created".to_string(), record.created_si.clone().unwrap_or_default());
            details.insert("FN_Created".to_string(), record.created_fn.clone().unwrap_or_default());
            details.insert("uSecZeros".to_string(), record.usec_zeros.clone());

            self.detections.push(Detection::new(
                record.created_fn.as_deref().or(record.created_si.as_deref()),
                DetectionType::Timestomping,
                Severity::Critical,
                &record.full_path(),
                &record.file_name,
                "Timestomping detected: $SI timestamp < $FN timestamp",
                get_mitre_technique("timestomping"),
                details,
            ));
        }

        // Secondary indicator: Subsecond zeros (tool signature)
        if record.has_usec_zeros() && !record.has_si_less_than_fn() {
            let mut details = HashMap::new();
            details.insert("SI_Created".to_string(), record.created_si.clone().unwrap_or_default());
            details.insert("Indicator".to_string(), "Subsecond precision is .0000000".to_string());

            self.detections.push(Detection::new(
                record.created_si.as_deref(),
                DetectionType::TimestompingUsecZeros,
                Severity::High,
                &record.full_path(),
                &record.file_name,
                "Possible timestomping: Subsecond zeros detected (tool signature)",
                get_mitre_technique("timestomping"),
                details,
            ));
        }
    }

    /// Detect deleted files in suspicious locations
    fn detect_deleted_suspicious(&mut self, record: &MftRecord) {
        if record.is_in_use() {
            return;
        }

        let is_suspicious = is_suspicious_path(&record.full_path())
            || is_credential_file(&record.file_name, &record.full_path())
            || is_lolbin(&record.file_name);

        if is_suspicious {
            let mut details = HashMap::new();
            details.insert("FileSize".to_string(), record.get_file_size().to_string());
            details.insert("LastModified".to_string(), record.modified_si.clone().unwrap_or_default());

            self.detections.push(Detection::new(
                record.modified_si.as_deref().or(record.created_si.as_deref()),
                DetectionType::DeletedFile,
                Severity::High,
                &record.full_path(),
                &record.file_name,
                "Suspicious deleted file detected",
                get_mitre_technique("file_deletion"),
                details,
            ));
        }
    }

    /// Detect executables in suspicious locations
    fn detect_suspicious_location(&mut self, record: &MftRecord) {
        if !record.is_in_use() {
            return;
        }

        let suspicious_extensions = vec![".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"];
        let ext_lower = record.extension.to_lowercase();
        
        if !suspicious_extensions.iter().any(|e| ext_lower == *e) {
            return;
        }

        if is_suspicious_path(&record.full_path()) {
            self.stats.suspicious_locations += 1;

            let mut details = HashMap::new();
            details.insert("Extension".to_string(), record.extension.clone());
            details.insert("FileSize".to_string(), record.get_file_size().to_string());

            self.detections.push(Detection::new(
                record.created_si.as_deref(),
                DetectionType::SuspiciousLocation,
                Severity::Medium,
                &record.full_path(),
                &record.file_name,
                "Executable in suspicious location",
                get_mitre_technique("masquerading"),
                details,
            ));
        }
    }

    /// Detect Alternate Data Streams (hidden data)
    fn detect_ads(&mut self, record: &MftRecord) {
        if record.has_alternate_data_stream() || record.is_alternate_data_stream() {
            self.stats.ads_detected += 1;

            // Zone.Identifier is normal, other ADS is suspicious
            if record.is_alternate_data_stream() && !record.file_name.contains("Zone.Identifier") {
                let mut details = HashMap::new();
                details.insert("IsAds".to_string(), record.is_ads.clone());
                details.insert("HasAds".to_string(), record.has_ads.clone());

                self.detections.push(Detection::new(
                    record.created_si.as_deref(),
                    DetectionType::AlternateDataStream,
                    Severity::High,
                    &record.full_path(),
                    &record.file_name,
                    "Suspicious Alternate Data Stream detected",
                    "T1564.004",
                    details,
                ));
            }
        }
    }

    /// Detect access to credential-related files
    fn detect_credential_access(&mut self, record: &MftRecord) {
        if !is_credential_file(&record.file_name, &record.full_path()) {
            return;
        }

        // Skip if it's in the normal system location and is in use
        // Support both standard paths and MFTECmd relative format
        let normal_locations = vec![
            r"C:\Windows\System32\config",
            r"C:\Windows\NTDS",
            r".\Windows\System32\config",
            r".\Windows\NTDS",
        ];
        let is_normal = normal_locations.iter().any(|loc| {
            record.full_path().to_lowercase().starts_with(&loc.to_lowercase())
        });

        // Flag if copied to unusual location or recently modified
        if !is_normal || !record.is_in_use() {
            self.stats.credential_access += 1;

            let mut details = HashMap::new();
            details.insert("InUse".to_string(), record.in_use.clone());
            details.insert("Copied".to_string(), record.copied.clone());

            self.detections.push(Detection::new(
                record.accessed_si.as_deref().or(record.modified_si.as_deref()),
                DetectionType::CredentialAccess,
                Severity::Critical,
                &record.full_path(),
                &record.file_name,
                "Credential file access detected",
                get_mitre_technique("credential_dumping"),
                details,
            ));
        }
    }

    /// Detect LOLBins in unusual locations
    fn detect_lolbin(&mut self, record: &MftRecord) {
        if !is_lolbin(&record.file_name) {
            return;
        }

        // Check if in unusual location (not System32)
        // Support both standard paths and MFTECmd relative format
        let normal_paths = vec![
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r".\Windows\System32",
            r".\Windows\SysWOW64",
        ];
        let is_normal = normal_paths.iter().any(|p| {
            record.parent_path.to_lowercase().starts_with(&p.to_lowercase())
        });

        if !is_normal && record.is_in_use() {
            let mut details = HashMap::new();
            details.insert("ExpectedLocation".to_string(), "System32/SysWOW64".to_string());
            details.insert("ActualLocation".to_string(), record.parent_path.clone());

            self.detections.push(Detection::new(
                record.created_si.as_deref(),
                DetectionType::LolbinExecution,
                Severity::High,
                &record.full_path(),
                &record.file_name,
                "LOLBin in unusual location",
                "T1218",
                details,
            ));
        }
    }

    /// Detect potential data staging (large archives in temp)
    fn detect_data_staging(&mut self, record: &MftRecord) {
        let ext_lower = record.extension.to_lowercase();
        
        if !DATA_STAGING_EXTENSIONS.contains(ext_lower.as_str()) {
            return;
        }

        if record.get_file_size() >= DATA_STAGING_SIZE_THRESHOLD {
            if is_suspicious_path(&record.full_path()) {
                let size_mb = record.get_file_size() as f64 / (1024.0 * 1024.0);
                
                let mut details = HashMap::new();
                details.insert("FileSize".to_string(), format!("{:.2} MB", size_mb));
                details.insert("Extension".to_string(), record.extension.clone());

                self.detections.push(Detection::new(
                    record.created_si.as_deref(),
                    DetectionType::DataStaging,
                    Severity::High,
                    &record.full_path(),
                    &record.file_name,
                    "Large archive in suspicious location (potential data staging)",
                    get_mitre_technique("data_staged"),
                    details,
                ));
            }
        }
    }

    /// Detect internet-downloaded executables
    fn detect_internet_download(&mut self, record: &MftRecord) {
        if let Some(ref zone_id) = record.zone_id_contents {
            let suspicious_extensions = vec![".exe", ".dll", ".ps1", ".bat"];
            let ext_lower = record.extension.to_lowercase();
            
            if suspicious_extensions.iter().any(|e| ext_lower == *e) && zone_id.contains("ZoneId=3") {
                let mut details = HashMap::new();
                details.insert("ZoneId".to_string(), zone_id.clone());

                self.detections.push(Detection::new(
                    record.created_si.as_deref(),
                    DetectionType::InternetDownload,
                    Severity::Medium,
                    &record.full_path(),
                    &record.file_name,
                    "Executable downloaded from internet",
                    "T1105",
                    details,
                ));
            }
        }
    }

    /// Detect files masquerading as Windows system files
    fn detect_masquerading(&mut self, record: &MftRecord) {
        if !is_windows_system_file(&record.file_name) {
            return;
        }

        // Support both standard paths and MFTECmd relative format
        let expected_paths = vec![
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows",
            r".\Windows\System32",
            r".\Windows\SysWOW64",
            r".\Windows",
        ];
        let is_expected = expected_paths.iter().any(|p| {
            record.parent_path.to_lowercase() == p.to_lowercase()
        });

        if !is_expected && record.is_in_use() {
            let mut details = HashMap::new();
            details.insert("ExpectedPath".to_string(), r"C:\Windows\System32".to_string());
            details.insert("ActualPath".to_string(), record.parent_path.clone());

            self.detections.push(Detection::new(
                record.created_si.as_deref(),
                DetectionType::Masquerading,
                Severity::Critical,
                &record.full_path(),
                &record.file_name,
                "File masquerading as Windows system file",
                get_mitre_technique("masquerading"),
                details,
            ));
        }
    }

    /// Get analysis statistics
    pub fn get_stats(&self) -> &AnalysisStats {
        &self.stats
    }

    /// Get all detections
    pub fn get_detections(&self) -> &Vec<Detection> {
        &self.detections
    }

    /// Export detections to CSV
    pub fn export_detections(&self, output_path: &str) -> Result<(), Box<dyn Error>> {
        let mut file = File::create(output_path)?;
        
        // Write header
        writeln!(file, "Timestamp,DetectionType,Severity,FilePath,FileName,Description,MitreTechnique,Details")?;
        
        // Write detections
        for detection in &self.detections {
            writeln!(
                file,
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                detection.timestamp,
                detection.detection_type,
                detection.severity,
                detection.file_path,
                detection.file_name,
                detection.description,
                detection.mitre_technique,
                detection.details.replace("\"", "'"),
            )?;
        }

        Ok(())
    }

    /// Get summary of analysis
    pub fn get_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        
        summary.insert("total_records".to_string(), self.stats.total_records);
        summary.insert("active_records".to_string(), self.stats.active_records);
        summary.insert("deleted_records".to_string(), self.stats.deleted_records);
        summary.insert("total_detections".to_string(), self.detections.len());
        summary.insert("timestomped_files".to_string(), self.stats.timestomped_files);
        summary.insert("suspicious_locations".to_string(), self.stats.suspicious_locations);
        summary.insert("ads_detected".to_string(), self.stats.ads_detected);
        summary.insert("credential_access".to_string(), self.stats.credential_access);
        
        // Count by severity
        let critical_count = self.detections.iter().filter(|d| d.severity == "CRITICAL").count();
        let high_count = self.detections.iter().filter(|d| d.severity == "HIGH").count();
        let medium_count = self.detections.iter().filter(|d| d.severity == "MEDIUM").count();
        
        summary.insert("critical_detections".to_string(), critical_count);
        summary.insert("high_detections".to_string(), high_count);
        summary.insert("medium_detections".to_string(), medium_count);
        
        summary
    }
}

impl Default for MftAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
