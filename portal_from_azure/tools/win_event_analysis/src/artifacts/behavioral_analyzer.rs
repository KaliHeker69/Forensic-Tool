//! Behavioral Analyzer - Detect attack patterns and behavioral indicators
//! Detects: Credential dumping, lateral movement, living-off-the-land, anti-forensics

use std::collections::HashMap;
use chrono::{DateTime, NaiveDateTime, Timelike};

use super::config::{
    get_mitre_technique, is_credential_file, is_lolbin, is_suspicious_path,
    Severity, CREDENTIAL_FILES, LATERAL_MOVEMENT_PATTERNS, SECURITY_TOOLS,
    DATA_STAGING_EXTENSIONS,
};
use super::mft_analyzer::MftRecord;

// =============================================================================
// BEHAVIOR TYPES
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BehaviorType {
    CredentialDumping,
    LateralMovement,
    LivingOffTheLand,
    DefenseEvasion,
    DataExfiltration,
    Persistence,
    Reconnaissance,
    PrivilegeEscalation,
    AntiForensics,
}

impl std::fmt::Display for BehaviorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehaviorType::CredentialDumping => write!(f, "Credential Dumping"),
            BehaviorType::LateralMovement => write!(f, "Lateral Movement"),
            BehaviorType::LivingOffTheLand => write!(f, "Living Off The Land"),
            BehaviorType::DefenseEvasion => write!(f, "Defense Evasion"),
            BehaviorType::DataExfiltration => write!(f, "Data Exfiltration"),
            BehaviorType::Persistence => write!(f, "Persistence"),
            BehaviorType::Reconnaissance => write!(f, "Reconnaissance"),
            BehaviorType::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            BehaviorType::AntiForensics => write!(f, "Anti-Forensics"),
        }
    }
}

// =============================================================================
// BEHAVIOR ALERT
// =============================================================================

#[derive(Debug, Clone)]
pub struct BehaviorAlert {
    pub timestamp: String,
    pub behavior_type: BehaviorType,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub mitre_techniques: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub source: String,
    pub file: String,
    pub timestamp: String,
    pub indicator: String,
}

impl BehaviorAlert {
    pub fn to_csv_row(&self) -> String {
        format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{:.0}%\"",
            self.timestamp,
            self.behavior_type,
            self.severity,
            self.description,
            self.mitre_techniques.join(", "),
            self.confidence * 100.0,
        )
    }
}

// =============================================================================
// BEHAVIORAL ANALYZER
// =============================================================================

pub struct BehavioralAnalyzer {
    alerts: Vec<BehaviorAlert>,
    mft_data: Vec<MftRecord>,
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        BehavioralAnalyzer {
            alerts: Vec::new(),
            mft_data: Vec::new(),
        }
    }

    /// Load MFT records for behavioral analysis
    pub fn load_mft_data(&mut self, records: Vec<MftRecord>) {
        self.mft_data = records;
    }

    /// Run all behavioral analyses
    pub fn analyze(&mut self) -> &Vec<BehaviorAlert> {
        self.alerts.clear();

        self.detect_credential_dumping();
        self.detect_lateral_movement();
        self.detect_lotl();
        self.detect_anti_forensics();
        self.detect_data_exfiltration();
        self.detect_burst_activity();
        self.detect_after_hours_activity();

        &self.alerts
    }

    /// Detect credential dumping patterns
    fn detect_credential_dumping(&mut self) {
        let mut evidence_list: Vec<Evidence> = Vec::new();

        for record in &self.mft_data {
            let file_name_lower = record.file_name.to_lowercase();
            let full_path = record.full_path();

            // Check for credential-related files
            if CREDENTIAL_FILES.contains(file_name_lower.as_str()) {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.accessed_si.clone().unwrap_or_default(),
                    indicator: "Credential file access".to_string(),
                });
            }

            // Check for memory dump files
            if file_name_lower.contains(".dmp") 
                && (file_name_lower.contains("lsass") || full_path.to_lowercase().contains("procdump")) 
            {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_si.clone().unwrap_or_default(),
                    indicator: "LSASS memory dump".to_string(),
                });
            }

            // Check for mimikatz artifacts
            if file_name_lower.contains("mimikatz") || file_name_lower.contains("sekurlsa") {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_si.clone().unwrap_or_default(),
                    indicator: "Mimikatz artifact".to_string(),
                });
            }

            // Check for SAM/SECURITY/SYSTEM hives in unusual locations
            if ["sam", "security", "system"].contains(&file_name_lower.as_str()) && !record.is_in_use() {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_si.clone().unwrap_or_default(),
                    indicator: "Registry hive copy (deleted)".to_string(),
                });
            }
        }

        if !evidence_list.is_empty() {
            let confidence = (0.3 + (evidence_list.len() as f64 * 0.15)).min(0.9);
            
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::CredentialDumping,
                severity: Severity::Critical,
                description: format!("Credential dumping activity detected ({} indicators)", evidence_list.len()),
                evidence: evidence_list,
                mitre_techniques: vec![
                    get_mitre_technique("credential_dumping").to_string(),
                    get_mitre_technique("lsass_dump").to_string(),
                    get_mitre_technique("sam_dump").to_string(),
                ],
                confidence,
            });
        }
    }

    /// Detect lateral movement patterns
    fn detect_lateral_movement(&mut self) {
        let mut evidence_list: Vec<Evidence> = Vec::new();

        for record in &self.mft_data {
            let full_path = record.full_path();
            let file_name_lower = record.file_name.to_lowercase();

            // Check for admin share access
            for pattern in LATERAL_MOVEMENT_PATTERNS.iter() {
                if pattern.is_match(&full_path) {
                    evidence_list.push(Evidence {
                        source: "MFT".to_string(),
                        file: full_path.clone(),
                        timestamp: record.created_si.clone().unwrap_or_default(),
                        indicator: "Admin share access".to_string(),
                    });
                    break;
                }
            }

            // Check for PsExec artifacts
            if file_name_lower.contains("psexe") {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_si.clone().unwrap_or_default(),
                    indicator: "PsExec artifact".to_string(),
                });
            }

            // Check for WMI artifacts
            if full_path.to_lowercase().contains("wmi") && full_path.to_lowercase().contains(".exe") {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_si.clone().unwrap_or_default(),
                    indicator: "WMI execution".to_string(),
                });
            }
        }

        if !evidence_list.is_empty() {
            let confidence = (0.25 + (evidence_list.len() as f64 * 0.2)).min(0.85);
            
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::LateralMovement,
                severity: Severity::High,
                description: format!("Lateral movement activity detected ({} indicators)", evidence_list.len()),
                evidence: evidence_list,
                mitre_techniques: vec![get_mitre_technique("lateral_movement_smb").to_string()],
                confidence,
            });
        }
    }

    /// Detect Living Off The Land Binary usage
    fn detect_lotl(&mut self) {
        let mut evidence_list: Vec<Evidence> = Vec::new();

        for record in &self.mft_data {
            let file_name_lower = record.file_name.to_lowercase();
            let parent_path_lower = record.parent_path.to_lowercase();

            if is_lolbin(&record.file_name) {
                let expected_paths = vec!["\\windows\\system32", "\\windows\\syswow64"];
                let is_normal = expected_paths.iter().any(|p| parent_path_lower.contains(p));

                if !is_normal && record.is_in_use() {
                    evidence_list.push(Evidence {
                        source: "MFT".to_string(),
                        file: record.full_path(),
                        timestamp: record.created_si.clone().unwrap_or_default(),
                        indicator: format!("LOLBin '{}' in unusual location", record.file_name),
                    });
                }
            }
        }

        if !evidence_list.is_empty() {
            let confidence = (0.3 + (evidence_list.len() as f64 * 0.1)).min(0.8);
            
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::LivingOffTheLand,
                severity: Severity::Medium,
                description: format!("Living Off The Land activity detected ({} LOLBins in unusual locations)", evidence_list.len()),
                evidence: evidence_list,
                mitre_techniques: vec!["T1218".to_string(), "T1059".to_string()],
                confidence,
            });
        }
    }

    /// Detect anti-forensics activity
    fn detect_anti_forensics(&mut self) {
        let mut evidence_list: Vec<Evidence> = Vec::new();

        for record in &self.mft_data {
            let file_name_lower = record.file_name.to_lowercase();
            let full_path = record.full_path();

            // Check for deleted event logs
            if !record.is_in_use() && file_name_lower.ends_with(".evtx") {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.modified_si.clone().unwrap_or_default(),
                    indicator: "Deleted event log".to_string(),
                });
            }

            // Check for deleted prefetch
            if !record.is_in_use() && file_name_lower.ends_with(".pf") {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.modified_si.clone().unwrap_or_default(),
                    indicator: "Deleted prefetch file".to_string(),
                });
            }

            // Check for timestomping
            if record.has_si_less_than_fn() {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.created_fn.clone().unwrap_or_default(),
                    indicator: "Timestomping detected".to_string(),
                });
            }

            // Check for deleted security tools
            if !record.is_in_use() && SECURITY_TOOLS.contains(file_name_lower.as_str()) {
                evidence_list.push(Evidence {
                    source: "MFT".to_string(),
                    file: full_path.clone(),
                    timestamp: record.modified_si.clone().unwrap_or_default(),
                    indicator: "Deleted security tool".to_string(),
                });
            }
        }

        if !evidence_list.is_empty() {
            let confidence = (0.4 + (evidence_list.len() as f64 * 0.15)).min(0.95);
            
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::AntiForensics,
                severity: Severity::Critical,
                description: format!("Anti-forensics activity detected ({} indicators)", evidence_list.len()),
                evidence: evidence_list,
                mitre_techniques: vec![
                    get_mitre_technique("indicator_removal").to_string(),
                    get_mitre_technique("log_clearing").to_string(),
                    get_mitre_technique("timestomping").to_string(),
                ],
                confidence,
            });
        }
    }

    /// Detect potential data staging/exfiltration
    fn detect_data_exfiltration(&mut self) {
        let mut evidence_list: Vec<Evidence> = Vec::new();

        let staging_locations = vec![
            "\\temp\\", "\\programdata\\", "\\users\\public\\",
            "\\appdata\\local\\temp\\",
        ];

        for record in &self.mft_data {
            let full_path_lower = record.full_path().to_lowercase();
            let ext_lower = record.extension.to_lowercase();

            if DATA_STAGING_EXTENSIONS.contains(ext_lower.as_str()) {
                let is_staging = staging_locations.iter().any(|loc| full_path_lower.contains(loc));

                if is_staging && record.get_file_size() > 10 * 1024 * 1024 {
                    let size_mb = record.get_file_size() as f64 / (1024.0 * 1024.0);
                    evidence_list.push(Evidence {
                        source: "MFT".to_string(),
                        file: record.full_path(),
                        timestamp: record.created_si.clone().unwrap_or_default(),
                        indicator: format!("Large archive ({:.2} MB) in staging location", size_mb),
                    });
                }
            }
        }

        if !evidence_list.is_empty() {
            let confidence = (0.3 + (evidence_list.len() as f64 * 0.2)).min(0.7);
            
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::DataExfiltration,
                severity: Severity::High,
                description: format!("Potential data staging detected ({} archives)", evidence_list.len()),
                evidence: evidence_list,
                mitre_techniques: vec![get_mitre_technique("data_staged").to_string()],
                confidence,
            });
        }
    }

    /// Detect burst file creation (automated attack indicator)
    fn detect_burst_activity(&mut self) {
        let mut creation_times: HashMap<String, Vec<&MftRecord>> = HashMap::new();

        for record in &self.mft_data {
            if let Some(ref created) = record.created_si {
                // Group by minute (first 16 chars: YYYY-MM-DD HH:MM)
                if created.len() >= 16 {
                    let minute_key = &created[..16];
                    creation_times
                        .entry(minute_key.to_string())
                        .or_insert_with(Vec::new)
                        .push(record);
                }
            }
        }

        let mut burst_events: Vec<Evidence> = Vec::new();
        for (time_key, records) in creation_times {
            if records.len() > 50 {
                burst_events.push(Evidence {
                    source: "MFT".to_string(),
                    file: format!("{} files", records.len()),
                    timestamp: time_key,
                    indicator: format!("Burst: {} files created in 1 minute", records.len()),
                });
            }
        }

        if !burst_events.is_empty() {
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::Reconnaissance,
                severity: Severity::Medium,
                description: format!("Burst file activity detected ({} events)", burst_events.len()),
                evidence: burst_events,
                mitre_techniques: vec!["T1083".to_string()],
                confidence: 0.6,
            });
        }
    }

    /// Detect suspicious after-hours file activity
    fn detect_after_hours_activity(&mut self) {
        let mut after_hours_files: Vec<Evidence> = Vec::new();

        for record in &self.mft_data {
            if let Some(ref created) = record.created_si {
                // Extract hour from timestamp (format: YYYY-MM-DD HH:MM:SS)
                if created.len() >= 13 {
                    if let Ok(hour) = created[11..13].parse::<u32>() {
                        // After hours: before 6 AM or after 10 PM
                        if hour < 6 || hour >= 22 {
                            let ext_lower = record.extension.to_lowercase();
                            if [".exe", ".dll", ".ps1", ".bat", ".vbs"].contains(&ext_lower.as_str()) {
                                after_hours_files.push(Evidence {
                                    source: "MFT".to_string(),
                                    file: record.full_path(),
                                    timestamp: created.clone(),
                                    indicator: format!("Created at {}:00", hour),
                                });
                            }
                        }
                    }
                }
            }
        }

        if after_hours_files.len() > 10 {
            self.alerts.push(BehaviorAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                behavior_type: BehaviorType::Reconnaissance,
                severity: Severity::Low,
                description: format!("After-hours file activity ({} executables)", after_hours_files.len()),
                evidence: after_hours_files.into_iter().take(10).collect(),
                mitre_techniques: vec!["T1059".to_string()],
                confidence: 0.5,
            });
        }
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &Vec<BehaviorAlert> {
        &self.alerts
    }

    /// Get summary
    pub fn get_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        
        summary.insert("total_alerts".to_string(), self.alerts.len());
        
        let mut behavior_counts: HashMap<String, usize> = HashMap::new();
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        
        for alert in &self.alerts {
            *behavior_counts.entry(alert.behavior_type.to_string()).or_insert(0) += 1;
            *severity_counts.entry(alert.severity.to_string()).or_insert(0) += 1;
        }
        
        for (k, v) in behavior_counts {
            summary.insert(k, v);
        }
        for (k, v) in severity_counts {
            summary.insert(k, v);
        }
        
        let high_confidence = self.alerts.iter().filter(|a| a.confidence >= 0.7).count();
        summary.insert("high_confidence_alerts".to_string(), high_confidence);
        
        summary
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
