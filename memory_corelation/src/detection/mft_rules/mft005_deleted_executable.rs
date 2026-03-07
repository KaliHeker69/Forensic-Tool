//! MFT005 – DeletedExecutableRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::mft::MftEntry;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting recently deleted executables
pub struct DeletedExecutableRule;

impl DetectionRule for DeletedExecutableRule {
    fn id(&self) -> &str {
        "MFT005"
    }

    fn name(&self) -> &str {
        "Deleted Executable Detection"
    }

    fn description(&self) -> &str {
        "Detects recently deleted executable files which may indicate anti-forensic activity"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1070.004")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in &data.mft_entries {
            if entry.is_deleted() && entry.is_executable() {
                let filename = entry.filename.as_deref().unwrap_or("unknown");
                let record_num = entry.record_number.unwrap_or(0);
                
                findings.push(create_finding(
                    self,
                    format!("Deleted executable: {}", filename),
                    format!(
                        "Deleted executable file found in MFT. This may indicate anti-forensic \
                        activity or malware cleanup. File: {} (Record: {})",
                        filename, record_num
                    ),
                    vec![Evidence {
                        source_plugin: "mftscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Filename:{} RecordNum:{} Deleted:true", filename, record_num),
                    }],
                ));
            }
        }

        findings
    }
}
