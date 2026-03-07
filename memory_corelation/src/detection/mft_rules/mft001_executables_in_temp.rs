//! MFT001 – ExecutablesInTempRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::mft::MftEntry;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting executables in temporary directories
pub struct ExecutablesInTempRule;

impl DetectionRule for ExecutablesInTempRule {
    fn id(&self) -> &str {
        "MFT001"
    }

    fn name(&self) -> &str {
        "Executables in Temp Directory"
    }

    fn description(&self) -> &str {
        "Detects executable files in temporary directories which is common malware behavior"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1204.002")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Known installer/update executables that legitimately run from temp
        let installer_patterns = [
            "setup", "install", "update", "patch", "unins",
            "msiexec", "dotnetfx", "vcredist", "ndp4", "windowsupdate",
            "au_.exe", "~nsu", "is-",  // NSIS, InnoSetup patterns
        ];

        for entry in &data.mft_entries {
            if entry.is_executable() && entry.is_in_suspicious_directory() {
                let filename = entry.filename.as_deref().unwrap_or("unknown");
                let lower = filename.to_lowercase();

                // Skip known installer patterns (reduce to Medium)
                let is_installer = installer_patterns.iter().any(|p| lower.contains(p));

                let mut finding = create_finding(
                    self,
                    format!("Executable in temp directory: {}", filename),
                    format!(
                        "Executable file found in suspicious location. \
                        This is commonly associated with malware staging. File: {}",
                        filename
                    ),
                    vec![Evidence {
                        source_plugin: "mftscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Filename:{} RecordNum:{:?}", filename, entry.record_number),
                    }],
                );

                if is_installer {
                    finding.severity = Severity::Low;
                    finding.confidence = 0.4;
                } else {
                    finding.confidence = 0.7;
                }

                findings.push(finding);
            }
        }

        findings
    }
}
