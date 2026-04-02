//! MFT004 – SystemFileMimicryRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting system file name mimicry
pub struct SystemFileMimicryRule;

impl DetectionRule for SystemFileMimicryRule {
    fn id(&self) -> &str {
        "MFT004"
    }

    fn name(&self) -> &str {
        "System File Name Mimicry"
    }

    fn description(&self) -> &str {
        "Detects files with names similar to system files located outside system directories"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.005")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in &data.mft_entries {
            if entry.mimics_system_file() {
                let filename = entry.filename.as_deref().unwrap_or("unknown");
                
                findings.push(create_finding(
                    self,
                    format!("System file mimicry: {}", filename),
                    format!(
                        "File name mimics a Windows system file but is not in the expected \
                        system directory. This is a common evasion technique. File: {}",
                        filename
                    ),
                    vec![Evidence {
                        source_plugin: "mftscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Filename:{}", filename),
                    }],
                ));
            }
        }

        findings
    }
}
