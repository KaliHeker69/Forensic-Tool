//! MFT002 – DoubleExtensionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting double extension files
pub struct DoubleExtensionRule;

impl DetectionRule for DoubleExtensionRule {
    fn id(&self) -> &str {
        "MFT002"
    }

    fn name(&self) -> &str {
        "Double Extension File Detection"
    }

    fn description(&self) -> &str {
        "Detects files with double extensions (e.g., document.pdf.exe) used to disguise malware"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.007")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in &data.mft_entries {
            if entry.has_double_extension() {
                let filename = entry.filename.as_deref().unwrap_or("unknown");
                
                findings.push(create_finding(
                    self,
                    format!("Double extension file: {}", filename),
                    format!(
                        "File with double extension detected. This technique is used to disguise \
                        executables as documents. File: {}",
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
