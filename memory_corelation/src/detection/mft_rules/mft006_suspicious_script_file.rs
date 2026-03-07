//! MFT006 – SuspiciousScriptFileRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::mft::MftEntry;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting suspicious script files
pub struct SuspiciousScriptFileRule;

impl DetectionRule for SuspiciousScriptFileRule {
    fn id(&self) -> &str {
        "MFT006"
    }

    fn name(&self) -> &str {
        "Suspicious Script File Detection"
    }

    fn description(&self) -> &str {
        "Detects script files (.ps1, .vbs, .js, etc.) in suspicious locations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1059.001")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        let script_extensions = [".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd"];

        for entry in &data.mft_entries {
            if let Some(ref filename) = entry.filename {
                let lower = filename.to_lowercase();
                let is_script = script_extensions.iter().any(|ext| lower.ends_with(ext));
                
                if is_script && entry.is_in_suspicious_directory() {
                    let severity = if lower.ends_with(".ps1") || lower.ends_with(".vbs") {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let mut finding = create_finding(
                        self,
                        format!("Script in suspicious location: {}", filename),
                        format!(
                            "Script file found in suspicious directory. \
                            This may indicate malware staging. File: {}",
                            filename
                        ),
                        vec![Evidence {
                            source_plugin: "mftscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("Filename:{}", filename),
                        }],
                    );
                    finding.severity = severity;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
