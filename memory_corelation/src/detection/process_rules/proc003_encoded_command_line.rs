//! PROC003 – EncodedCommandLineRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect encoded/obfuscated command lines
pub struct EncodedCommandLineRule;

impl DetectionRule for EncodedCommandLineRule {
    fn id(&self) -> &str {
        "PROC003"
    }

    fn name(&self) -> &str {
        "Encoded Command Line"
    }

    fn description(&self) -> &str {
        "Detects Base64 encoded or otherwise obfuscated command line arguments"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1027") // Obfuscated Files or Information
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cmdline in engine.find_encoded_cmdlines() {
            let decoded = cmdline.decode_base64();

            let mut finding = create_finding(
                self,
                format!("Encoded cmdline: {} (PID:{})", cmdline.process, cmdline.pid),
                format!(
                    "Process {} has encoded/obfuscated command line arguments.{}",
                    cmdline.process,
                    decoded
                        .as_ref()
                        .map(|d| format!(" Decoded content: {}", d))
                        .unwrap_or_default()
                ),
                vec![Evidence {
                    source_plugin: "cmdline".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: cmdline.args.clone(),
                }],
            );
            finding.related_pids = vec![cmdline.pid];
            finding.confidence = 0.9;
            findings.push(finding);
        }

        findings
    }
}
