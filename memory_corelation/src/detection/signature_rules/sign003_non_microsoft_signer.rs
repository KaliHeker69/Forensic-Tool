//! SIGN003 – NonMicrosoftSignerRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect non-Microsoft signers for processes that should be Microsoft-signed
pub struct NonMicrosoftSignerRule;

impl DetectionRule for NonMicrosoftSignerRule {
    fn id(&self) -> &str {
        "SIGN003"
    }

    fn name(&self) -> &str {
        "Non-Microsoft Signer for System Process"
    }

    fn description(&self) -> &str {
        "Detects critical system processes signed by non-Microsoft entities"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.005") // Masquerading: Match Legitimate Name
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let nodes = engine.build_process_nodes();

        for node in &nodes {
            if !node.is_critical_system_process() {
                continue;
            }

            if let Some(ref sig) = node.signature {
                // Signed with valid signature but not by Microsoft
                if sig.is_signed && sig.signature_valid && !sig.is_microsoft_signed() {
                    let mut finding = create_finding(
                        self,
                        format!("Non-Microsoft signer: {} signed by {}", 
                            node.name, 
                            sig.signer.as_deref().unwrap_or("Unknown")
                        ),
                        format!(
                            "Critical system process {} (PID:{}) is signed by '{}' instead of Microsoft. \
                             Legitimate Windows system processes (lsass.exe, svchost.exe, etc.) are \
                             exclusively signed by Microsoft Corporation.",
                            node.name,
                            node.pid,
                            sig.signer.as_deref().unwrap_or("Unknown")
                        ),
                        vec![Evidence {
                            source_plugin: "signature_check".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("{} signed by: {}", node.name, sig.signer.as_deref().unwrap_or("?")),
                        }],
                    );
                    finding.related_pids = vec![node.pid];
                    finding.confidence = 0.92;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

// Signature verification detection rules

