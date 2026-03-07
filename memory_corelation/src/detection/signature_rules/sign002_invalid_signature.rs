//! SIGN002 – InvalidSignatureRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect system processes with invalid signatures
pub struct InvalidSignatureRule;

impl DetectionRule for InvalidSignatureRule {
    fn id(&self) -> &str {
        "SIGN002"
    }

    fn name(&self) -> &str {
        "Invalid Signature"
    }

    fn description(&self) -> &str {
        "Detects processes with present but invalid digital signatures"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1553.002") // Subvert Trust Controls: Code Signing
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let nodes = engine.build_process_nodes();

        for node in &nodes {
            if let Some(ref sig) = node.signature {
                // Signed but invalid
                if sig.is_signed && !sig.signature_valid {
                    let reason = if sig.certificate_expired {
                        "expired certificate"
                    } else if !sig.certificate_chain_valid {
                        "invalid certificate chain"
                    } else {
                        "invalid signature"
                    };

                    let mut finding = create_finding(
                        self,
                        format!("Invalid signature: {} ({})", node.name, reason),
                        format!(
                            "Process {} (PID:{}) has a digital signature that failed verification: {}. \
                             Signer: {}. This could indicate a tampered binary or malware.",
                            node.name,
                            node.pid,
                            reason,
                            sig.signer.as_deref().unwrap_or("Unknown")
                        ),
                        vec![Evidence {
                            source_plugin: "signature_check".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("{} - {} by {}", node.name, reason, sig.signer.as_deref().unwrap_or("?")),
                        }],
                    );
                    finding.related_pids = vec![node.pid];
                    finding.confidence = 0.88;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
