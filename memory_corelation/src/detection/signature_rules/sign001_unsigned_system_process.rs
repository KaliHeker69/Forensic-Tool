//! SIGN001 – UnsignedSystemProcessRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unsigned system processes
pub struct UnsignedSystemProcessRule;

impl DetectionRule for UnsignedSystemProcessRule {
    fn id(&self) -> &str {
        "SIGN001"
    }

    fn name(&self) -> &str {
        "Unsigned System Process"
    }

    fn description(&self) -> &str {
        "Detects critical Windows system processes that are not digitally signed"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036") // Masquerading
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let nodes = engine.build_process_nodes();

        for node in &nodes {
            if !node.is_critical_system_process() {
                continue;
            }

            // Check if signature info is present and unsigned
            if let Some(ref sig) = node.signature {
                if !sig.is_signed {
                    let mut finding = create_finding(
                        self,
                        format!("Unsigned system process: {}", node.name),
                        format!(
                            "Critical system process {} (PID:{}) is NOT digitally signed. \
                             Legitimate Windows system processes are always signed by Microsoft. \
                             This could indicate malware masquerading as a system process.",
                            node.name, node.pid
                        ),
                        vec![Evidence {
                            source_plugin: "signature_check".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("{} - unsigned", node.name),
                        }],
                    );
                    finding.related_pids = vec![node.pid];
                    finding.confidence = 0.95;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
