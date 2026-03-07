//! PROC002 – SuspiciousParentChildRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious parent-child process relationships
pub struct SuspiciousParentChildRule;

impl DetectionRule for SuspiciousParentChildRule {
    fn id(&self) -> &str {
        "PROC002"
    }

    fn name(&self) -> &str {
        "Suspicious Parent-Child Process"
    }

    fn description(&self) -> &str {
        "Detects unusual parent-child process relationships such as Office spawning cmd/PowerShell"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1204.002") // User Execution: Malicious File
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for chain in engine.find_suspicious_parent_child() {
            let finding_severity = if chain.is_encoded {
                Severity::Critical
            } else {
                Severity::High
            };

            let mut finding = create_finding(
                self,
                format!("{} spawned {}", chain.parent.name, chain.child.name),
                format!(
                    "Suspicious process chain detected: {} (PID:{}) spawned {} (PID:{}){}",
                    chain.parent.name,
                    chain.parent.pid,
                    chain.child.name,
                    chain.child.pid,
                    chain
                        .cmdline
                        .as_ref()
                        .map(|c| format!(" with cmdline: {}", c))
                        .unwrap_or_default()
                ),
                vec![Evidence {
                    source_plugin: "pslist+cmdline".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: chain.description(),
                }],
            );
            finding.severity = finding_severity;
            finding.related_pids = vec![chain.parent.pid, chain.child.pid];
            finding.timestamp = chain.child.create_time;
            finding.confidence = if chain.is_encoded { 0.95 } else { 0.85 };
            findings.push(finding);
        }

        findings
    }
}
