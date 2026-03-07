//! PROC007 – SuspiciousParentRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::process::ProcessNode;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious parent-child process relationships
/// Focuses on critical Windows system processes that have strict parent requirements
pub struct SuspiciousParentRule;

impl DetectionRule for SuspiciousParentRule {
    fn id(&self) -> &str {
        "PROC007"
    }

    fn name(&self) -> &str {
        "Suspicious Parent Process"
    }

    fn description(&self) -> &str {
        "Detects system processes spawned by unexpected parents (e.g., lsass.exe not from wininit.exe)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055") // Process Injection
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let process_nodes = engine.build_process_nodes();

        for node in &process_nodes {
            // Only check processes that have strict parent requirements
            if node.expected_parent().is_some() && !node.has_legitimate_parent() {
                let expected = node.expected_parent().unwrap_or("unknown");
                
                let fallback = format!("PID {}", node.parent_pid);
                let actual_parent = node
                    .parent_name
                    .as_deref()
                    .unwrap_or(&fallback);

                let mut finding = create_finding(
                    self,
                    format!(
                        "{} spawned by unexpected parent: {}",
                        node.name, actual_parent
                    ),
                    format!(
                        "{} (PID:{}) has suspicious parent. Expected: {}, Actual: {} (PPID:{}). \
                         This could indicate process hollowing, injection, or malware masquerading.",
                        node.name,
                        node.pid,
                        expected,
                        actual_parent,
                        node.parent_pid
                    ),
                    vec![Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "{} (PID:{}) -> Parent: {} (PPID:{})",
                            node.name, node.pid, actual_parent, node.parent_pid
                        ),
                    }],
                );

                finding.related_pids = vec![node.pid, node.parent_pid];
                finding.timestamp = node.create_time;
                finding.confidence = 0.95;
                findings.push(finding);
            }
        }

        findings
    }
}
