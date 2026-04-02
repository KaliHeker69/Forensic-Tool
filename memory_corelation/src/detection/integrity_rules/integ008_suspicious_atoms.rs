//! INTEG008 – SuspiciousAtomPatternRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding_with_category, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, FindingCategory, Severity};

/// Detect suspicious atom names commonly used in injection/message-hook tradecraft.
pub struct SuspiciousAtomPatternRule;

impl DetectionRule for SuspiciousAtomPatternRule {
    fn id(&self) -> &str {
        "INTEG008"
    }

    fn name(&self) -> &str {
        "Suspicious Atom Pattern"
    }

    fn description(&self) -> &str {
        "Detects suspicious atom table entries associated with injection/message-hook abuse"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for atom in &data.atoms {
            if !atom.is_suspicious_name() {
                continue;
            }

            let atom_owner = atom.process.as_deref().unwrap_or("unknown");
            let mut finding = create_finding_with_category(
                self,
                format!("Suspicious atom value detected: {}", atom.atom),
                format!(
                    "Atom entry '{}' matches suspicious naming/entropy heuristics used in message-hook and staged injection workflows.",
                    atom.atom
                ),
                vec![Evidence {
                    source_plugin: "atoms".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "Atom:{} PID:{:?} Owner:{} RefCount:{:?}",
                        atom.atom, atom.pid, atom_owner, atom.ref_count
                    ),
                }],
                FindingCategory::Injection,
            );

            if let Some(pid) = atom.pid {
                finding.related_pids = vec![pid];
            }
            finding.confidence = 0.65;
            findings.push(finding);
        }

        findings
    }
}
