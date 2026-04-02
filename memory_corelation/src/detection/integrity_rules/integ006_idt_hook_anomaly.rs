//! INTEG006 – IdtHookAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding_with_category, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, FindingCategory, Severity};

/// Detect suspicious IDT handlers resolving outside expected core kernel modules.
pub struct IdtHookAnomalyRule;

impl DetectionRule for IdtHookAnomalyRule {
    fn id(&self) -> &str {
        "INTEG006"
    }

    fn name(&self) -> &str {
        "IDT Hook Anomaly"
    }

    fn description(&self) -> &str {
        "Detects IDT entries whose handlers resolve outside expected core kernel modules"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for entry in &data.idt_entries {
            if !entry.is_suspicious_owner() {
                continue;
            }

            let module = entry.module.as_deref().unwrap_or("unknown");
            let symbol = entry.symbol.as_deref().unwrap_or("unknown");
            let idx = entry.index.as_deref().unwrap_or("?");

            let mut finding = create_finding_with_category(
                self,
                format!("Suspicious IDT handler ownership (vector {})", idx),
                format!(
                    "IDT vector {} points to address {} owned by module '{}' (symbol '{}'). \
                    This is inconsistent with expected kernel handler ownership and may indicate IDT hooking.",
                    idx, entry.address, module, symbol
                ),
                vec![Evidence {
                    source_plugin: "idt".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "Vector:{} Address:{} Module:{} Symbol:{}",
                        idx, entry.address, module, symbol
                    ),
                }],
                FindingCategory::Rootkit,
            );

            finding.confidence = if module.eq_ignore_ascii_case("unknown") {
                0.95
            } else {
                0.90
            };
            findings.push(finding);
        }

        findings
    }
}
