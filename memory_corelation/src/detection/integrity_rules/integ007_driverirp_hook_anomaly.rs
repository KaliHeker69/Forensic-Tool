//! INTEG007 – DriverIrpHookAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding_with_category, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, FindingCategory, Severity};

/// Detect suspicious IRP dispatch handlers from driverirp output.
pub struct DriverIrpHookAnomalyRule;

impl DetectionRule for DriverIrpHookAnomalyRule {
    fn id(&self) -> &str {
        "INTEG007"
    }

    fn name(&self) -> &str {
        "Driver IRP Dispatch Anomaly"
    }

    fn description(&self) -> &str {
        "Detects IRP handlers with unknown or suspicious owner modules"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for irp in &data.driver_irps {
            if !irp.is_suspicious_handler_owner() {
                continue;
            }

            let owner = irp.module.as_deref().unwrap_or("unknown");
            let symbol = irp.symbol.as_deref().unwrap_or("unknown");

            let mut finding = create_finding_with_category(
                self,
                format!(
                    "Suspicious IRP handler owner for {} ({})",
                    irp.driver_name, irp.irp
                ),
                format!(
                    "Driver '{}' IRP '{}' dispatch points to address {} with owner module '{}' (symbol '{}'). \
                    This can indicate IRP table hooking or handler redirection.",
                    irp.driver_name, irp.irp, irp.address, owner, symbol
                ),
                vec![Evidence {
                    source_plugin: "driverirp".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "Driver:{} IRP:{} Address:{} Owner:{} Symbol:{}",
                        irp.driver_name, irp.irp, irp.address, owner, symbol
                    ),
                }],
                FindingCategory::Rootkit,
            );
            finding.related_files = if owner == "unknown" {
                Vec::new()
            } else {
                vec![owner.to_string()]
            };
            finding.confidence = if owner == "unknown" { 0.85 } else { 0.78 };
            findings.push(finding);
        }

        findings
    }
}
