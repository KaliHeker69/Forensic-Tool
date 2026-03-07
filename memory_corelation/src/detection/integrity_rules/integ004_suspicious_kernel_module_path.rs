//! INTEG004 – SuspiciousKernelModulePathRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious kernel module load paths from modscan/modules/driverscan outputs
pub struct SuspiciousKernelModulePathRule;

impl DetectionRule for SuspiciousKernelModulePathRule {
    fn id(&self) -> &str {
        "INTEG004"
    }

    fn name(&self) -> &str {
        "Suspicious Kernel Module Path"
    }

    fn description(&self) -> &str {
        "Detects kernel modules loaded from non-standard user-writable locations"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1543.003")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for drv in &data.drivers {
            let path = drv.path.as_deref().unwrap_or("");
            if path.is_empty() {
                continue;
            }

            let lower = path.to_lowercase();
            let known_safe = lower.contains("\\microsoft\\windows defender\\")
                || lower.contains("\\windows defender\\definition updates\\")
                || lower.contains("\\systemroot\\system32\\")
                || lower.contains("\\windows\\system32\\");
            if known_safe {
                continue;
            }

            let suspicious = (lower.contains("\\users\\")
                || lower.contains("\\appdata\\")
                || lower.contains("\\temp\\")
                || lower.contains("\\programdata\\")
                || lower.contains("\\$recycle.bin\\"))
                && (lower.ends_with(".sys") || lower.ends_with(".dll"));

            if !suspicious {
                continue;
            }

            let mut finding = create_finding(
                self,
                format!("Kernel module from suspicious path: {}", drv.name),
                format!(
                    "Kernel module '{}' appears loaded from suspicious path '{}'. This may indicate malicious driver/module persistence.",
                    drv.name, path
                ),
                vec![Evidence {
                    source_plugin: "modscan/driverscan/modules".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("Name:{} Path:{}", drv.name, path),
                }],
            );
            finding.related_files = vec![path.to_string()];
            finding.confidence = 0.9;
            findings.push(finding);
        }

        findings
    }
}
