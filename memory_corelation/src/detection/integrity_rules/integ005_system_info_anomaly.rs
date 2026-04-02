//! INTEG005 – SystemInfoAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect anomalies in system info plugin output
pub struct SystemInfoAnomalyRule;

impl DetectionRule for SystemInfoAnomalyRule {
    fn id(&self) -> &str {
        "INTEG005"
    }

    fn name(&self) -> &str {
        "System Info Anomaly"
    }

    fn description(&self) -> &str {
        "Detects malformed or missing critical fields in volatility info output"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1497")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.system_info_records.is_empty() {
            return findings;
        }

        let mut has_kernel_base = false;
        let mut has_dtb = false;

        for rec in &data.system_info_records {
            let var = rec
                .get("Variable")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let val = rec
                .get("Value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            if var.contains("kernel base") {
                has_kernel_base = true;
                if val == "0x0" || val == "0" {
                    let mut finding = create_finding(
                        self,
                        "Invalid kernel base in info output".to_string(),
                        "The info plugin reported a null kernel base, which may indicate profile mismatch or tampered metadata.".to_string(),
                        vec![Evidence {
                            source_plugin: "info".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("Variable:{} Value:{}", var, val),
                        }],
                    );
                    finding.confidence = 0.7;
                    findings.push(finding);
                }
            }

            if var == "dtb" {
                has_dtb = true;
            }
        }

        if !has_kernel_base || !has_dtb {
            let mut finding = create_finding(
                self,
                "Incomplete critical system info fields".to_string(),
                "The info plugin output is missing one or more critical fields (Kernel Base, DTB).".to_string(),
                vec![Evidence {
                    source_plugin: "info".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("HasKernelBase:{} HasDTB:{}", has_kernel_base, has_dtb),
                }],
            );
            finding.confidence = 0.6;
            findings.push(finding);
        }

        findings
    }
}
