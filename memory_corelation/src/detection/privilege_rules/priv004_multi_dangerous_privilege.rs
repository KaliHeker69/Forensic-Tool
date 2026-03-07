//! PRIV004 – MultiDangerousPrivilegeRule
use super::priv005_impersonate_privilege_abuse::build_privilege_summaries;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::{is_expected_system_process, PrivilegeInfo, PrivilegeSummary};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::HashMap;

/// Rule for detecting multiple dangerous privileges in a single process
pub struct MultiDangerousPrivilegeRule;

impl DetectionRule for MultiDangerousPrivilegeRule {
    fn id(&self) -> &str {
        "PRIV004"
    }

    fn name(&self) -> &str {
        "Multiple Dangerous Privileges"
    }

    fn description(&self) -> &str {
        "Detects processes with multiple dangerous privileges enabled simultaneously"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        let summaries = build_privilege_summaries(&data.privileges);

        for summary in summaries {
            if is_expected_system_process(&summary.process_name) {
                continue;
            }

            if summary.dangerous_enabled.len() >= 3 {
                let mut finding = create_finding(
                    self,
                    format!("Multiple dangerous privileges in {} (PID {})", summary.process_name, summary.pid),
                    format!(
                        "Process has {} dangerous privileges enabled: {}",
                        summary.dangerous_enabled.len(),
                        summary.dangerous_enabled.join(", ")
                    ),
                    vec![Evidence {
                        source_plugin: "privileges".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Privileges: {}", summary.dangerous_enabled.join(", ")),
                    }],
                );
                finding.related_pids = vec![summary.pid];
                findings.push(finding);
            }
        }

        findings
    }
}
