//! PRIV003 – LoadDriverPrivilegeAbuseRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::is_expected_system_process;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting SeLoadDriverPrivilege abuse
pub struct LoadDriverPrivilegeAbuseRule;

impl DetectionRule for LoadDriverPrivilegeAbuseRule {
    fn id(&self) -> &str {
        "PRIV003"
    }

    fn name(&self) -> &str {
        "SeLoadDriverPrivilege Abuse Detection"
    }

    fn description(&self) -> &str {
        "Detects unexpected processes with driver loading capability"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1543.003")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for priv_info in &data.privileges {
            if is_expected_system_process(&priv_info.process) {
                continue;
            }

            if priv_info.is_load_driver_privilege() && priv_info.is_enabled() {
                let mut finding = create_finding(
                    self,
                    format!("SeLoadDriverPrivilege enabled for {} (PID {})", priv_info.process, priv_info.pid),
                    format!(
                        "Process {} can load kernel drivers - this could be used to load malicious drivers.",
                        priv_info.process
                    ),
                    vec![Evidence {
                        source_plugin: "privileges".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("PID:{} Process:{} Privilege:SeLoadDriverPrivilege", priv_info.pid, priv_info.process),
                    }],
                );
                finding.related_pids = vec![priv_info.pid];
                findings.push(finding);
            }
        }

        findings
    }
}
