//! PRIV002 – TcbPrivilegeAbuseRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::is_expected_system_process;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting SeTcbPrivilege abuse
pub struct TcbPrivilegeAbuseRule;

impl DetectionRule for TcbPrivilegeAbuseRule {
    fn id(&self) -> &str {
        "PRIV002"
    }

    fn name(&self) -> &str {
        "SeTcbPrivilege Abuse Detection"
    }

    fn description(&self) -> &str {
        "Detects processes with Act as Part of Operating System privilege"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134.002")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for priv_info in &data.privileges {
            if is_expected_system_process(&priv_info.process) {
                continue;
            }

            if priv_info.is_tcb_privilege() && priv_info.is_enabled() {
                let mut finding = create_finding(
                    self,
                    format!("SeTcbPrivilege enabled for {} (PID {})", priv_info.process, priv_info.pid),
                    format!(
                        "Process {} has SeTcbPrivilege (Act as Part of Operating System) ENABLED - \
                        this is extremely dangerous and allows complete system control.",
                        priv_info.process
                    ),
                    vec![Evidence {
                        source_plugin: "privileges".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("PID:{} Process:{} Privilege:SeTcbPrivilege", priv_info.pid, priv_info.process),
                    }],
                );
                finding.related_pids = vec![priv_info.pid];
                findings.push(finding);
            }
        }

        findings
    }
}
