//! PRIV001 – DebugPrivilegeAbuseRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::{is_expected_system_process, PrivilegeInfo, PrivilegeSummary};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::HashMap;

/// Rule for detecting SeDebugPrivilege in unexpected processes
pub struct DebugPrivilegeAbuseRule;

impl DetectionRule for DebugPrivilegeAbuseRule {
    fn id(&self) -> &str {
        "PRIV001"
    }

    fn name(&self) -> &str {
        "SeDebugPrivilege Abuse Detection"
    }

    fn description(&self) -> &str {
        "Detects processes with SeDebugPrivilege enabled that don't normally require it"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134.001")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group privileges by PID
        let mut by_pid: HashMap<u32, Vec<&PrivilegeInfo>> = HashMap::new();
        for priv_info in &data.privileges {
            by_pid.entry(priv_info.pid).or_default().push(priv_info);
        }

        for (pid, privs) in by_pid {
            let proc_name = privs.first().map(|p| p.process.as_str()).unwrap_or("unknown");

            if is_expected_system_process(proc_name) {
                continue;
            }

            for priv_info in &privs {
                if priv_info.is_debug_privilege() && priv_info.is_enabled() {
                    let mut finding = create_finding(
                        self,
                        format!("SeDebugPrivilege enabled for {} (PID {})", proc_name, pid),
                        format!(
                            "Process {} has SeDebugPrivilege ENABLED - this allows reading/writing \
                            other process memory and is commonly abused for credential theft.",
                            proc_name
                        ),
                        vec![Evidence {
                            source_plugin: "privileges".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("PID:{} Process:{} Privilege:SeDebugPrivilege Attributes:{}", 
                                pid, proc_name, priv_info.attributes),
                        }],
                    );
                    finding.related_pids = vec![pid];
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
