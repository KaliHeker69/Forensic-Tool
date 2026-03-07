//! PRIV005 – ImpersonatePrivilegeAbuseRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::{is_expected_system_process, PrivilegeInfo, PrivilegeSummary};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::HashMap;

/// Rule for detecting SeImpersonatePrivilege abuse (Potato attacks)
pub struct ImpersonatePrivilegeAbuseRule;

impl DetectionRule for ImpersonatePrivilegeAbuseRule {
    fn id(&self) -> &str {
        "PRIV005"
    }

    fn name(&self) -> &str {
        "SeImpersonatePrivilege Abuse Detection"
    }

    fn description(&self) -> &str {
        "Detects non-service processes with impersonation capability (Potato attacks)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134.003")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Service accounts that legitimately have this privilege
        let service_processes = [
            "svchost.exe",
            "services.exe",
            "w3wp.exe",
            "sqlservr.exe",
            "iisexpress.exe",
            "wmiprvse.exe",
            "dllhost.exe",
            "msdtc.exe",
            "taskhostw.exe",
            "spoolsv.exe",
            "searchindexer.exe",
            "msiexec.exe",
            "tiworker.exe",
            "trustedinstaller.exe",
            "compattelrunner.exe",
            "wmiapsrv.exe",
            "unsecapp.exe",
            "vboxservice.exe",
            "officeclicktorun.exe",
            "mousocoreworker.exe",
            "audiodg.exe",
            "sgrmbroker.exe",
            "dashost.exe",
            "conhost.exe",
            "runtimebroker.exe",
            "smartscreen.exe",
            "searchprotocolhost.exe",
            "searchfilterhost.exe",
            // Sysinternals and forensic tools
            "procmon64.exe",
            "procmon.exe",
            "procexp64.exe",
            "procexp.exe",
            "magnetramcapture",
            "magnetramcaptu",
            "dumpit.exe",
        ];

        for priv_info in &data.privileges {
            let lower_name = priv_info.process.to_lowercase();
            if is_expected_system_process(&priv_info.process) {
                continue;
            }
            if service_processes.iter().any(|s| lower_name.contains(s) || s.starts_with(&*lower_name) || lower_name.starts_with(s)) {
                continue;
            }

            if priv_info.is_impersonate_privilege() && priv_info.is_enabled() {
                let mut finding = create_finding(
                    self,
                    format!("SeImpersonatePrivilege in {} (PID {})", priv_info.process, priv_info.pid),
                    format!(
                        "Process {} has SeImpersonatePrivilege - potential for Potato-style privilege escalation attacks.",
                        priv_info.process
                    ),
                    vec![Evidence {
                        source_plugin: "privileges".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("PID:{} Process:{} Privilege:SeImpersonatePrivilege", priv_info.pid, priv_info.process),
                    }],
                );
                finding.related_pids = vec![priv_info.pid];
                findings.push(finding);
            }
        }

        findings
    }
}

/// Build privilege summaries per process
pub fn build_privilege_summaries(privileges: &[PrivilegeInfo]) -> Vec<PrivilegeSummary> {
    let mut by_pid: HashMap<u32, Vec<&PrivilegeInfo>> = HashMap::new();
    for priv_info in privileges {
        by_pid.entry(priv_info.pid).or_default().push(priv_info);
    }

    by_pid
        .into_iter()
        .map(|(pid, privs)| {
            let process_name = privs.first().map(|p| p.process.clone()).unwrap_or_default();

            let dangerous_enabled: Vec<String> = privs
                .iter()
                .filter(|p| p.is_dangerous() && p.is_enabled())
                .map(|p| p.privilege.clone())
                .collect();

            let has_debug = privs.iter().any(|p| p.is_debug_privilege() && p.is_enabled());
            let has_tcb = privs.iter().any(|p| p.is_tcb_privilege() && p.is_enabled());
            let has_load_driver = privs.iter().any(|p| p.is_load_driver_privilege() && p.is_enabled());
            let has_impersonate = privs.iter().any(|p| p.is_impersonate_privilege() && p.is_enabled());

            PrivilegeSummary {
                pid,
                process_name,
                total_privileges: privs.len(),
                dangerous_enabled,
                has_debug,
                has_tcb,
                has_load_driver,
                has_impersonate,
                running_as_system: false,
                integrity_level: None,
                risk_score: 0,
            }
        })
        .collect()
}
