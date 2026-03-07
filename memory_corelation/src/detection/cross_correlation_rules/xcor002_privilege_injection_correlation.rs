//! XCOR002 – PrivilegeInjectionCorrelationRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect processes that have dangerous privileges AND show injection indicators.
/// A process with SeDebugPrivilege that also has malfind hits in other processes
/// is very likely a credential dumper or injection tool.
pub struct PrivilegeInjectionCorrelationRule;

impl DetectionRule for PrivilegeInjectionCorrelationRule {
    fn id(&self) -> &str {
        "XCOR002"
    }

    fn name(&self) -> &str {
        "Privileged Process with Injection Activity"
    }

    fn description(&self) -> &str {
        "Detects processes with dangerous privileges that also show code injection indicators"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // PIDs with dangerous privileges enabled (excluding expected system procs)
        let mut dangerous_priv_pids: HashMap<u32, Vec<String>> = HashMap::new();
        for priv_info in &data.privileges {
            if crate::models::security::is_expected_system_process(&priv_info.process) {
                continue;
            }
            if priv_info.is_dangerous() && priv_info.is_enabled() {
                dangerous_priv_pids
                    .entry(priv_info.pid)
                    .or_default()
                    .push(priv_info.privilege.clone());
            }
        }

        // PIDs with malfind hits
        let malfind_pids: HashSet<u32> = data.malfind.iter().map(|m| m.pid).collect();

        // Process names
        let proc_names: HashMap<u32, &str> = data
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        // Find overlap: processes with both dangerous privileges AND malfind hits
        for (pid, privs) in &dangerous_priv_pids {
            if malfind_pids.contains(pid) {
                let proc_name = proc_names.get(pid).copied().unwrap_or("unknown");
                let malfind_count = data.malfind.iter().filter(|m| m.pid == *pid).count();

                let mut finding = create_finding(
                    self,
                    format!(
                        "{} (PID {}) has dangerous privileges + injection indicators",
                        proc_name, pid
                    ),
                    format!(
                        "Process {} (PID {}) has {} dangerous privilege(s) ({}) AND \
                        {} malfind hit(s). This combination strongly suggests a malicious \
                        tool performing credential theft or process injection.",
                        proc_name, pid, privs.len(), privs.join(", "),
                        malfind_count
                    ),
                    vec![Evidence {
                        source_plugin: "privileges+malfind".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "Privileges:{} MalfindHits:{}",
                            privs.join(","),
                            malfind_count
                        ),
                    }],
                );
                finding.related_pids = vec![*pid];
                finding.confidence = 0.92;
                findings.push(finding);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR003: Network + Privilege Cross-Reference
// ---------------------------------------------------------------------------
