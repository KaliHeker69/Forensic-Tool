//! SID001 – UnexpectedSystemSidRule
use std::collections::HashMap;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::{is_expected_system_process, SidInfo};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect non-system processes running with SYSTEM SID
pub struct UnexpectedSystemSidRule;

impl DetectionRule for UnexpectedSystemSidRule {
    fn id(&self) -> &str {
        "SID001"
    }

    fn name(&self) -> &str {
        "Unexpected SYSTEM SID"
    }

    fn description(&self) -> &str {
        "Detects processes running as SYSTEM that typically should not"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group SIDs by PID
        let mut sids_by_pid: HashMap<u32, Vec<&SidInfo>> = HashMap::new();
        for sid in &data.sids {
            sids_by_pid.entry(sid.pid).or_default().push(sid);
        }

        for (pid, sids) in &sids_by_pid {
            let proc_name = sids.first().map(|s| s.process.as_str()).unwrap_or("unknown");

            // Skip expected system processes
            if is_expected_system_process(proc_name) {
                continue;
            }

            // Check if process has SYSTEM SID
            let has_system = sids.iter().any(|s| s.is_system());
            if has_system {
                // User-facing processes running as SYSTEM are suspicious
                let lower = proc_name.to_lowercase();
                let is_user_proc = lower.contains("notepad")
                    || lower.contains("calc")
                    || lower.contains("mspaint")
                    || lower.contains("cmd.exe")
                    || lower.contains("powershell")
                    || lower.contains("explorer")
                    || lower.contains("wordpad")
                    || lower.contains("write.exe");

                if is_user_proc {
                    let mut finding = create_finding(
                        self,
                        format!("{} (PID {}) running as SYSTEM", proc_name, pid),
                        format!(
                            "User-facing process '{}' (PID {}) is running with SYSTEM SID. \
                            This is unusual and may indicate privilege escalation or token manipulation.",
                            proc_name, pid
                        ),
                        vec![Evidence {
                            source_plugin: "getsids".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("PID:{} Process:{} SID:S-1-5-18 (SYSTEM)", pid, proc_name),
                        }],
                    );
                    finding.related_pids = vec![*pid];
                    finding.confidence = 0.88;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
