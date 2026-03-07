//! SID002 – IntegrityLevelAnomalyRule
use super::sid003_unknown_sid::is_expected_low_integrity_system_process;
use std::collections::HashMap;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::{is_expected_system_process, SidInfo};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect integrity level anomalies (e.g., high-integrity process that should be medium)
pub struct IntegrityLevelAnomalyRule;

impl DetectionRule for IntegrityLevelAnomalyRule {
    fn id(&self) -> &str {
        "SID002"
    }

    fn name(&self) -> &str {
        "Integrity Level Anomaly"
    }

    fn description(&self) -> &str {
        "Detects processes with unexpected integrity levels"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134.002")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group SIDs by PID
        let mut sids_by_pid: HashMap<u32, Vec<&SidInfo>> = HashMap::new();
        for sid in &data.sids {
            sids_by_pid.entry(sid.pid).or_default().push(sid);
        }

        // Processes that should normally run at Medium integrity
        let normally_medium = [
            "notepad.exe",
            "calc.exe",
            "mspaint.exe",
            "wordpad.exe",
            "write.exe",
            "explorer.exe",
        ];

        for (pid, sids) in &sids_by_pid {
            let proc_name = sids.first().map(|s| s.process.as_str()).unwrap_or("unknown");
            let lower_name = proc_name.to_lowercase();

            // Find integrity level SID
            let integrity_sid = sids.iter().find(|s| s.is_integrity_level());
            if let Some(int_sid) = integrity_sid {
                let level = int_sid.integrity_level().unwrap_or("Unknown");

                // Check if a normally-medium process is running at System/High integrity
                if normally_medium.iter().any(|p| lower_name.contains(p))
                    && (level == "System" || level == "High")
                {
                    let mut finding = create_finding(
                        self,
                        format!("{} running at {} integrity (PID {})", proc_name, level, pid),
                        format!(
                            "Process '{}' (PID {}) is running at {} integrity level. \
                            This process normally runs at Medium integrity. \
                            Elevated integrity may indicate privilege escalation.",
                            proc_name, pid, level
                        ),
                        vec![Evidence {
                            source_plugin: "getsids".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "PID:{} Process:{} IntegritySID:{} Level:{}",
                                pid, proc_name, int_sid.sid, level
                            ),
                        }],
                    );
                    finding.related_pids = vec![*pid];
                    finding.confidence = 0.8;
                    findings.push(finding);
                }

                // System processes at low integrity can be suspicious, but some are
                // expected to run low (e.g., fontdrvhost instances).
                if is_expected_system_process(proc_name)
                    && level == "Low"
                    && !is_expected_low_integrity_system_process(proc_name)
                {
                    let mut finding = create_finding(
                        self,
                        format!(
                            "System process {} at Low integrity (PID {})",
                            proc_name, pid
                        ),
                        format!(
                            "System process '{}' (PID {}) is running at Low integrity. \
                            System processes should run at System or High integrity. \
                            This may indicate a sandbox escape or integrity downgrade attack.",
                            proc_name, pid
                        ),
                        vec![Evidence {
                            source_plugin: "getsids".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("PID:{} Process:{} Level:Low", pid, proc_name),
                        }],
                    );
                    finding.related_pids = vec![*pid];
                    finding.severity = Severity::Critical;
                    finding.confidence = 0.90;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
