//! THRD001 – OrphanedThreadRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::{HashMap, HashSet};

/// Rule for detecting orphaned threads (threads without valid parent process)
pub struct OrphanedThreadRule;

impl DetectionRule for OrphanedThreadRule {
    fn id(&self) -> &str {
        "THRD001"
    }

    fn name(&self) -> &str {
        "Orphaned Thread Detection"
    }

    fn description(&self) -> &str {
        "Detects threads that have no associated parent process, which can indicate process hollowing or injection"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.012")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let process_pids: HashSet<u32> = data.processes.iter().map(|p| p.pid).collect();
        // PIDs found via psscan but NOT in pslist (terminated processes still in memory)
        let psscan_pids: HashSet<u32> = data.psscan_processes.iter().map(|p| p.pid).collect();

        // Group orphaned threads by PID to avoid thousands of individual findings
        let mut orphan_by_pid: HashMap<u32, Vec<u32>> = HashMap::new();

        for thread in &data.threads {
            // PID 4 (System) and PID 0 (Idle) are kernel-level and may not appear in pslist/psscan
            if thread.pid == 0 || thread.pid == 4 {
                continue;
            }

            if !process_pids.contains(&thread.pid) {
                orphan_by_pid
                    .entry(thread.pid)
                    .or_default()
                    .push(thread.tid);
            }
        }

        for (pid, tids) in &orphan_by_pid {
            let in_psscan = psscan_pids.contains(pid);

            // If the PID is in psscan, it's a terminated process — much lower severity
            if in_psscan {
                // Only report if there are many orphaned threads (could be interesting)
                if tids.len() >= 5 {
                    let mut finding = create_finding(
                        self,
                        format!(
                            "{} orphaned threads for terminated PID {} (in psscan)",
                            tids.len(), pid
                        ),
                        format!(
                            "PID {} has {} threads in memory but the process has terminated \
                            (found in psscan but not pslist). This is normal for recently exited processes.",
                            pid, tids.len()
                        ),
                        vec![Evidence {
                            source_plugin: "thrdscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "PID:{} TIDs(first 5):{:?} Total:{}",
                                pid,
                                &tids[..tids.len().min(5)],
                                tids.len()
                            ),
                        }],
                    );
                    finding.related_pids = vec![*pid];
                    finding.severity = Severity::Low;
                    finding.confidence = 0.3;
                    findings.push(finding);
                }
            } else {
                // PID not in pslist OR psscan — truly suspicious
                let mut finding = create_finding(
                    self,
                    format!(
                        "{} orphaned threads for non-existent PID {} (not in pslist or psscan)",
                        tids.len(), pid
                    ),
                    format!(
                        "PID {} has {} threads but does not exist in pslist or psscan. \
                        This may indicate DKOM manipulation or advanced process hiding.",
                        pid, tids.len()
                    ),
                    vec![Evidence {
                        source_plugin: "thrdscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID:{} TIDs(first 5):{:?} Total:{}",
                            pid,
                            &tids[..tids.len().min(5)],
                            tids.len()
                        ),
                    }],
                );
                finding.related_pids = vec![*pid];
                finding.confidence = 0.9;
                findings.push(finding);
            }
        }

        findings
    }
}
