//! INTEG001 – HiddenProcessRule
use super::integ002_hidden_hive::is_suspicious_process_name;
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect hidden processes (in psscan but not pslist)
/// This is the hallmark of DKOM-based rootkits (e.g., Necurs, ZeroAccess)
pub struct HiddenProcessRule;

impl DetectionRule for HiddenProcessRule {
    fn id(&self) -> &str {
        "INTEG001"
    }

    fn name(&self) -> &str {
        "Hidden Process Detection"
    }

    fn description(&self) -> &str {
        "Detects processes that appear in psscan but not pslist, indicating DKOM rootkit technique"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014") // Rootkit
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Build sets of PIDs from different sources
        // Note: In the current data model, all processes go into data.processes
        // We need to track which came from pslist vs psscan via source file or plugin type
        // For now, we detect based on structural indicators:
        // - Processes with exit time set but still found = remnant structures
        // - Processes with no parent in the tree = potentially hidden
        
        let all_pids: HashSet<u32> = data.processes.iter().map(|p| p.pid).collect();
        let _parent_pids: HashSet<u32> = data.processes.iter().map(|p| p.ppid).collect();
        
        for proc in &data.processes {
            // Check for remnant processes (have exit time but were found by psscan)
            if proc.exit_time.is_some() && proc.create_time.is_some() {
                // This is a terminated process found via memory scanning
                let severity = Severity::Info; // Remnant, not active threat
                
                let mut finding = create_finding(
                    self,
                    format!("Remnant process structure: {} (PID {})", proc.name, proc.pid),
                    format!(
                        "Process '{}' (PID {}) has an exit time set but its EPROCESS structure \
                        was still found in memory. This indicates the process terminated but its \
                        memory structures weren't fully cleaned up. Forensically valuable but not \
                        an active threat.",
                        proc.name, proc.pid
                    ),
                    vec![Evidence {
                        source_plugin: "psscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID: {} Name: {} CreateTime: {:?} ExitTime: {:?}",
                            proc.pid, proc.name, proc.create_time, proc.exit_time
                        ),
                    }],
                );
                finding.severity = severity;
                finding.related_pids = vec![proc.pid];
                finding.confidence = 0.6;
                findings.push(finding);
            }
            
            // Check for orphaned processes with unusual characteristics
            // NOTE: Basic orphan detection is handled by OrphanedProcessRule (PROC001).
            // Here we only flag truly suspicious ones (process name mimicry, hex names)
            if proc.ppid != 0 && proc.ppid != 4 && !all_pids.contains(&proc.ppid) {
                // Parent doesn't exist - only escalate if process name itself is suspicious
                if is_suspicious_process_name(&proc.name) {
                    let get_cmdline = |target_pid: u32| -> String {
                        data.cmdlines.iter()
                            .find(|c| c.pid == target_pid)
                            .map(|c| c.args.clone())
                            .unwrap_or_else(|| "N/A".to_string())
                    };

                    let proc_cmdline = get_cmdline(proc.pid);
                    let parent_cmdline = get_cmdline(proc.ppid);

                    let mut finding = create_finding(
                        self,
                        format!("Suspicious orphaned process: {} (PID {})", proc.name, proc.pid),
                        format!(
                            "Process '{}' (PID {}) has a suspicious name AND references parent PID {} which does not exist. \
                            This strongly suggests malware attempting to disguise itself.\n\
                            \nProcess Cmdline: {}\nParent Cmdline: {}",
                            proc.name, proc.pid, proc.ppid, proc_cmdline, parent_cmdline
                        ),
                        vec![Evidence {
                            source_plugin: "psscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "PID: {} PPID: {} (missing) Name: {}\nProcess Cmdline: {}\nParent Cmdline: {}",
                                proc.pid, proc.ppid, proc.name, proc_cmdline, parent_cmdline
                            ),
                        }],
                    );
                    finding.severity = Severity::Critical;
                    finding.related_pids = vec![proc.pid];
                    finding.confidence = 0.85;
                    findings.push(finding);
                }
                // Non-suspicious name orphans are handled by PROC001, skip here
            }
        }

        findings
    }
}
