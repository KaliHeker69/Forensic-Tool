//! XCOR004 – HiddenProcessCrossCheckRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Compare psscan and pslist results. Processes in psscan but not pslist
/// are hidden via DKOM – the hallmark of rootkit activity.
pub struct HiddenProcessCrossCheckRule;

impl DetectionRule for HiddenProcessCrossCheckRule {
    fn id(&self) -> &str {
        "XCOR004"
    }

    fn name(&self) -> &str {
        "DKOM Hidden Process (psscan vs pslist)"
    }

    fn description(&self) -> &str {
        "Detects processes visible in psscan (memory scan) but missing from pslist (kernel linked list)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Need both sources to compare
        if data.pslist_processes.is_empty() || data.psscan_processes.is_empty() {
            return findings;
        }

        let pslist_pids: HashSet<u32> = data.pslist_processes.iter().map(|p| p.pid).collect();

        for proc in &data.psscan_processes {
            // Skip PID 0 (Idle) — always shows anomalies
            if proc.pid == 0 {
                continue;
            }

            // Process in psscan but NOT in pslist = potentially hidden
            if !pslist_pids.contains(&proc.pid) {
                // Terminated processes (with exit time) are expected in psscan but not pslist
                if proc.exit_time.is_some() {
                    continue;
                }

                let mut finding = create_finding(
                    self,
                    format!(
                        "DKOM hidden process: {} (PID {})",
                        proc.name, proc.pid
                    ),
                    format!(
                        "Process '{}' (PID {}, PPID {}) was found by psscan (memory scanning) \
                        but is NOT in pslist (kernel linked list). This is the hallmark \
                        of Direct Kernel Object Manipulation (DKOM) rootkit activity.",
                        proc.name, proc.pid, proc.ppid
                    ),
                    vec![Evidence {
                        source_plugin: "psscan vs pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID:{} Name:{} PPID:{} CreateTime:{:?}",
                            proc.pid, proc.name, proc.ppid, proc.create_time
                        ),
                    }],
                );
                finding.related_pids = vec![proc.pid];
                finding.confidence = 0.92;
                findings.push(finding);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR005: Hidden Registry Hive (hivescan vs hivelist)
// ---------------------------------------------------------------------------
