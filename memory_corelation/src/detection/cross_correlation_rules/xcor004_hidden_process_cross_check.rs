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

        let psxview_by_pid: HashMap<u32, &crate::models::process::PsXViewEntry> = data
            .psxview_entries
            .iter()
            .map(|entry| (entry.pid, entry))
            .collect();

        // Fallback mode: if pslist/psscan are unavailable, still surface psxview-hidden entries.
        if data.pslist_processes.is_empty() || data.psscan_processes.is_empty() {
            for entry in &data.psxview_entries {
                if entry.pid == 0 || !entry.is_likely_hidden() {
                    continue;
                }

                let process_name = if entry.process.trim().is_empty() {
                    "unknown".to_string()
                } else {
                    entry.process.clone()
                };
                let hidden_votes = entry.hidden_votes();

                let mut finding = create_finding(
                    self,
                    format!(
                        "Potential hidden process (psxview): {} (PID {})",
                        process_name, entry.pid
                    ),
                    format!(
                        "Process '{}' (PID {}) appears hidden in psxview integrity checks. \
                        Hidden votes: {} across process enumeration methods.",
                        process_name, entry.pid, hidden_votes
                    ),
                    vec![Evidence {
                        source_plugin: "psxview".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID:{} Name:{} pslist:{:?} psscan:{:?} hidden_votes:{}",
                            entry.pid,
                            process_name,
                            entry.in_pslist,
                            entry.in_psscan,
                            hidden_votes
                        ),
                    }],
                );
                finding.related_pids = vec![entry.pid];
                finding.confidence = (0.82 + (hidden_votes as f32 * 0.03)).min(0.95);
                findings.push(finding);
            }

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

                let mut source_plugin = "psscan vs pslist".to_string();
                let mut confidence = 0.92;
                let mut detail_suffix = String::new();

                if let Some(psx) = psxview_by_pid.get(&proc.pid) {
                    source_plugin.push_str(" + psxview");

                    let hidden_votes = psx.hidden_votes();
                    if psx.is_likely_hidden() {
                        confidence = 0.97;
                    } else if hidden_votes > 0 {
                        confidence = 0.94;
                    }

                    detail_suffix = format!(
                        " psxview hidden votes: {} (pslist:{:?}, psscan:{:?}).",
                        hidden_votes,
                        psx.in_pslist,
                        psx.in_psscan
                    );
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
                        of Direct Kernel Object Manipulation (DKOM) rootkit activity.{}",
                        proc.name, proc.pid, proc.ppid, detail_suffix
                    ),
                    vec![Evidence {
                        source_plugin,
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID:{} Name:{} PPID:{} CreateTime:{:?}",
                            proc.pid, proc.name, proc.ppid, proc.create_time
                        ),
                    }],
                );
                finding.related_pids = vec![proc.pid];
                finding.confidence = confidence;
                findings.push(finding);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR005: Hidden Registry Hive (hivescan vs hivelist)
// ---------------------------------------------------------------------------
