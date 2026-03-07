//! THRD002 – SuspiciousThreadStartRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::threads::ThreadSummary;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::{HashMap, HashSet};

/// Rule for detecting threads with suspicious start addresses
pub struct SuspiciousThreadStartRule;

impl DetectionRule for SuspiciousThreadStartRule {
    fn id(&self) -> &str {
        "THRD002"
    }

    fn name(&self) -> &str {
        "Suspicious Thread Start Address"
    }

    fn description(&self) -> &str {
        "Detects threads with start addresses pointing to unusual or suspicious locations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.003")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let process_pids: HashSet<u32> = data.processes.iter().map(|p| p.pid).collect();

        // Build process name lookup
        let proc_names: HashMap<u32, &str> = data.processes.iter().map(|p| (p.pid, p.name.as_str())).collect();

        // Processes whose threads legitimately start from unusual/unbacked paths
        let thread_exempt_processes = [
            "msmpeng.exe",    // Defender - dynamically generated scanning code
            "mssense.exe",    // Defender ATP
            "nissrv.exe",     // Defender NIS
            "procmon64.exe",  // Sysinternals Process Monitor
            "procmon.exe",
            "procexp64.exe",  // Sysinternals Process Explorer
            "procexp.exe",
        ];

        // Kernel pseudo-processes: these have no user-mode modules, so all threads appear "unbacked"
        let kernel_pseudo_processes = [
            "memcompression", "memory compression", "registry", "system", "secure system",
        ];

        // Group unbacked threads by PID to reduce noise
        let mut unbacked_by_pid: HashMap<u32, Vec<u32>> = HashMap::new();

        for thread in &data.threads {
            // Skip kernel threads (PID 4) - they legitimately have no user-mode start paths
            if thread.pid == 0 || thread.pid == 4 {
                continue;
            }

            // Skip exempt processes
            if let Some(name) = proc_names.get(&thread.pid) {
                let lower_name = name.to_lowercase();
                if thread_exempt_processes.iter().any(|p| lower_name.contains(p)) {
                    continue;
                }
                if kernel_pseudo_processes.iter().any(|p| lower_name.contains(p)) {
                    continue;
                }
            }

            // Check for threads starting from unusual paths
            if thread.has_suspicious_start_path() {
                let mut finding = create_finding(
                    self,
                    format!(
                        "Thread TID {} in PID {} has suspicious start path",
                        thread.tid, thread.pid
                    ),
                    format!(
                        "Thread has unusual start path: {:?} (Win32: {:?}). \
                        This may indicate shellcode injection or unbacked code execution.",
                        thread.start_path, thread.win32_start_path
                    ),
                    vec![Evidence {
                        source_plugin: "thrdscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "TID:{} StartPath:{:?} Win32StartPath:{:?}",
                            thread.tid, thread.start_path, thread.win32_start_path
                        ),
                    }],
                );
                finding.related_pids = vec![thread.pid];

                // Orphaned threads are more critical
                if thread.is_orphaned() {
                    finding.severity = Severity::Critical;
                }

                findings.push(finding);
            } else if thread.is_orphaned() && process_pids.contains(&thread.pid) {
                // Only flag unbacked threads for RUNNING processes (in pslist)
                // Threads from terminated processes commonly lose path info
                unbacked_by_pid
                    .entry(thread.pid)
                    .or_default()
                    .push(thread.tid);
            }
        }

        // Emit aggregated findings for unbacked threads in running processes
        for (pid, tids) in &unbacked_by_pid {
            // Only flag processes with a meaningful number of unbacked threads
            if tids.len() >= 3 {
                let name = proc_names.get(pid).unwrap_or(&"unknown");
                // Skip kernel pseudo-processes for unbacked aggregation too
                let lower_name = name.to_lowercase();
                if kernel_pseudo_processes.iter().any(|p| lower_name.contains(p)) {
                    continue;
                }
                if thread_exempt_processes.iter().any(|p| lower_name.contains(p)) {
                    continue;
                }
                let mut finding = create_finding(
                    self,
                    format!(
                        "{} unbacked threads in {} (PID {})",
                        tids.len(), name, pid
                    ),
                    format!(
                        "Process {} (PID {}) has {} threads with no backing module. \
                        This may indicate injected code.",
                        name, pid, tids.len()
                    ),
                    vec![Evidence {
                        source_plugin: "thrdscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "PID:{} UnbackedTIDs(first 5):{:?} Total:{}",
                            pid,
                            &tids[..tids.len().min(5)],
                            tids.len()
                        ),
                    }],
                );
                finding.related_pids = vec![*pid];
                findings.push(finding);
            }
        }

        findings
    }
}
