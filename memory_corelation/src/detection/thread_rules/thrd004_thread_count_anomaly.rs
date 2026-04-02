//! THRD004 – ThreadCountAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::threads::ThreadSummary;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::HashMap;

/// Rule for detecting high thread count anomalies
pub struct ThreadCountAnomalyRule;

impl DetectionRule for ThreadCountAnomalyRule {
    fn id(&self) -> &str {
        "THRD004"
    }

    fn name(&self) -> &str {
        "Abnormal Thread Count"
    }

    fn description(&self) -> &str {
        "Detects processes with unusually high or suspicious thread patterns"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build thread summaries
        let summaries = build_thread_summaries(&data.threads, data);

        for summary in summaries {
            // Skip kernel/system processes and known thread-heavy processes from ratio check
            let lower_name = summary.process_name.to_lowercase();
            let exempt_from_ratio = [
                "system", "memcompression", "memory compression", "registry", "secure system",
                "msmpeng.exe", "mssense.exe", "procmon64.exe", "procmon.exe",
                "procexp64.exe", "procexp.exe", "nissrv.exe",
            ];
            if exempt_from_ratio.iter().any(|p| lower_name.contains(p)) {
                continue;
            }

            // High percentage of suspicious threads
            if summary.total_threads > 5 {
                let suspicious_count = summary.suspicious_path_threads + summary.orphaned_threads;
                let suspicious_pct =
                    (suspicious_count as f32 / summary.total_threads as f32) * 100.0;
                if suspicious_pct > 20.0 {
                    let mut finding = create_finding(
                        self,
                        format!(
                            "Process {} has high ratio of suspicious threads",
                            summary.process_name
                        ),
                        format!(
                            "{:.0}% of threads ({}/{}) in {} (PID {}) have suspicious characteristics.",
                            suspicious_pct,
                            suspicious_count,
                            summary.total_threads,
                            summary.process_name,
                            summary.pid
                        ),
                        vec![Evidence {
                            source_plugin: "thrdscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "TotalThreads:{} Suspicious:{}",
                                summary.total_threads, suspicious_count
                            ),
                        }],
                    );
                    finding.severity = Severity::High;
                    finding.related_pids = vec![summary.pid];
                    findings.push(finding);
                }
            }

            // Unusually high thread count for non-service process
            if summary.total_threads > 500
                && !is_expected_high_thread_process(&summary.process_name)
            {
                let mut finding = create_finding(
                    self,
                    format!("Abnormally high thread count in {}", summary.process_name),
                    format!(
                        "Process {} (PID {}) has {} threads, which is unusually high.",
                        summary.process_name, summary.pid, summary.total_threads
                    ),
                    vec![Evidence {
                        source_plugin: "thrdscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("ThreadCount:{}", summary.total_threads),
                    }],
                );
                finding.related_pids = vec![summary.pid];
                findings.push(finding);
            }
        }

        findings
    }
}

/// Build thread summaries for analysis
fn build_thread_summaries(
    threads: &[crate::models::threads::ThreadInfo],
    data: &ParsedData,
) -> Vec<ThreadSummary> {
    let mut by_pid: HashMap<u32, Vec<&crate::models::threads::ThreadInfo>> = HashMap::new();
    for thread in threads {
        by_pid.entry(thread.pid).or_default().push(thread);
    }

    // ProcessInfo.name is String, pid is u32
    let proc_names: HashMap<u32, String> =
        data.processes.iter().map(|p| (p.pid, p.name.clone())).collect();

    by_pid
        .into_iter()
        .map(|(pid, threads)| {
            let suspicious_path_count = threads
                .iter()
                .filter(|t| t.has_suspicious_start_path())
                .count();

            let orphaned_count = threads.iter().filter(|t| t.is_orphaned()).count();

            let suspicious_tids: Vec<u32> = threads
                .iter()
                .filter(|t| t.has_suspicious_start_path() || t.is_orphaned())
                .map(|t| t.tid)
                .collect();

            ThreadSummary {
                pid,
                process_name: proc_names.get(&pid).cloned().unwrap_or_default(),
                total_threads: threads.len(),
                active_threads: threads.iter().filter(|t| t.is_active()).count(),
                orphaned_threads: orphaned_count,
                suspicious_path_threads: suspicious_path_count,
                threads_in_suspicious_regions: suspicious_tids,
                risk_score: 0,
            }
        })
        .collect()
}

/// Check if process is expected to have high thread count
fn is_expected_high_thread_process(name: &str) -> bool {
    let high_thread_procs = [
        "svchost.exe",
        "system",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "sqlservr.exe",
        "w3wp.exe",
        "java.exe",
        "javaw.exe",
        "node.exe",
    ];

    let lower = name.to_lowercase();
    high_thread_procs.iter().any(|p| lower.contains(p))
}
