//! THRD003 – SystemProcessThreadAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::threads::ThreadSummary;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};
use std::collections::{HashMap, HashSet};

/// Rule for detecting threads in system processes that shouldn't have user-mode threads
pub struct SystemProcessThreadAnomalyRule;

impl DetectionRule for SystemProcessThreadAnomalyRule {
    fn id(&self) -> &str {
        "THRD003"
    }

    fn name(&self) -> &str {
        "System Process Thread Anomaly"
    }

    fn description(&self) -> &str {
        "Detects unusual thread activity in critical system processes"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.012")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get system process PIDs - ProcessInfo.name is String, pid is u32
        let system_procs: HashMap<u32, &str> = data
            .processes
            .iter()
            .filter_map(|p| {
                let lower = p.name.to_lowercase();
                if matches!(
                    lower.as_str(),
                    "system" | "smss.exe" | "csrss.exe" | "lsass.exe" | "services.exe"
                ) {
                    Some((p.pid, p.name.as_str()))
                } else {
                    None
                }
            })
            .collect();

        // Expanded whitelist of legitimate system DLLs
        let system_dlls = [
            "ntdll", "kernel32", "kernelbase", "ntoskrnl",
            "lsasrv", "crypt32", "samlib", "kerberos", "msv1_0",
            "sechost", "rpcrt4", "advapi32", "combase", "bcrypt",
            "ucrtbase", "msvcrt", "user32", "gdi32", "ole32",
            "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
            "cryptdll", "samsrv", "netlogon", "winsrv", "basesrv",
            "csrsrv", "win32k", "ci.dll", "clfs", "umppc",
            "ncrypt", "dpapi", "sspicli", "secur32", "nsi",
            "ws2_32", "mswsock", "dnsapi", "iphlpapi",
            "wintrust", "rsaenh", "cryptsp", "cryptbase",
        ];

        for thread in &data.threads {
            if let Some(&proc_name) = system_procs.get(&thread.pid) {
                if let Some(ref start_path) = thread.start_path {
                    let lower = start_path.to_lowercase();
                    // System process threads should point to known system DLLs
                    if !system_dlls.iter().any(|dll| lower.contains(dll))
                        && !lower.contains("\\windows\\system32\\")
                        && !lower.contains("\\windows\\syswow64\\")
                        && !lower.is_empty()
                    {
                        let mut finding = create_finding(
                            self,
                            format!(
                                "System process {} has thread with unusual start path",
                                proc_name
                            ),
                            format!(
                                "Critical system process {} (PID {}) has thread TID {} with \
                                unusual start path: {}. This is highly suspicious.",
                                proc_name, thread.pid, thread.tid, start_path
                            ),
                            vec![Evidence {
                                source_plugin: "thrdscan".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!(
                                    "Process:{} TID:{} StartPath:{}",
                                    proc_name, thread.tid, start_path
                                ),
                            }],
                        );
                        finding.related_pids = vec![thread.pid];
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }
}
