//! INJ004 – ProcessInjectionCmdlineRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect process injection tools via command line patterns
/// This catches tools like inject.x64.exe, VirtualAllocEx wrappers, etc.
pub struct ProcessInjectionCmdlineRule;

impl DetectionRule for ProcessInjectionCmdlineRule {
    fn id(&self) -> &str {
        "INJ004"
    }

    fn name(&self) -> &str {
        "Process Injection Tool Detection"
    }

    fn description(&self) -> &str {
        "Detects known injection tools and injection-related command line patterns"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055") // Process Injection
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Known injection tool names (process names)
        let injection_tools = [
            "inject.x64", "inject.x86", "inject64", "inject32",
            "reflective", "shellcode_inject", "process_inject",
            "hollower", "processhollowing", "runpe",
            "donut", "sRDI", "shinject",
        ];

        // Suspicious cmdline patterns that indicate injection activity
        let injection_cmdline_patterns = [
            "createremotethread",
            "virtualalloc",
            "writeprocessmemory",
            "ntcreatethreadex",
            "rtlcreateuserthread",
            "queueuserapc",
            "setthreadcontext",
            "zwunmapviewofsection",
            "-inject",
            "/inject",
            "--pid",
            "reflective",
            "shellcode",
            "hollow",
        ];

        // Build a set of sensitive PIDs (lsass, csrss, winlogon etc.)
        let sensitive_pids: HashSet<u32> = data.processes.iter()
            .filter(|p| {
                let lower = p.name.to_lowercase();
                lower == "lsass.exe" || lower == "csrss.exe" || lower == "winlogon.exe"
                    || lower == "services.exe" || lower == "smss.exe"
            })
            .map(|p| p.pid)
            .collect();

        // Build PID->name map
        let pid_names: std::collections::HashMap<u32, &str> = data.processes.iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        for cmd in &data.cmdlines {
            let args_lower = cmd.args.to_lowercase();
            let proc_lower = cmd.process.to_lowercase();

            // Check 1: Known injection tool process names
            let is_injection_tool = injection_tools.iter().any(|t| proc_lower.contains(t));

            // Check 2: Injection-related command line patterns
            let has_injection_pattern = injection_cmdline_patterns.iter()
                .any(|p| args_lower.contains(p));

            if !is_injection_tool && !has_injection_pattern {
                continue;
            }

            // Try to extract target PID from cmdline (e.g., "inject.x64.exe 708")
            let target_pid = extract_target_pid(&cmd.args);
            let target_name = target_pid
                .and_then(|pid| pid_names.get(&pid))
                .map(|n| n.to_string());

            let targets_sensitive = target_pid
                .map(|pid| sensitive_pids.contains(&pid))
                .unwrap_or(false);

            let severity = if targets_sensitive {
                Severity::Critical
            } else if is_injection_tool {
                Severity::Critical
            } else {
                Severity::High
            };

            let target_desc = match (&target_name, target_pid) {
                (Some(name), Some(pid)) => format!(" targeting {} (PID:{})", name, pid),
                (None, Some(pid)) => format!(" targeting PID:{}", pid),
                _ => String::new(),
            };

            let mut finding = create_finding(
                self,
                format!("Injection tool detected: {} (PID:{}){}", cmd.process, cmd.pid, target_desc),
                format!(
                    "Process '{}' (PID {}) appears to be a process injection tool{}. \
                    Command line: '{}'. \
                    This indicates active code injection activity.",
                    cmd.process, cmd.pid, target_desc, cmd.args
                ),
                vec![
                    Evidence {
                        source_plugin: "cmdline".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Process: {} PID: {} Args: {}", cmd.process, cmd.pid, cmd.args),
                    },
                ],
            );
            finding.severity = severity;
            finding.related_pids = {
                let mut pids = vec![cmd.pid];
                if let Some(tp) = target_pid {
                    pids.push(tp);
                }
                pids
            };
            finding.confidence = if is_injection_tool { 0.95 } else { 0.80 };
            findings.push(finding);
        }

        // Also check process names directly (even without cmdline)
        for proc in &data.processes {
            let proc_lower = proc.name.to_lowercase();
            if injection_tools.iter().any(|t| proc_lower.contains(t)) {
                // Check if we already created a finding for this PID via cmdline
                if findings.iter().any(|f| f.related_pids.contains(&proc.pid)) {
                    continue;
                }

                let mut finding = create_finding(
                    self,
                    format!("Injection tool process: {} (PID:{})", proc.name, proc.pid),
                    format!(
                        "Process '{}' (PID {}) has a name matching known injection tools. \
                        PPID: {}. Created: {}",
                        proc.name, proc.pid, proc.ppid,
                        proc.create_time.map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or("Unknown".to_string())
                    ),
                    vec![Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Process: {} PID: {} PPID: {}", proc.name, proc.pid, proc.ppid),
                    }],
                );
                finding.severity = Severity::Critical;
                finding.related_pids = vec![proc.pid];
                finding.confidence = 0.90;
                findings.push(finding);
            }
        }

        findings
    }
}

/// Try to extract a target PID from command line arguments
/// Handles patterns like: "inject.x64.exe 708", "tool.exe -pid 708", "tool.exe --pid=708"
fn extract_target_pid(args: &str) -> Option<u32> {
    let parts: Vec<&str> = args.split_whitespace().collect();

    for (i, part) in parts.iter().enumerate() {
        // Check "-pid 708" or "--pid 708"
        if (*part == "-pid" || *part == "--pid" || *part == "-p") && i + 1 < parts.len() {
            if let Ok(pid) = parts[i + 1].parse::<u32>() {
                return Some(pid);
            }
        }
        // Check "--pid=708"
        if let Some(val) = part.strip_prefix("--pid=").or_else(|| part.strip_prefix("-pid=")) {
            if let Ok(pid) = val.parse::<u32>() {
                return Some(pid);
            }
        }
    }

    // Fallback: if the last argument is a bare number (like "inject.x64.exe 708")
    if parts.len() >= 2 {
        if let Ok(pid) = parts.last().unwrap().parse::<u32>() {
            if pid > 0 && pid < 100000 {
                return Some(pid);
            }
        }
    }

    None
}
