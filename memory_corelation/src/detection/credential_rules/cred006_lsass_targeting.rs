//! CRED006 – LsassTargetingRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect processes that target lsass.exe via command line arguments
/// This catches injection/dumping tools that specify lsass PID or name
pub struct LsassTargetingRule;

impl DetectionRule for LsassTargetingRule {
    fn id(&self) -> &str {
        "CRED006"
    }

    fn name(&self) -> &str {
        "LSASS Targeting Detection"
    }

    fn description(&self) -> &str {
        "Detects processes that reference lsass.exe PID or name in their command line"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1003.001") // LSASS Memory
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find lsass PIDs
        let lsass_pids: HashSet<u32> = data.processes.iter()
            .filter(|p| p.name.to_lowercase() == "lsass.exe")
            .map(|p| p.pid)
            .collect();

        if lsass_pids.is_empty() {
            return findings;
        }

        // Known credential dumping tools (by process name)
        let known_dumpers = [
            "procdump", "procdump64", "mimikatz", "wce", "pwdump",
            "fgdump", "gsecdump", "secretsdump", "pypykatz", "nanodump",
            "handlekatz", "lsassy", "sqldumper", "comsvcs",
            "inject.x64", "inject.x86", "inject64", "inject32",
        ];

        for cmd in &data.cmdlines {
            let args_lower = cmd.args.to_lowercase();
            let proc_lower = cmd.process.to_lowercase();

            // Skip lsass itself
            if proc_lower == "lsass.exe" || proc_lower.starts_with("lsass") {
                continue;
            }

            let mut is_targeting_lsass = false;
            let mut evidence_detail = String::new();

            // Check 1: Does the cmdline contain "lsass" directly?
            if args_lower.contains("lsass") {
                is_targeting_lsass = true;
                evidence_detail = "Command line references 'lsass' directly".to_string();
            }

            // Check 2: Does the cmdline contain an lsass PID as an argument?
            if !is_targeting_lsass {
                let parts: Vec<&str> = cmd.args.split_whitespace().collect();
                for part in &parts {
                    if let Ok(pid) = part.parse::<u32>() {
                        if lsass_pids.contains(&pid) {
                            is_targeting_lsass = true;
                            evidence_detail = format!(
                                "Command line contains PID {} which belongs to lsass.exe", pid);
                            break;
                        }
                    }
                    // Also check --pid=708, -p708 patterns
                    for prefix in &["--pid=", "-pid=", "-p"] {
                        if let Some(val) = part.to_lowercase().strip_prefix(prefix) {
                            if let Ok(pid) = val.parse::<u32>() {
                                if lsass_pids.contains(&pid) {
                                    is_targeting_lsass = true;
                                    evidence_detail = format!(
                                        "Command line targets PID {} (lsass.exe) via {}", pid, prefix);
                                    break;
                                }
                            }
                        }
                    }
                    if is_targeting_lsass { break; }
                }
            }

            if !is_targeting_lsass {
                continue;
            }

            // Determine if it's a known dumping tool
            let is_known_dumper = known_dumpers.iter().any(|d| proc_lower.contains(d));

            let severity = if is_known_dumper {
                Severity::Critical
            } else {
                Severity::High
            };

            let tool_label = if is_known_dumper {
                " [KNOWN CREDENTIAL/INJECTION TOOL]"
            } else {
                ""
            };

            // Get process creation time
            let create_time = data.processes.iter()
                .find(|p| p.pid == cmd.pid)
                .and_then(|p| p.create_time)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or("Unknown".to_string());

            let mut finding = create_finding(
                self,
                format!("LSASS targeting: {} (PID:{}){}", cmd.process, cmd.pid, tool_label),
                format!(
                    "Process '{}' (PID {}) is targeting lsass.exe via its command line.{}\n\n\
                    Evidence: {}\n\
                    Command: {}\n\
                    Created: {}\n\n\
                    This is a strong indicator of credential dumping or process injection \
                    targeting the Local Security Authority Subsystem Service.",
                    cmd.process, cmd.pid, tool_label,
                    evidence_detail, cmd.args, create_time
                ),
                vec![
                    Evidence {
                        source_plugin: "cmdline".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Process: {} PID: {} Args: {}", cmd.process, cmd.pid, cmd.args),
                    },
                    Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Created: {} LSASS PIDs: {:?}", create_time, lsass_pids),
                    },
                ],
            );
            finding.severity = severity;
            finding.related_pids = {
                let mut pids = vec![cmd.pid];
                pids.extend(lsass_pids.iter());
                pids
            };
            finding.confidence = if is_known_dumper { 0.98 } else { 0.85 };
            findings.push(finding);
        }

        findings
    }
}
