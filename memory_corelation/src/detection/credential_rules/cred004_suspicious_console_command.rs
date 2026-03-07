//! CRED004 – SuspiciousConsoleCommandRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious command history from cmdscan/consoles plugins
pub struct SuspiciousConsoleCommandRule;

impl DetectionRule for SuspiciousConsoleCommandRule {
    fn id(&self) -> &str {
        "CRED004"
    }

    fn name(&self) -> &str {
        "Suspicious Console Command History"
    }

    fn description(&self) -> &str {
        "Detects credential theft and injection-related commands from cmdscan/consoles history"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1059.003")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {

        let mut findings = Vec::new();
        let mut commands_by_pid: HashMap<u32, HashSet<String>> = HashMap::new();

        // Keywords intentionally constrained to avoid noisy shell usage
        let suspicious_patterns = [
            "mimikatz",
            "sekurlsa",
            "procdump",
            "nanodump",
            "lsassy",
            "comsvcs.dll",
            "reg save hklm\\sam",
            "reg save hklm\\security",
            "inject.x64.exe",
        ];

        for rec in data.cmdscan_records.iter().chain(data.console_records.iter()) {
            collect_suspicious_console_commands(rec, &suspicious_patterns, &mut commands_by_pid);
        }

        for (pid, cmds) in commands_by_pid {
            if cmds.is_empty() {
                continue;
            }

            let mut cmd_list: Vec<String> = cmds.into_iter().collect();
            cmd_list.sort();
            let preview = cmd_list.iter().take(5).cloned().collect::<Vec<_>>().join(" | ");

            let mut finding = create_finding(
                self,
                format!("Suspicious console command history (PID {})", pid),
                format!(
                    "Detected suspicious command history entries from cmdscan/consoles for PID {}. Commands: {}",
                    pid, preview
                ),
                vec![Evidence {
                    source_plugin: "cmdscan+consoles".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: preview,
                }],
            );
            finding.related_pids = vec![pid];
            finding.confidence = 0.92;
            findings.push(finding);
        }

        findings
    }
}

fn collect_suspicious_console_commands(
    rec: &serde_json::Value,
    suspicious_patterns: &[&str],
    commands_by_pid: &mut std::collections::HashMap<u32, std::collections::HashSet<String>>,
) {
    let pid = rec
        .get("PID")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    if pid != 0 {
        let prop = rec
            .get("Property")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let data_str = rec
            .get("Data")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        if !data_str.is_empty()
            && (prop.contains("command") || prop.contains("title") || prop.contains("history"))
        {
            let lower = data_str.to_lowercase();
            if suspicious_patterns.iter().any(|p| lower.contains(p)) {
                commands_by_pid
                    .entry(pid)
                    .or_default()
                    .insert(data_str.to_string());
            }
        }
    }

    if let Some(children) = rec.get("__children").and_then(|v| v.as_array()) {
        for child in children {
            collect_suspicious_console_commands(child, suspicious_patterns, commands_by_pid);
        }
    }
}
