//! PROC008 – LsassParentRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect lsass.exe specifically spawned by non-wininit parents
pub struct LsassParentRule;

impl DetectionRule for LsassParentRule {
    fn id(&self) -> &str {
        "PROC008"
    }

    fn name(&self) -> &str {
        "LSASS Suspicious Parent"
    }

    fn description(&self) -> &str {
        "Detects lsass.exe spawned by anything other than wininit.exe - strong indicator of credential theft"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1003") // OS Credential Dumping
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build PID -> name map
        let pid_map: std::collections::HashMap<_, _> = data
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        for proc in &data.processes {
            let name_lower = proc.name.to_lowercase();
            if name_lower != "lsass.exe" {
                continue;
            }

            let parent_name = pid_map.get(&proc.ppid).map(|s| s.to_lowercase());

            // lsass.exe MUST be spawned by wininit.exe
            if parent_name.as_deref() != Some("wininit.exe") {
                let actual_parent = pid_map.get(&proc.ppid).unwrap_or(&"?");

                let mut finding = create_finding(
                    self,
                    format!("LSASS spawned by {}", actual_parent),
                    format!(
                        "CRITICAL: lsass.exe (PID:{}) was spawned by {} (PPID:{}) instead of wininit.exe. \
                         This is a strong indicator of credential theft malware, process hollowing, or \
                         a fake lsass.exe process.",
                        proc.pid, actual_parent, proc.ppid
                    ),
                    vec![Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("lsass.exe PPID:{} -> {}", proc.ppid, actual_parent),
                    }],
                );

                finding.related_pids = vec![proc.pid, proc.ppid];
                finding.timestamp = proc.create_time;
                finding.confidence = 0.98;
                findings.push(finding);
            }
        }

        findings
    }
}
