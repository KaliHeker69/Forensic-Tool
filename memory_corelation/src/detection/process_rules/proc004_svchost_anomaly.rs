//! PROC004 – SvchostAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect svchost.exe anomalies
pub struct SvchostAnomalyRule;

impl DetectionRule for SvchostAnomalyRule {
    fn id(&self) -> &str {
        "PROC004"
    }

    fn name(&self) -> &str {
        "Svchost Anomaly"
    }

    fn description(&self) -> &str {
        "Detects svchost.exe running from unexpected location or with unexpected parent"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.004") // Masquerading: Masquerade Task or Service
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build PID -> process name map
        let pid_map: std::collections::HashMap<_, _> = data
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        for proc in &data.processes {
            let name_lower = proc.name.to_lowercase();
            if !name_lower.contains("svchost") {
                continue;
            }

            // Check parent process
            let parent_name = pid_map
                .get(&proc.ppid)
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            // svchost.exe should be spawned by services.exe
            if !parent_name.contains("services.exe") && proc.ppid != 0 {
                let proc_cmdline = data.cmdlines.iter()
                    .find(|c| c.pid == proc.pid)
                    .map(|c| c.args.clone())
                    .unwrap_or_else(|| "N/A".to_string());

                let mut finding = create_finding(
                    self,
                    format!("Svchost anomaly: unexpected parent (PID:{})", proc.pid),
                    format!(
                        "svchost.exe (PID:{}) has unexpected parent '{}' (PPID:{}). \
                         Legitimate svchost.exe is spawned by services.exe.\n\
                         \nCommand Line: {}",
                        proc.pid,
                        pid_map.get(&proc.ppid).unwrap_or(&"?"),
                        proc.ppid,
                        proc_cmdline
                    ),
                    vec![Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("svchost.exe PPID:{}", proc.ppid),
                    }],
                );
                finding.related_pids = vec![proc.pid, proc.ppid];
                finding.timestamp = proc.create_time;
                findings.push(finding);
            }
        }

        findings
    }
}
