//! PROC005 – SuspiciousDllPathRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect DLLs loaded from suspicious paths
pub struct SuspiciousDllPathRule {
    whitelist: crate::config::WhitelistConfig,
    blacklist: crate::config::BlacklistConfig,
}

impl SuspiciousDllPathRule {
    pub fn new() -> Self {
        let whitelist = crate::config::WhitelistConfig::load_from_file("config/whitelist.json")
            .unwrap_or_default();
        let blacklist = crate::config::BlacklistConfig::load_from_file("config/blacklist.json")
            .unwrap_or_default();
        Self { whitelist, blacklist }
    }
}

impl DetectionRule for SuspiciousDllPathRule {
    fn id(&self) -> &str {
        "PROC005"
    }

    fn name(&self) -> &str {
        "Suspicious DLL Path"
    }

    fn description(&self) -> &str {
        "Detects DLLs loaded from unusual locations like Temp, Downloads, or user directories"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1574.002") // Hijack Execution Flow: DLL Side-Loading
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for dll in &data.dlls {
            // Use blacklist config
            let is_suspicious = self.blacklist.is_suspicious(&dll.path);

            if is_suspicious {
                // Check whitelist
                if self.whitelist.is_whitelisted(&dll.path) {
                    continue;
                }

                let proc_cmdline = data.cmdlines.iter()
                    .find(|c| c.pid == dll.pid)
                    .map(|c| c.args.clone())
                    .unwrap_or_else(|| "N/A".to_string());

                let mut finding = create_finding(
                    self,
                    format!("Suspicious DLL: {} in {}", dll.name, dll.process),
                    format!(
                        "DLL '{}' loaded from suspicious path '{}' into process {} (PID:{})\n\
                        Process Cmdline: {}",
                        dll.name, dll.path, dll.process, dll.pid, proc_cmdline
                    ),
                    vec![Evidence {
                        source_plugin: "dlllist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: dll.path.clone(),
                    }],
                );
                finding.related_pids = vec![dll.pid];
                finding.related_files = vec![dll.path.clone()];
                findings.push(finding);
            }
        }

        findings
    }
}
