//! PROC009 – DuplicateSystemProcessRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::process::ProcessNode;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect multiple instances of processes that should be unique
pub struct DuplicateSystemProcessRule;

impl DetectionRule for DuplicateSystemProcessRule {
    fn id(&self) -> &str {
        "PROC009"
    }

    fn name(&self) -> &str {
        "Duplicate System Process"
    }

    fn description(&self) -> &str {
        "Detects multiple instances of processes that should be unique (e.g., multiple lsass.exe)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.005") // Masquerading: Match Legitimate Name
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        use std::collections::HashSet;
        let mut findings = Vec::new();

        // Processes that should only have one instance
        let unique_processes = [
            "lsass.exe",
            "services.exe",
            "wininit.exe",
            "smss.exe", // First smss exits, so only one should remain
        ];

        for target in unique_processes {
            // Use HashSet to deduplicate PIDs - same PID from pslist/psscan/pstree should only count once
            let unique_pids: HashSet<u32> = data
                .processes
                .iter()
                .filter(|p| p.name.to_lowercase() == target)
                .map(|p| p.pid)
                .collect();
            
            let instances: Vec<_> = unique_pids.iter().copied().collect();

            if instances.len() > 1 {
                let mut pids: Vec<_> = instances.clone();
                pids.sort();  // Sort for consistent output

                let mut finding = create_finding(
                    self,
                    format!("Multiple {} instances detected", target),
                    format!(
                        "Found {} instances of {} (PIDs: {:?}). This process should only have \
                         one instance. One or more may be malware masquerading as a system process.",
                        instances.len(),
                        target,
                        pids
                    ),
                    vec![Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} instances: {:?}", target, pids),
                    }],
                );

                finding.related_pids = pids;
                finding.confidence = 0.85;
                findings.push(finding);
            }
        }

        findings
    }
}

// Parent-child process relationship detection rules

