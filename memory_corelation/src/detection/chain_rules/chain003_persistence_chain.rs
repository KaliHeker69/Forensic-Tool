//! CHAIN003 – PersistenceChainRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect persistence installation chain
/// Pattern: service creation + suspicious path + running process
pub struct PersistenceChainRule;

impl DetectionRule for PersistenceChainRule {
    fn id(&self) -> &str {
        "CHAIN003"
    }

    fn name(&self) -> &str {
        "Persistence Installation Chain"
    }

    fn description(&self) -> &str {
        "Correlates service registration, file paths, and process execution for persistence detection"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1543.003") // Create or Modify System Process: Windows Service
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Build file existence map from filescan
        let files_on_disk: HashSet<String> = data.files
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Build running process map
        let running_pids: HashSet<u32> = data.processes
            .iter()
            .filter(|p| p.exit_time.is_none())
            .map(|p| p.pid)
            .collect();
        
        for svc in &data.services {
            let binary = svc.binary_path.as_deref().unwrap_or("");
            if binary.is_empty() {
                continue;
            }
            
            let binary_lower = binary.to_lowercase();
            
            // Chain validation step 1: Is binary in suspicious location?
            let suspicious_path = binary_lower.contains("\\temp\\") ||
                binary_lower.contains("\\tmp\\") ||
                binary_lower.contains("\\appdata\\") ||
                (binary_lower.contains("\\users\\public\\") && !binary_lower.contains("\\desktop\\.ink"));
            
            // Chain validation step 2: Does binary exist in filescan?
            let binary_in_filescan = files_on_disk.iter()
                .any(|f| f.contains(&binary_lower) || binary_lower.contains(f));
            
            // Chain validation step 3: Is service PID running?
            let svc_pid: Option<u32> = svc.pid.as_ref().and_then(|p| p.parse().ok());
            let is_running = svc_pid.map(|p| running_pids.contains(&p)).unwrap_or(false);
            
            // Calculate chain evidence
            let mut evidence_score = 0;
            let mut evidence_details = Vec::new();
            
            if suspicious_path {
                evidence_score += 25;
                evidence_details.push("binary in suspicious location");
            }
            
            if !binary_in_filescan && !binary_lower.contains("\\system32\\") {
                evidence_score += 20;
                evidence_details.push("binary not found in filescan");
            }
            
            if is_running {
                evidence_score += 15;
                evidence_details.push("service is actively running");
            }
            
            // Check for suspicious execution patterns in binary path
            if svc.has_suspicious_execution() {
                evidence_score += 30;
                evidence_details.push("suspicious execution pattern (cmd/powershell invocation)");
            }
            
            if evidence_score >= 35 {
                let mut finding = create_finding(
                    self,
                    format!("Persistence chain: service {}", svc.name),
                    format!(
                        "Service '{}' shows persistence installation pattern: {}. \
                        Binary: {}. Evidence score: {}/100.",
                        svc.name, evidence_details.join(", "), binary, evidence_score
                    ),
                    vec![Evidence {
                        source_plugin: "chain_analysis".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Service: {} Binary: {}", svc.name, binary),
                    }],
                );
                finding.related_pids = svc_pid.into_iter().collect();
                finding.related_files = vec![binary.to_string()];
                finding.confidence = (evidence_score as f32) / 100.0;
                findings.push(finding);
            }
        }

        findings
    }
}

// Attack chain detection rules
//
// These rules correlate findings across multiple plugins to detect
// complete attack chains (credential dumping, process hollowing,
// persistence installation, lateral movement).


