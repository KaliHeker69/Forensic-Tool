//! CRED003 – SensitiveProcessInjectionRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect malfind hits in sensitive system processes
/// Injection into lsass, csrss, winlogon indicates advanced attack
pub struct SensitiveProcessInjectionRule;

impl DetectionRule for SensitiveProcessInjectionRule {
    fn id(&self) -> &str {
        "CRED003"
    }

    fn name(&self) -> &str {
        "Sensitive Process Injection"
    }

    fn description(&self) -> &str {
        "Detects code injection (malfind) in sensitive system processes"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055") // Process Injection
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Sensitive processes where injection is extremely concerning
        let sensitive_processes: HashSet<&str> = [
            "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
            "smss.exe", "wininit.exe", "lsaiso.exe",
        ].iter().cloned().collect();
        
        // Build PID to process name map
        let pid_map: HashMap<u32, &str> = data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        for mf in &data.malfind {
            let process_name = pid_map.get(&mf.pid).map(|s| s.to_lowercase());
            
            if let Some(name) = process_name {
                let is_sensitive = sensitive_processes.iter().any(|&s| name == s);
                
                if is_sensitive {
                    let has_mz = mf.hexdump.as_deref()
                        .map(|h| h.starts_with("4d5a") || h.starts_with("4D5A") || h.contains("MZ"))
                        .unwrap_or(false);
                    
                    let has_shellcode = mf.has_shellcode_patterns();
                    
                    // lsass.exe commonly has RWX from SSP DLLs — only flag if MZ or shellcode present
                    if name.starts_with("lsass") && !has_mz && !has_shellcode {
                        continue;
                    }
                    
                    let severity = if has_mz {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    
                    let mut finding = create_finding(
                        self,
                        format!("Code injection in {}", name),
                        format!(
                            "Malfind detected suspicious memory region in sensitive process '{}' (PID {}). \
                            Address: {} Protection: {}{}. \
                            This indicates process injection targeting a critical system component.",
                            name, mf.pid, mf.start,
                            &mf.protection,
                            if has_mz { " [Contains MZ header - injected PE]" } else { "" }
                        ),
                        vec![Evidence {
                            source_plugin: "malfind".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!(
                                "Process: {} PID: {} Start: {} Protection: {}",
                                name, mf.pid, mf.start, mf.protection
                            ),
                        }],
                    );
                    finding.severity = severity;
                    finding.related_pids = vec![mf.pid];
                    finding.confidence = if has_mz { 0.95 } else { 0.85 };
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
