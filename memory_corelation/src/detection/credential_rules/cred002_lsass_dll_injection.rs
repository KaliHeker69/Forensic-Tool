//! CRED002 – LsassDllInjectionRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious DLLs loaded in lsass
/// APT groups often inject DLLs into lsass for persistence and credential theft
pub struct LsassDllInjectionRule {
    whitelist: crate::config::WhitelistConfig,
    blacklist: crate::config::BlacklistConfig,
}

impl LsassDllInjectionRule {
    pub fn new() -> Self {
        let whitelist = crate::config::WhitelistConfig::load_from_file("config/whitelist.json")
            .unwrap_or_default();
        let blacklist = crate::config::BlacklistConfig::load_from_file("config/blacklist.json")
            .unwrap_or_default();
        Self { whitelist, blacklist }
    }
}

impl DetectionRule for LsassDllInjectionRule {
    fn id(&self) -> &str {
        "CRED002"
    }

    fn name(&self) -> &str {
        "LSASS DLL Injection Detection"
    }

    fn description(&self) -> &str {
        "Detects unusual DLLs loaded in lsass.exe that may indicate injection"
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
        let lsass_pids: HashSet<u32> = data.processes
            .iter()
            .filter(|p| p.name.to_lowercase() == "lsass.exe")
            .map(|p| p.pid)
            .collect();
        
        // Expected DLLs in lsass (this is a subset, there are more)
        // Expected DLLs in lsass from config
        let binding = Vec::new(); // empty fallback
        let expected_dlls: &[String] = self.whitelist.get_allowed_dlls("lsass.exe")
            .map(|v| v)
            .unwrap_or(binding.as_slice());
        
        for dll in &data.dlls {
            // Only check DLLs in lsass
            if !lsass_pids.contains(&dll.pid) {
                continue;
            }
            
            let dll_name = dll.path.rsplit(['\\', '/']).next().unwrap_or(&dll.path).to_lowercase();
            
            // Check if DLL is not in expected list
            // Note: whitelist config is case-insensitive in lookup but here we have strings
            // We should use case-insensitive compare
            if !expected_dlls.iter().any(|k| dll_name.eq_ignore_ascii_case(k)) {
                // Check if it's from a suspicious path
                let path_lower = dll.path.to_lowercase();
                let is_suspicious_path = self.blacklist.is_suspicious(&dll.path) || !path_lower.contains("\\windows\\");
                
                // Skip if it's from System32 (likely legitimate but unknown)
                if path_lower.contains("\\system32\\") && !is_suspicious_path {
                    continue;
                }
                
                let severity = if is_suspicious_path {
                    Severity::Critical
                } else {
                    Severity::High
                };
                
                let mut finding = create_finding(
                    self,
                    format!("Unusual DLL in lsass: {}", dll_name),
                    format!(
                        "LSASS.exe (PID {}) has loaded DLL '{}' which is not in the expected \
                        DLL list for lsass. Full path: {}. This could indicate DLL injection \
                        for credential theft or persistence.",
                        dll.pid, dll_name, dll.path
                    ),
                    vec![Evidence {
                        source_plugin: "dlllist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("DLL: {} Base: {:?}", dll.path, dll.base),
                    }],
                );
                finding.severity = severity;
                finding.related_pids = vec![dll.pid];
                finding.related_files = vec![dll.path.clone()];
                finding.confidence = if is_suspicious_path { 0.90 } else { 0.65 };
                findings.push(finding);
            }
        }

        findings
    }
}
