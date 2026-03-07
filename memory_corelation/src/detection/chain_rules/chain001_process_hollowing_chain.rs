//! CHAIN001 – ProcessHollowingChainRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect process hollowing attack chain
/// Pattern: malfind hit + no DLL at address + empty/mismatched cmdline + legitimate-looking name
pub struct ProcessHollowingChainRule;

impl DetectionRule for ProcessHollowingChainRule {
    fn id(&self) -> &str {
        "CHAIN001"
    }

    fn name(&self) -> &str {
        "Process Hollowing Attack Chain"
    }

    fn description(&self) -> &str {
        "Correlates malfind, dlllist, and cmdline to detect process hollowing attacks"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.012") // Process Hollowing
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Build lookup maps
        let cmdline_by_pid: HashMap<u32, &str> = data.cmdlines
            .iter()
            .map(|c| (c.pid, c.args.as_str()))
            .collect();
        
        let dlls_by_pid: HashMap<u32, Vec<(u64, u64)>> = {
            let mut map: HashMap<u32, Vec<(u64, u64)>> = HashMap::new();
            for dll in &data.dlls {
                let base_str = dll.base.trim_start_matches("0x");
                if let Ok(base) = u64::from_str_radix(base_str, 16) {
                    let size = dll.size.unwrap_or(0x1000); // Default page size if unknown
                    map.entry(dll.pid).or_default().push((base, base + size));
                }
            }
            map
        };
        
        let proc_by_pid: HashMap<u32, &str> = data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        // Legitimate-looking process names (hollowing camouflage targets)
        let hollow_targets = [
            "svchost.exe", "explorer.exe", "iexplore.exe", "chrome.exe",
            "firefox.exe", "notepad.exe", "calc.exe", "mspaint.exe",
            "rundll32.exe", "dllhost.exe", "regsvr32.exe", "msiexec.exe",
        ];
        
        for mf in &data.malfind {
            let pid = mf.pid;
            
            // Check 1: Has MZ header (injected PE)?
            let has_mz = mf.hexdump.as_deref()
                .map(|h| h.to_lowercase().starts_with("4d5a") || h.contains("MZ"))
                .unwrap_or(false);
            
            if !has_mz {
                continue; // Focus on PE injection for hollowing
            }
            
            // Check 2: Is the address covered by any known DLL?
            let mf_addr = u64::from_str_radix(mf.start.trim_start_matches("0x"), 16).unwrap_or(0);
            let covered_by_dll = dlls_by_pid.get(&pid)
                .map(|ranges| ranges.iter().any(|(start, end)| mf_addr >= *start && mf_addr < *end))
                .unwrap_or(false);
            
            // Check 3: Is cmdline empty or mismatched?
            let cmdline = cmdline_by_pid.get(&pid).copied();
            let has_empty_cmdline = cmdline.map(|c| c.trim().is_empty()).unwrap_or(true);
            let process_name = proc_by_pid.get(&pid).copied().unwrap_or("");
            let cmdline_mismatch = cmdline.map(|c: &str| {
                let c_lower = c.to_lowercase();
                let p_lower = process_name.to_lowercase();
                !c_lower.contains(&p_lower.replace(".exe", ""))
            }).unwrap_or(false);
            
            // Check 4: Is it a legitimate-looking process name?
            let is_hollow_target = hollow_targets.iter()
                .any(|&t| process_name.to_lowercase() == t);
            
            // Count evidence weight
            let mut evidence_score = 35; // Base: MZ header in memory
            let mut evidence_details = vec!["MZ header in unbacked memory region"];
            
            if !covered_by_dll {
                evidence_score += 20;
                evidence_details.push("address not covered by any loaded DLL");
            }
            if has_empty_cmdline {
                evidence_score += 20;
                evidence_details.push("empty command line");
            } else if cmdline_mismatch {
                evidence_score += 15;
                evidence_details.push("command line doesn't match process name");
            }
            if is_hollow_target {
                evidence_score += 10;
                evidence_details.push("legitimate-looking target process");
            }
            
            // Only flag if evidence is strong enough
            if evidence_score >= 55 {
                let mut finding = create_finding(
                    self,
                    format!("Process hollowing: {} (PID {})", process_name, pid),
                    format!(
                        "Multiple indicators suggest process hollowing in '{}' (PID {}): {}. \
                        Evidence score: {}/100. This attack technique replaces legitimate process \
                        code with malicious code while maintaining the original process name.",
                        process_name, pid, evidence_details.join(", "), evidence_score
                    ),
                    vec![Evidence {
                        source_plugin: "chain_analysis".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "malfind: {} | dlllist: {} DLLs | cmdline: {:?}",
                            mf.start,
                            dlls_by_pid.get(&pid).map(|v| v.len()).unwrap_or(0),
                            cmdline
                        ),
                    }],
                );
                finding.related_pids = vec![pid];
                finding.confidence = (evidence_score as f32) / 100.0;
                findings.push(finding);
            }
        }

        findings
    }
}
