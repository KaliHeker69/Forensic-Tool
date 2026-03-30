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

        let mut malfind_by_pid: HashMap<u32, Vec<_>> = HashMap::new();
        for mf in &data.malfind {
            malfind_by_pid.entry(mf.pid).or_default().push(mf);
        }

        let hollow_process_pids: HashSet<u32> =
            data.hollow_processes.iter().map(|entry| entry.pid).collect();

        let mut vadyara_rules_by_pid: HashMap<u32, HashSet<String>> = HashMap::new();
        for match_entry in &data.vad_yara_matches {
            let Some(pid) = match_entry.pid else {
                continue;
            };
            if match_entry.rule.trim().is_empty() {
                continue;
            }
            vadyara_rules_by_pid
                .entry(pid)
                .or_default()
                .insert(match_entry.rule.clone());
        }
        
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
        
        for (pid, malfind_entries) in malfind_by_pid {
            // Check 1: Is cmdline empty or mismatched?
            let cmdline = cmdline_by_pid.get(&pid).copied();
            let has_empty_cmdline = cmdline.map(|c| c.trim().is_empty()).unwrap_or(true);
            let process_name = proc_by_pid
                .get(&pid)
                .copied()
                .or_else(|| malfind_entries.first().map(|m| m.process.as_str()))
                .unwrap_or("unknown");
            let cmdline_mismatch = cmdline.map(|c: &str| {
                let c_lower = c.to_lowercase();
                let p_lower = process_name.to_lowercase();
                !c_lower.contains(&p_lower.replace(".exe", ""))
            }).unwrap_or(false);
            
            // Check 2: Is it a legitimate-looking process name?
            let is_hollow_target = hollow_targets.iter()
                .any(|&t| process_name.to_lowercase() == t);

            let has_hollowprocess_signal = hollow_process_pids.contains(&pid);
            let vadyara_rules: Vec<String> = vadyara_rules_by_pid
                .get(&pid)
                .map(|set| {
                    let mut rules: Vec<String> = set.iter().cloned().collect();
                    rules.sort();
                    rules
                })
                .unwrap_or_default();

            let mut best_score = 0u8;
            let mut best_details: Vec<String> = Vec::new();
            let mut best_region = String::new();

            for mf in malfind_entries {
                // Check 3: Has MZ header (injected PE)?
                let has_mz = mf.hexdump.as_deref()
                    .map(|h| h.to_lowercase().starts_with("4d5a") || h.contains("MZ"))
                    .unwrap_or(false);

                // If neither MZ nor hollowprocess signal exists, evidence is too weak.
                if !has_mz && !has_hollowprocess_signal {
                    continue;
                }

                // Check 4: Is the address covered by any known DLL?
                let mf_addr = u64::from_str_radix(mf.start.trim_start_matches("0x"), 16).unwrap_or(0);
                let covered_by_dll = dlls_by_pid
                    .get(&pid)
                    .map(|ranges| ranges.iter().any(|(start, end)| mf_addr >= *start && mf_addr < *end))
                    .unwrap_or(false);
            
                // Count evidence weight
                let mut evidence_score: u8 = if has_mz { 35 } else { 20 };
                let mut evidence_details = Vec::new();
                if has_mz {
                    evidence_details.push("MZ header in unbacked memory region".to_string());
                }
            
                if !covered_by_dll {
                    evidence_score = evidence_score.saturating_add(20);
                    evidence_details.push("address not covered by any loaded DLL".to_string());
                }
                if has_empty_cmdline {
                    evidence_score = evidence_score.saturating_add(20);
                    evidence_details.push("empty command line".to_string());
                } else if cmdline_mismatch {
                    evidence_score = evidence_score.saturating_add(15);
                    evidence_details.push("command line doesn't match process name".to_string());
                }
                if is_hollow_target {
                    evidence_score = evidence_score.saturating_add(10);
                    evidence_details.push("legitimate-looking target process".to_string());
                }
                if has_hollowprocess_signal {
                    evidence_score = evidence_score.saturating_add(30);
                    evidence_details.push("hollowprocesses plugin flagged this PID".to_string());
                }
                if !vadyara_rules.is_empty() {
                    let yara_bonus = ((vadyara_rules.len() as u8) * 5).min(20);
                    evidence_score = evidence_score.saturating_add(yara_bonus);
                    evidence_details.push(format!(
                        "vadyarascan matched rules: {}",
                        vadyara_rules.join(", ")
                    ));
                }

                if evidence_score > best_score {
                    best_score = evidence_score;
                    best_details = evidence_details;
                    best_region = mf.start.clone();
                }
            }
            
            // Only flag if evidence is strong enough
            if best_score >= 55 {
                let mut finding = create_finding(
                    self,
                    format!("Process hollowing: {} (PID {})", process_name, pid),
                    format!(
                        "Multiple indicators suggest process hollowing in '{}' (PID {}): {}. \
                        Evidence score: {}/100. This attack technique replaces legitimate process \
                        code with malicious code while maintaining the original process name.",
                        process_name,
                        pid,
                        best_details.join(", "),
                        best_score
                    ),
                    vec![Evidence {
                        source_plugin: "chain_analysis".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "malfind_region: {} | dlllist: {} DLLs | cmdline: {:?} | hollowprocesses_hit: {} | vadyarascan_rules: {}",
                            best_region,
                            dlls_by_pid.get(&pid).map(|v| v.len()).unwrap_or(0),
                            cmdline,
                            has_hollowprocess_signal,
                            vadyara_rules.join(", ")
                        ),
                    }],
                );
                finding.related_pids = vec![pid];
                finding.confidence = (best_score as f32 / 100.0).min(0.99);
                findings.push(finding);
            }
        }

        findings
    }
}
