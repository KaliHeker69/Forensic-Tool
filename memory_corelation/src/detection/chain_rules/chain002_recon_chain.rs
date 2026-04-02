//! CHAIN002 – ReconChainRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect lateral movement / reconnaissance chain
/// Pattern: recon commands + unusual parent + network activity
pub struct ReconChainRule;

impl DetectionRule for ReconChainRule {
    fn id(&self) -> &str {
        "CHAIN002"
    }

    fn name(&self) -> &str {
        "Reconnaissance Chain Detection"
    }

    fn description(&self) -> &str {
        "Detects reconnaissance activity chains (commands, unusual parent, network)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1082") // System Information Discovery
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Recon commands
        let recon_patterns = [
            "whoami", "hostname", "ipconfig", "net user", "net group", "net localgroup",
            "net share", "net view", "netstat", "tasklist", "systeminfo", "nltest",
            "dsquery", "qwinsta", "query user", "arp -a", "route print", "nslookup",
            "ping", "tracert", "dir /s", "tree /f", "wmic", "cmdkey /list",
        ];
        
        // Unusual parent processes for recon commands
        let suspicious_parents = [
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "acrord32.exe", "reader.exe", "iexplore.exe", "chrome.exe", 
            "firefox.exe", "onenote.exe", "mshta.exe", "wscript.exe", "cscript.exe",
        ];
        
        // Build parent-child relationships
        let parent_map: HashMap<u32, u32> = data.processes
            .iter()
            .map(|p| (p.pid, p.ppid))
            .collect();
        
        let proc_name_map: HashMap<u32, &str> = data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        // PIDs with network connections
        let network_pids: HashSet<u32> = data.connections
            .iter()
            .map(|c| c.pid)
            .collect();
        
        for cmd in &data.cmdlines {
            let cmdline = cmd.args.to_lowercase();
            
            // Check if this is a recon command
            let is_recon = recon_patterns.iter().any(|&p| cmdline.contains(p));
            if !is_recon {
                continue;
            }
            
            // Check parent
            let parent_pid = parent_map.get(&cmd.pid).copied();
            let parent_name = parent_pid.and_then(|ppid| proc_name_map.get(&ppid).copied())
                .unwrap_or("");
            let has_suspicious_parent = suspicious_parents.iter()
                .any(|&p| parent_name.to_lowercase() == p);
            
            // Check network activity from parent or self
            let has_network = network_pids.contains(&cmd.pid) || 
                parent_pid.map(|p| network_pids.contains(&p)).unwrap_or(false);
            
            // Calculate evidence score
            let mut evidence_score = 15; // Base: recon command
            let mut evidence_details = vec![format!("recon command: {}", &cmdline[..cmdline.len().min(50)])];
            
            if has_suspicious_parent {
                evidence_score += 20;
                evidence_details.push(format!("suspicious parent: {}", parent_name));
            }
            if has_network {
                evidence_score += 15;
                evidence_details.push("process or parent has network connections".to_string());
            }
            
            // Only report if there's corroborating evidence
            // Threshold raised to require at least suspicious parent OR multiple indicators
            if evidence_score >= 35 {
                let process_name = proc_name_map.get(&cmd.pid).copied().unwrap_or("unknown");
                
                let mut finding = create_finding(
                    self,
                    format!("Reconnaissance chain: {} via {}", process_name, parent_name),
                    format!(
                        "Reconnaissance activity detected: {}. \
                        This pattern suggests post-exploitation discovery activity.",
                        evidence_details.join("; ")
                    ),
                    vec![Evidence {
                        source_plugin: "chain_analysis".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("cmdline: {}", cmd.args),
                    }],
                );
                finding.related_pids = vec![cmd.pid];
                finding.confidence = (evidence_score as f32) / 100.0;
                findings.push(finding);
            }
        }

        findings
    }
}
