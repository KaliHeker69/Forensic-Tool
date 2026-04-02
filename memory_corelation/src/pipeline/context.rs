//! Analysis context shared between pipeline modules
//!
//! Contains findings, PID scores, chain tags, and flagged PIDs
//! that accumulate as modules execute in sequence.

use std::collections::{HashMap, HashSet};

use crate::parsers::ParsedData;
use crate::{Finding, Severity};

/// Weight-based evidence for a PID
#[derive(Debug, Clone, Default)]
pub struct PidEvidence {
    /// Accumulated severity weight
    pub total_weight: i32,
    /// Individual findings for this PID
    pub findings: Vec<Finding>,
    /// Chain tags (e.g., "CREDENTIAL_DUMPING", "PROCESS_HOLLOWING")
    pub chain_tags: HashSet<String>,
    /// Module sources that flagged this PID
    pub flagged_by_modules: HashSet<String>,
}

/// Context passed between pipeline modules
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    /// Reference to parsed data
    pub data: &'a ParsedData,
    
    /// Per-PID evidence accumulator
    pub pid_evidence: HashMap<u32, PidEvidence>,
    
    /// Global findings (not PID-specific)
    pub global_findings: Vec<Finding>,
    
    /// PIDs flagged as injection targets (for Module 7)
    pub injection_flagged_pids: HashSet<u32>,
    
    /// PIDs flagged for credential access indicators
    pub credential_flagged_pids: HashSet<u32>,
    
    /// PIDs with anomalous cmdlines
    pub cmdline_anomaly_pids: HashSet<u32>,
    
    /// PIDs with network activity
    pub network_pids: HashSet<u32>,
    
    /// Allowlisted PIDs (dismissed from reporting)
    pub allowlisted_pids: HashSet<u32>,
    
    /// Allowlisted service names
    pub allowlisted_services: HashSet<String>,
    
    /// Files found in filescan (lowercased paths)
    pub filescan_paths: HashSet<String>,
    
    /// Set of finding keys used for deduplication
    pub seen_findings: HashSet<String>,
    
    /// lsass PID (if found)
    pub lsass_pid: Option<u32>,
}

impl<'a> AnalysisContext<'a> {
    /// Create a new context from parsed data
    pub fn new(data: &'a ParsedData) -> Self {
        // Pre-compute filescan paths
        let filescan_paths: HashSet<String> = data.files
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Find lsass PID
        let lsass_pid = data.processes
            .iter()
            .find(|p| p.name.to_lowercase() == "lsass.exe")
            .map(|p| p.pid);
        
        // Pre-compute network PIDs
        let network_pids: HashSet<u32> = data.connections
            .iter()
            .map(|c| c.pid)
            .collect();
        
        Self {
            data,
            pid_evidence: HashMap::new(),
            global_findings: Vec::new(),
            injection_flagged_pids: HashSet::new(),
            credential_flagged_pids: HashSet::new(),
            cmdline_anomaly_pids: HashSet::new(),
            network_pids,
            allowlisted_pids: HashSet::new(),
            allowlisted_services: HashSet::new(),
            filescan_paths,
            seen_findings: HashSet::new(),
            lsass_pid,
        }
    }
    
    /// Add finding with weight for a specific PID
    pub fn add_finding(&mut self, pid: u32, finding: Finding, weight: i32, module: &str) {
        // Deduplication: Check if we've seen this finding for this PID before
        // Key: {pid}:{rule_id}:{title}
        let dedup_key = format!("{}:{}:{}", pid, finding.rule_id, finding.title);
        
        if self.seen_findings.contains(&dedup_key) {
            // Skip duplicate finding
            return;
        }
        
        self.seen_findings.insert(dedup_key);
        
        let evidence = self.pid_evidence.entry(pid).or_default();
        evidence.total_weight += weight;
        evidence.findings.push(finding);
        evidence.flagged_by_modules.insert(module.to_string());
    }
    
    /// Add global finding (not PID-specific)
    pub fn add_global_finding(&mut self, finding: Finding) {
        // Global dedup key: {rule_id}:{title}
        let dedup_key = format!("GLOBAL:{}:{}", finding.rule_id, finding.title);
        
        if self.seen_findings.contains(&dedup_key) {
            return;
        }
        
        self.seen_findings.insert(dedup_key);
        self.global_findings.push(finding);
    }
    
    /// Add chain bonus to a PID
    pub fn add_chain_bonus(&mut self, pid: u32, chain_tag: &str, bonus: i32) {
        let evidence = self.pid_evidence.entry(pid).or_default();
        evidence.total_weight += bonus;
        evidence.chain_tags.insert(chain_tag.to_string());
    }
    
    /// Mark PID as having injection indicators
    pub fn flag_injection(&mut self, pid: u32) {
        self.injection_flagged_pids.insert(pid);
    }
    
    /// Mark PID as having credential access indicators
    pub fn flag_credential_access(&mut self, pid: u32) {
        self.credential_flagged_pids.insert(pid);
    }
    
    /// Mark PID as having cmdline anomaly
    pub fn flag_cmdline_anomaly(&mut self, pid: u32) {
        self.cmdline_anomaly_pids.insert(pid);
    }
    
    /// Mark PID as allowlisted
    pub fn allowlist_pid(&mut self, pid: u32) {
        self.allowlisted_pids.insert(pid);
    }
    
    /// Check if PID is allowlisted
    pub fn is_allowlisted(&self, pid: u32) -> bool {
        self.allowlisted_pids.contains(&pid)
    }
    
    /// Get process name by PID
    pub fn get_process_name(&self, pid: u32) -> Option<&str> {
        self.data.processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.name.as_str())
    }
}

/// Severity thresholds for final scoring
pub const THRESHOLD_CRITICAL: i32 = 70;
pub const THRESHOLD_HIGH: i32 = 40;
pub const THRESHOLD_MEDIUM: i32 = 20;
pub const THRESHOLD_INFO: i32 = 1;

/// Map score to severity
pub fn score_to_severity(score: i32) -> Option<Severity> {
    if score >= THRESHOLD_CRITICAL {
        Some(Severity::Critical)
    } else if score >= THRESHOLD_HIGH {
        Some(Severity::High)
    } else if score >= THRESHOLD_MEDIUM {
        Some(Severity::Medium)
    } else if score >= THRESHOLD_INFO {
        Some(Severity::Info)
    } else {
        None // Dismissed
    }
}
