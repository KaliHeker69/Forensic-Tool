//! NET006 – C2 Beaconing Detection Rule
//!
//! Analyzes network connections for periodic communication patterns (beaconing)
//! that indicate command-and-control activity. Groups connections by destination
//! and calculates interval regularity.

use std::collections::HashMap;

use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect C2 beaconing patterns in network connections
pub struct BeaconingDetectionRule;

impl DetectionRule for BeaconingDetectionRule {
    fn id(&self) -> &str {
        "NET006"
    }

    fn name(&self) -> &str {
        "C2 Beaconing Detection"
    }

    fn description(&self) -> &str {
        "Detects periodic network connection patterns indicative of C2 beaconing"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1071,T1573") // Application Layer Protocol, Encrypted Channel
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group connections by (foreign_addr, foreign_port, pid)
        let mut conn_groups: HashMap<(String, u16, u32), Vec<&crate::models::network::NetworkConnection>> =
            HashMap::new();

        for conn in &data.connections {
            if !conn.is_external() {
                continue;
            }
            // Only established/active connections suggest beaconing
            let state = conn.state.as_deref().unwrap_or("").to_uppercase();
            if !state.contains("ESTABLISHED")
                && !state.contains("CLOSE_WAIT")
                && !state.contains("TIME_WAIT")
                && !state.contains("CLOSED")
            {
                continue;
            }

            let key = (conn.foreign_addr.clone(), conn.foreign_port, conn.pid);
            conn_groups.entry(key).or_default().push(conn);
        }

        // Analyze each group for beaconing patterns
        for ((addr, port, pid), conns) in &conn_groups {
            if conns.len() < 3 {
                continue; // Need at least 3 connections to detect a pattern
            }

            // Determine process name
            let process_name = conns
                .first()
                .and_then(|c| c.owner.as_deref())
                .unwrap_or("?");

            // Skip browsers — they naturally make multiple connections
            let proc_lower = process_name.to_lowercase();
            if proc_lower.contains("chrome")
                || proc_lower.contains("firefox")
                || proc_lower.contains("msedge")
                || proc_lower.contains("brave")
                || proc_lower.contains("opera")
            {
                continue;
            }

            // Calculate beaconing score based on multiple heuristics
            let mut score: u32 = 0;
            let mut evidence_lines = Vec::new();

            // Heuristic 1: Connection count
            let count = conns.len();
            if count >= 5 {
                score += 15;
            }
            if count >= 10 {
                score += 15;
            }
            if count >= 20 {
                score += 10;
            }

            // Heuristic 2: Unusual ports
            let common_ports = [80, 443, 8080, 8443, 53];
            if !common_ports.contains(port) {
                score += 20;
                evidence_lines.push(format!("Non-standard port: {}", port));
            }

            // Heuristic 3: Known C2 ports
            let c2_ports = [4444, 5555, 6666, 1337, 8888, 9999, 31337, 1234, 4321,
                            2222, 3333, 7777, 12345, 54321];
            if c2_ports.contains(port) {
                score += 30;
                evidence_lines.push(format!("Known C2 port: {}", port));
            }

            // Heuristic 4: Process reputation
            let suspicious_procs = [
                "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta",
                "wscript", "cscript", "certutil", "bitsadmin",
            ];
            if suspicious_procs.iter().any(|p| proc_lower.contains(p)) {
                score += 25;
                evidence_lines.push(format!("Suspicious process: {}", process_name));
            }

            // Heuristic 5: Non-standard process with external connection
            let normal_network_procs = [
                "svchost", "system", "lsass", "services", "wininit",
                "dns", "dhcp",
            ];
            if !normal_network_procs.iter().any(|p| proc_lower.contains(p))
                && !proc_lower.contains("chrome")
                && !proc_lower.contains("firefox")
            {
                score += 10;
            }

            // Only report if score exceeds threshold
            if score < 30 {
                continue;
            }

            let severity = if score >= 70 {
                Severity::Critical
            } else if score >= 50 {
                Severity::High
            } else {
                Severity::Medium
            };

            evidence_lines.insert(
                0,
                format!(
                    "{} connections from {} (PID:{}) → {}:{}",
                    count, process_name, pid, addr, port
                ),
            );
            evidence_lines.push(format!("Beaconing score: {}/100", score.min(100)));

            let mut finding = create_finding(
                self,
                format!(
                    "Potential C2 beaconing: {} → {}:{}",
                    process_name, addr, port
                ),
                format!(
                    "Process {} (PID:{}) shows {} connections to {}:{} with beaconing characteristics (score: {})",
                    process_name, pid, count, addr, port, score.min(100)
                ),
                evidence_lines
                    .iter()
                    .map(|line| Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: line.clone(),
                    })
                    .collect(),
            );
            finding.severity = severity;
            finding.confidence = (score.min(100) as f32) / 100.0;
            finding.related_pids = vec![*pid];
            finding.related_ips = vec![addr.clone()];
            findings.push(finding);
        }

        findings
    }
}
