//! XCOR003 – NetworkPrivilegeCorrelationRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect processes with external network connections AND dangerous privileges.
pub struct NetworkPrivilegeCorrelationRule;

impl DetectionRule for NetworkPrivilegeCorrelationRule {
    fn id(&self) -> &str {
        "XCOR003"
    }

    fn name(&self) -> &str {
        "Privileged Process with External Network"
    }

    fn description(&self) -> &str {
        "Detects processes with dangerous privileges that also have external network connections"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1071")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // PIDs with dangerous privileges (excluding expected system procs)
        let mut dangerous_priv_pids: HashMap<u32, Vec<String>> = HashMap::new();
        for priv_info in &data.privileges {
            if crate::models::security::is_expected_system_process(&priv_info.process) {
                continue;
            }
            if priv_info.is_dangerous() && priv_info.is_enabled() {
                dangerous_priv_pids
                    .entry(priv_info.pid)
                    .or_default()
                    .push(priv_info.privilege.clone());
            }
        }

        // PIDs with external network connections
        let mut external_conn_pids: HashMap<u32, Vec<String>> = HashMap::new();
        for conn in &data.connections {
            let addr = conn.foreign_addr.as_str();
            // Skip loopback, local, and empty
            if !addr.is_empty()
                && addr != "0.0.0.0"
                && addr != "::"
                && addr != "127.0.0.1"
                && addr != "::1"
                && !addr.starts_with("10.")
                && !addr.starts_with("192.168.")
                && !addr.starts_with("172.")
            {
                external_conn_pids
                    .entry(conn.pid)
                    .or_default()
                    .push(format!("{}:{}", addr, conn.foreign_port));
            }
        }

        let proc_names: HashMap<u32, &str> = data
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        // Find overlap
        for (pid, privs) in &dangerous_priv_pids {
            if let Some(connections) = external_conn_pids.get(pid) {
                let proc_name = proc_names.get(pid).copied().unwrap_or("unknown");

                let mut finding = create_finding(
                    self,
                    format!(
                        "{} (PID {}) has privileges + external connections",
                        proc_name, pid
                    ),
                    format!(
                        "Process {} (PID {}) has dangerous privileges ({}) AND {} external \
                        network connection(s). This may indicate C2 communication or data exfiltration.",
                        proc_name, pid, privs.join(", "), connections.len()
                    ),
                    vec![Evidence {
                        source_plugin: "privileges+netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "Privileges:{} Connections:{}",
                            privs.join(","),
                            connections.iter().take(5).cloned().collect::<Vec<_>>().join(",")
                        ),
                    }],
                );
                finding.related_pids = vec![*pid];
                finding.related_ips = connections.iter().map(|c| {
                    c.split(':').next().unwrap_or("").to_string()
                }).collect();
                finding.confidence = 0.85;
                findings.push(finding);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR004: Hidden Process Detection (psscan vs pslist)
// ---------------------------------------------------------------------------
