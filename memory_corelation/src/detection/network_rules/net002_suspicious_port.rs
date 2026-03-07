//! NET002 – SuspiciousPortRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect connections to suspicious ports
pub struct SuspiciousPortRule;

impl DetectionRule for SuspiciousPortRule {
    fn id(&self) -> &str {
        "NET002"
    }

    fn name(&self) -> &str {
        "Suspicious Port Connection"
    }

    fn description(&self) -> &str {
        "Detects connections to known suspicious ports commonly used by backdoors and C2"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1571") // Non-Standard Port
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Ports commonly used by malware/backdoors
        let very_suspicious = [4444, 5555, 6666, 7777, 8888, 1337, 31337];

        for conn in &data.connections {
            if !conn.is_external() {
                continue;
            }

            let port = conn.foreign_port;
            if very_suspicious.contains(&port) {
                let mut finding = create_finding(
                    self,
                    format!("Connection to suspicious port {}", port),
                    format!(
                        "Process {} (PID:{}) connected to {}:{} - this port is commonly used by backdoors",
                        conn.owner.as_deref().unwrap_or("?"),
                        conn.pid,
                        conn.foreign_addr,
                        port
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: conn.foreign_endpoint(),
                    }],
                );
                finding.related_pids = vec![conn.pid];
                finding.related_ips = vec![conn.foreign_addr.clone()];
                finding.timestamp = conn.created;
                finding.confidence = 0.9;
                findings.push(finding);
            }
        }

        findings
    }
}
