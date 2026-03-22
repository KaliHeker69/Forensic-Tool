//! NET005 – ListeningPortAnalysisRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unusual listening ports that may indicate backdoors or C2 servers
pub struct ListeningPortAnalysisRule;

impl DetectionRule for ListeningPortAnalysisRule {
    fn id(&self) -> &str {
        "NET005"
    }

    fn name(&self) -> &str {
        "Listening Port Analysis"
    }

    fn description(&self) -> &str {
        "Detects unusual listening ports that may indicate backdoors or reverse shells"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1571") // Non-Standard Port
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tuning = crate::config::network_tuning();
        let mut seen: std::collections::HashSet<(u32, u16)> = std::collections::HashSet::new();

        for conn in &data.connections {
            if !conn.is_listening() {
                continue;
            }

            let port = conn.local_port;
            let owner = conn.owner.as_deref().unwrap_or("?");

            if tuning.is_ip_allowlisted(&conn.local_addr) {
                continue;
            }

            // Skip already seen
            if seen.contains(&(conn.pid, port)) {
                continue;
            }
            seen.insert((conn.pid, port));

            // Check: is this a backdoor port?
            let suspicious_port = tuning.is_suspicious_port(port);
            let expected_listener = tuning.is_expected_listener_process(owner);
            let expected_port = tuning.is_expected_listener_port(port);
            let non_local_bind = conn.local_addr != "127.0.0.1" && conn.local_addr != "::1";

            // Multi-attribute gating for medium/high.
            let mut signal_count = 0u8;
            if suspicious_port {
                signal_count += 1;
            }
            if !expected_listener {
                signal_count += 1;
            }
            if !expected_port {
                signal_count += 1;
            }
            if non_local_bind {
                signal_count += 1;
            }

            if suspicious_port {
                let mut finding = create_finding(
                    self,
                    format!("Suspicious listening port: {} on port {}", owner, port),
                    format!(
                        "Process '{}' (PID {}) is listening on port {} which is commonly \
                        used by backdoors and C2 frameworks.",
                        owner, conn.pid, port
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} {}:{} LISTENING", conn.protocol, conn.local_addr, port),
                    }],
                );
                finding.severity = if signal_count >= 3 { Severity::High } else { Severity::Medium };
                finding.related_pids = vec![conn.pid];
                finding.confidence = if signal_count >= 3 { 0.9 } else { 0.75 };
                findings.push(finding);
                continue;
            }

            if signal_count >= 2 && !expected_listener && !expected_port {
                let mut finding = create_finding(
                    self,
                    format!("Unusual listener: {} on port {}", owner, port),
                    format!(
                        "Process '{}' (PID {}) is listening on non-standard port {}. \
                        This may indicate a backdoor, reverse shell, or unauthorized service.",
                        owner, conn.pid, port
                    ),
                    vec![Evidence {
                        source_plugin: "netscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} {}:{} LISTENING", conn.protocol, conn.local_addr, port),
                    }],
                );
                finding.severity = if signal_count >= 3 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                finding.related_pids = vec![conn.pid];
                finding.confidence = if signal_count >= 3 { 0.8 } else { 0.65 };
                findings.push(finding);
            }
        }

        findings
    }
}
