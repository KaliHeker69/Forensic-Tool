//! NET001 – ExternalConnectionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect external network connections from non-browser processes
pub struct ExternalConnectionRule;

impl DetectionRule for ExternalConnectionRule {
    fn id(&self) -> &str {
        "NET001"
    }

    fn name(&self) -> &str {
        "External Network Connection"
    }

    fn description(&self) -> &str {
        "Detects connections to external (non-RFC1918) IP addresses from processes"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1071") // Application Layer Protocol
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tuning = crate::config::network_tuning();

        for link in engine.network_process_correlation() {
            if !link.connection.is_external() {
                continue;
            }

            if tuning.is_ip_allowlisted(&link.connection.foreign_addr) {
                continue;
            }

            // Accept ESTABLISHED, CLOSE_WAIT, CLOSED, TIME_WAIT, SYN_SENT
            // (all indicate active/recent communication)
            let state = link.connection.state.as_deref().unwrap_or("");
            let state_upper = state.to_uppercase();
            let is_active = state_upper.contains("ESTABLISHED")
                || state_upper.contains("CLOSE_WAIT")
                || state_upper.contains("CLOSED")
                || state_upper.contains("TIME_WAIT")
                || state_upper.contains("SYN_SENT")
                || state_upper.contains("FIN_WAIT");

            if !is_active {
                continue;
            }

            let process_name = link
                .process
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or("?");

            if tuning.is_allowlisted_process(process_name) {
                continue;
            }

            let is_browser_web = tuning.is_browser_process(process_name)
                && link.connection.is_established()
                && link.connection.is_common_web_port();

            let suspicious_cmdline = link
                .cmdline
                .as_ref()
                .map(|cmd| {
                    let lower = cmd.to_lowercase();
                    lower.contains("-enc")
                        || lower.contains("-e ")
                        || lower.contains("-w hidden")
                        || lower.contains("downloadstring")
                })
                .unwrap_or(false);

            // Benign browsing should remain contextual, not an alert.
            if is_browser_web && !suspicious_cmdline {
                continue;
            }

            let suspicious_port = tuning.is_suspicious_port(link.connection.foreign_port)
                || tuning.is_suspicious_port(link.connection.local_port);
            let high_risk_remote = tuning.is_high_risk_remote_port(link.connection.foreign_port);
            let unusual_process = !tuning.is_expected_network_process(process_name);
            let non_web_channel = !link.connection.is_common_web_port();

            let mut signal_count = 0u8;
            if unusual_process {
                signal_count += 1;
            }
            if suspicious_port || high_risk_remote {
                signal_count += 1;
            }
            if suspicious_cmdline {
                signal_count += 1;
            }
            if non_web_channel {
                signal_count += 1;
            }

            // Multi-attribute gating: don't raise medium/high without corroboration.
            if signal_count == 0 {
                continue;
            }

            let severity = if signal_count >= 3 {
                Severity::High
            } else if signal_count >= 2 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut finding = create_finding(
                self,
                format!(
                    "External connection: {} → {}",
                    process_name,
                    link.connection.foreign_endpoint()
                ),
                format!(
                    "Process {} (PID:{}) has {} connection to external address {}:{}",
                    process_name,
                    link.connection.pid,
                    state,
                    link.connection.foreign_addr,
                    link.connection.foreign_port
                ),
                vec![Evidence {
                    source_plugin: "netscan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "{} {} → {} [{}]",
                        link.connection.protocol,
                        link.connection.local_endpoint(),
                        link.connection.foreign_endpoint(),
                        state
                    ),
                }],
            );
            finding.severity = severity;
            finding.related_pids = vec![link.connection.pid];
            finding.related_ips = vec![link.connection.foreign_addr.clone()];
            finding.timestamp = link.connection.created;
            finding.confidence = match severity {
                Severity::High => 0.9,
                Severity::Medium => 0.75,
                _ => 0.55,
            };
            findings.push(finding);
        }

        findings
    }
}
