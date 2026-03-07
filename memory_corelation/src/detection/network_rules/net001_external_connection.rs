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

        for link in engine.network_process_correlation() {
            if !link.connection.is_external() {
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

            // Only suppress well-known browsers — all other processes are notable
            if !link.is_suspicious() && is_browser_process(process_name) {
                continue;
            }

            let severity = if link.is_suspicious() {
                Severity::High
            } else if is_os_telemetry_process(process_name) {
                Severity::Low
            } else {
                // Non-browser, non-OS process with external connection
                Severity::Medium
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
            findings.push(finding);
        }

        findings
    }
}

/// Only suppress well-known web browsers
fn is_browser_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    let browsers = [
        "firefox", "chrome", "msedge", "opera", "brave", "iexplore",
    ];
    browsers.iter().any(|p| lower.contains(p))
}

/// OS telemetry / update processes that make expected external connections
fn is_os_telemetry_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    let telemetry = [
        "svchost", "wuauclt", "msmpeng", "mssense", "onedrive",
        "teams", "searchapp",
    ];
    telemetry.iter().any(|p| lower.contains(p))
}
