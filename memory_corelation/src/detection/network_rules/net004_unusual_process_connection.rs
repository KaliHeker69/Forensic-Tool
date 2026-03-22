//! NET004 – UnusualProcessConnectionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unusual processes making external network connections
/// Flags processes not typically expected to have network activity
pub struct UnusualProcessConnectionRule;

impl DetectionRule for UnusualProcessConnectionRule {
    fn id(&self) -> &str {
        "NET004"
    }

    fn name(&self) -> &str {
        "Unusual Process Network Activity"
    }

    fn description(&self) -> &str {
        "Detects processes that should not typically make external network connections"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1071") // Application Layer Protocol
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tuning = crate::config::network_tuning();
        let mut seen: std::collections::HashSet<(u32, String, u16)> = std::collections::HashSet::new();

        for conn in &data.connections {
            if !conn.is_external() {
                continue;
            }

            if tuning.is_ip_allowlisted(&conn.foreign_addr) {
                continue;
            }

            let owner = conn.owner.as_deref().unwrap_or("?");

            // Skip already-reported process+endpoint combinations
            let dedupe_key = (conn.pid, conn.foreign_addr.clone(), conn.foreign_port);
            if !seen.insert(dedupe_key) {
                continue;
            }

            let is_expected = tuning.is_expected_network_process(owner);
            let is_never = tuning.is_never_network_process(owner);

            if is_expected && !is_never {
                continue;
            }

            let cmdline = data
                .cmdlines
                .iter()
                .find(|c| c.pid == conn.pid)
                .map(|c| c.args.to_lowercase())
                .unwrap_or_default();
            let encoded_or_download = cmdline.contains("-enc")
                || cmdline.contains("downloadstring")
                || cmdline.contains("invoke-webrequest")
                || cmdline.contains("bitsadmin");

            let suspicious_port = tuning.is_suspicious_port(conn.foreign_port)
                || tuning.is_suspicious_port(conn.local_port);
            let high_risk_remote = tuning.is_high_risk_remote_port(conn.foreign_port);
            let non_web_channel = !conn.is_common_web_port();

            // Multi-attribute gating for medium/high.
            let mut corroborating = 0u8;
            if suspicious_port || high_risk_remote {
                corroborating += 1;
            }
            if encoded_or_download {
                corroborating += 1;
            }
            if non_web_channel {
                corroborating += 1;
            }

            if !is_never && corroborating == 0 {
                continue;
            }

            let severity = if is_never && corroborating >= 1 {
                Severity::Critical
            } else if corroborating >= 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            let state = conn.state.as_deref().unwrap_or("UNKNOWN");

            let mut finding = create_finding(
                self,
                format!("Unusual network activity: {} → {}:{}",
                    owner, conn.foreign_addr, conn.foreign_port),
                format!(
                    "Process '{}' (PID {}) has an external network connection to {}:{} [{}]. \
                    This process is not typically expected to have network activity, which may \
                    indicate C2 communication or data exfiltration.",
                    owner, conn.pid, conn.foreign_addr, conn.foreign_port, state
                ),
                vec![Evidence {
                    source_plugin: "netscan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("{} {}:{} → {}:{} [{}]",
                        conn.protocol, conn.local_addr, conn.local_port,
                        conn.foreign_addr, conn.foreign_port, state),
                }],
            );
            finding.severity = severity;
            finding.related_pids = vec![conn.pid];
            finding.related_ips = vec![conn.foreign_addr.clone()];
            finding.timestamp = conn.created;
            finding.confidence = if is_never && corroborating >= 1 {
                0.95
            } else if corroborating >= 2 {
                0.85
            } else {
                0.7
            };
            findings.push(finding);
        }

        findings
    }
}
