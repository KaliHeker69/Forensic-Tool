//! NET003 – BrowserNetworkCorrelationRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Correlate browser activity with network connections
pub struct BrowserNetworkCorrelationRule;

impl DetectionRule for BrowserNetworkCorrelationRule {
    fn id(&self) -> &str {
        "NET003"
    }

    fn name(&self) -> &str {
        "Browser-Network Correlation"
    }

    fn description(&self) -> &str {
        "Detects when suspicious browser URLs correspond to network connections"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1189") // Drive-by Compromise
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get browser-network correlations
        let correlations = engine.browser_network_correlation();

        for event in correlations {
            if event.risk_score >= 50 {
                let mut finding = create_finding(
                    self,
                    "Browser activity correlated with network connection".to_string(),
                    event.description.clone(),
                    vec![Evidence {
                        source_plugin: event.source_plugin.clone(),
                        source_file: String::new(),
                        line_number: None,
                        data: event.description,
                    }],
                );
                finding.related_pids = event.pid.into_iter().collect();
                finding.related_ips = event.related_ips;
                finding.timestamp = Some(event.timestamp);

                if event.risk_score >= 70 {
                    finding.severity = Severity::High;
                }

                findings.push(finding);
            }
        }

        // Also check downloads
        for link in engine.download_file_correlation() {
            if link.is_suspicious() {
                let mut finding = create_finding(
                    self,
                    format!("Downloaded executable found in memory: {}", link.download.filename()),
                    format!(
                        "Executable file '{}' was downloaded from {} and found in {} memory location(s)",
                        link.download.filename(),
                        link.download.url,
                        link.file_count()
                    ),
                    vec![Evidence {
                        source_plugin: "download_history+filescan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} → {}", link.download.url, link.download.target_path),
                    }],
                );
                finding.severity = Severity::High;
                finding.related_files = vec![link.download.target_path.clone()];
                finding.related_ips = link.download.domain().map(|d| d.to_string()).into_iter().collect();
                finding.timestamp = Some(link.download.timestamp);
                findings.push(finding);
            }
        }

        findings
    }
}
