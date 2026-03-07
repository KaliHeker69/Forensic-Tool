//! CERT005 – CertificateStoreAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting certificate store anomalies
pub struct CertificateStoreAnomalyRule;

impl DetectionRule for CertificateStoreAnomalyRule {
    fn id(&self) -> &str {
        "CERT005"
    }

    fn name(&self) -> &str {
        "Certificate Store Anomaly Detection"
    }

    fn description(&self) -> &str {
        "Detects unusual patterns in certificate stores that may indicate tampering"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1562.001")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        let suspicious_in_root = data
            .certificates
            .iter()
            .filter(|c| c.is_in_root_store() && c.has_suspicious_name())
            .count();

        if suspicious_in_root > 3 {
            findings.push(create_finding(
                self,
                format!("Multiple suspicious root certificates ({})", suspicious_in_root),
                "Multiple suspicious certificates found in the root certificate store. This may indicate widespread certificate tampering.".to_string(),
                vec![Evidence {
                    source_plugin: "certificates".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("SuspiciousCount:{}", suspicious_in_root),
                }],
            ));
        }

        let total_certs = data.certificates.len();
        let empty_names = data
            .certificates
            .iter()
            .filter(|c| c.certificate_name.trim().is_empty())
            .count();

        // Empty certificate names can occur in partial/corrupt extraction output.
        // Alert only when this is statistically significant.
        let empty_ratio = if total_certs > 0 {
            empty_names as f64 / total_certs as f64
        } else {
            0.0
        };

        if empty_names >= 25 || (empty_names >= 10 && empty_ratio >= 0.20) {
            let mut finding = create_finding(
                self,
                format!(
                    "Certificates with empty names ({}/{}, {:.0}%)",
                    empty_names,
                    total_certs,
                    empty_ratio * 100.0
                ),
                "A significant portion of certificates have empty names. This may indicate store corruption, parser issues, or tampering and should be validated against raw plugin output.".to_string(),
                vec![Evidence {
                    source_plugin: "certificates".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "EmptyNameCount:{} Total:{} Ratio:{:.3}",
                        empty_names, total_certs, empty_ratio
                    ),
                }],
            );
            finding.severity = Severity::Low;
            finding.confidence = 0.55;
            findings.push(finding);
        }

        findings
    }
}

// Certificate-based detection rules for identifying suspicious certificate stores

