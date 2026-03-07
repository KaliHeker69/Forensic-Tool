//! CERT001 – RogueCACertificateRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting rogue CA certificates in trusted root store
pub struct RogueCACertificateRule;

impl DetectionRule for RogueCACertificateRule {
    fn id(&self) -> &str {
        "CERT001"
    }

    fn name(&self) -> &str {
        "Rogue CA Certificate Detection"
    }

    fn description(&self) -> &str {
        "Detects suspicious certificates in the trusted root CA store that could enable MITM attacks"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1553.004")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cert in &data.certificates {
            if cert.is_potential_rogue_ca() {
                findings.push(create_finding(
                    self,
                    format!("Suspicious CA certificate: {}", cert.certificate_name),
                    format!(
                        "Certificate '{}' in trusted root store has suspicious characteristics. \
                        Path: {} (ID: {}). This could enable MITM attacks.",
                        cert.certificate_name, cert.certificate_path, cert.certificate_id
                    ),
                    vec![Evidence {
                        source_plugin: "certificates".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Name:{} Path:{} Section:{}", 
                            cert.certificate_name, cert.certificate_path, cert.certificate_section),
                    }],
                ));
            }
        }

        findings
    }
}
