//! CERT002 – MimickedCACertificateRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting certificates that mimic legitimate CAs
pub struct MimickedCACertificateRule;

impl DetectionRule for MimickedCACertificateRule {
    fn id(&self) -> &str {
        "CERT002"
    }

    fn name(&self) -> &str {
        "CA Certificate Mimicry Detection"
    }

    fn description(&self) -> &str {
        "Detects certificates with names similar to legitimate CAs that may indicate tampering"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cert in &data.certificates {
            if cert.mimics_legitimate_ca() {
                findings.push(create_finding(
                    self,
                    format!("Certificate mimics legitimate CA: {}", cert.certificate_name),
                    format!(
                        "Certificate '{}' appears to mimic a legitimate Certificate Authority \
                        in store: {}. This may indicate certificate tampering or MITM attempt.",
                        cert.certificate_name, cert.store_category()
                    ),
                    vec![Evidence {
                        source_plugin: "certificates".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Name:{} ID:{}", cert.certificate_name, cert.certificate_id),
                    }],
                ));
            }
        }

        findings
    }
}
