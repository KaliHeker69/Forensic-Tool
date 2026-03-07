//! CERT004 – SelfSignedRootCertificateRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting self-signed certificates in root store
pub struct SelfSignedRootCertificateRule;

impl DetectionRule for SelfSignedRootCertificateRule {
    fn id(&self) -> &str {
        "CERT004"
    }

    fn name(&self) -> &str {
        "Self-Signed Root Certificate Detection"
    }

    fn description(&self) -> &str {
        "Detects self-signed or test certificates installed in the root certificate store"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1553.004")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        let self_signed_patterns = [
            "self-signed",
            "selfsigned",
            "localhost",
            "my certificate",
            "local ca",
        ];

        // Slightly broader patterns that need exact word matching
        let broad_patterns = [
            "test ca",
            "test root",
            "dev ca",
            "dev root",
        ];

        for cert in &data.certificates {
            if !cert.is_in_root_store() {
                continue;
            }

            let lower_name = cert.certificate_name.to_lowercase();
            let mut matched_pattern = None;

            for pattern in &self_signed_patterns {
                if lower_name.contains(pattern) {
                    matched_pattern = Some(*pattern);
                    break;
                }
            }

            if matched_pattern.is_none() {
                for pattern in &broad_patterns {
                    if lower_name.contains(pattern) {
                        matched_pattern = Some(*pattern);
                        break;
                    }
                }
            }

            if let Some(pattern) = matched_pattern {
                findings.push(create_finding(
                    self,
                    format!("Self-signed certificate in root store: {}", cert.certificate_name),
                    format!(
                        "Certificate '{}' appears to be self-signed or for testing (matched: '{}').",
                        cert.certificate_name, pattern
                    ),
                    vec![Evidence {
                        source_plugin: "certificates".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Name:{} Section:{}", cert.certificate_name, cert.certificate_section),
                    }],
                ));
            }
        }

        findings
    }
}
