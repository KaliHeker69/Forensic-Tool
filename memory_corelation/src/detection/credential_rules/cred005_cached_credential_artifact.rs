//! CRED005 – CachedCredentialArtifactRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect evidence of cached credential extraction artifacts
pub struct CachedCredentialArtifactRule;

impl DetectionRule for CachedCredentialArtifactRule {
    fn id(&self) -> &str {
        "CRED005"
    }

    fn name(&self) -> &str {
        "Cached Credential Artifact"
    }

    fn description(&self) -> &str {
        "Detects extracted cached credential artifacts from cachedump output"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1003.005")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.cachedump_records.is_empty() {
            return findings;
        }

        let count = data.cachedump_records.len();
        let mut finding = create_finding(
            self,
            format!("Cached credential records detected ({})", count),
            "cachedump output contains credential cache artifacts, which may indicate credential dumping activity or post-compromise collection.".to_string(),
            vec![Evidence {
                source_plugin: "cachedump".to_string(),
                source_file: String::new(),
                line_number: None,
                data: format!("CachedumpRecords:{}", count),
            }],
        );
        finding.confidence = 0.95;
        findings.push(finding);

        findings
    }
}
