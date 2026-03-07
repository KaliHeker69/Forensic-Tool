//! MFT003 – AlternateDataStreamRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::mft::MftEntry;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting Alternate Data Streams
pub struct AlternateDataStreamRule;

impl DetectionRule for AlternateDataStreamRule {
    fn id(&self) -> &str {
        "MFT003"
    }

    fn name(&self) -> &str {
        "Alternate Data Stream Detection"
    }

    fn description(&self) -> &str {
        "Detects NTFS Alternate Data Streams which can be used to hide malicious content"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1564.004")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Common legitimate ADS names to filter out
        let benign_ads = [
            "zone.identifier",     // Windows download zone marker
            "encryptable",         // EFS-related
            "wofcompresseddata",   // Windows overlay filter
            "favicon",             // Browser icon
        ];

        for entry in &data.mft_entries {
            if entry.has_alternate_data_stream() {
                let filename = entry.filename.as_deref().unwrap_or("unknown");
                let lower = filename.to_lowercase();

                // Skip known benign ADS types
                if benign_ads.iter().any(|ads| lower.contains(ads)) {
                    continue;
                }

                // Executable ADS is more suspicious
                let has_exe_stream = MftEntry::SUSPICIOUS_EXTENSIONS
                    .iter()
                    .any(|ext| lower.ends_with(ext));

                let mut finding = create_finding(
                    self,
                    format!("Alternate Data Stream: {}", filename),
                    format!(
                        "File with Alternate Data Stream detected. ADS can be used to hide data \
                        or executables. File: {}",
                        filename
                    ),
                    vec![Evidence {
                        source_plugin: "mftscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Filename:{}", filename),
                    }],
                );

                if has_exe_stream {
                    finding.severity = Severity::High;
                    finding.confidence = 0.85;
                } else {
                    finding.confidence = 0.65;
                }

                findings.push(finding);
            }
        }

        findings
    }
}
