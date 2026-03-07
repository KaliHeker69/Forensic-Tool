//! XCOR005 – HiddenHiveCrossCheckRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Compare hivescan and hivelist results. Hives in hivescan but not hivelist
/// indicate rootkit hidden hives.
pub struct HiddenHiveCrossCheckRule;

impl DetectionRule for HiddenHiveCrossCheckRule {
    fn id(&self) -> &str {
        "XCOR005"
    }

    fn name(&self) -> &str {
        "Hidden Registry Hive (hivescan vs hivelist)"
    }

    fn description(&self) -> &str {
        "Detects registry hives visible in hivescan but missing from hivelist"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1112")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.hives.is_empty() || data.hivescan_hives.is_empty() {
            return findings;
        }

        // Normalize hivelist paths for comparison
        let hivelist_offsets: HashSet<String> = data
            .hives
            .iter()
            .map(|h| h.offset.to_lowercase())
            .collect();

        let hivelist_paths: HashSet<String> = data
            .hives
            .iter()
            .map(|h| h.path.to_lowercase())
            .collect();

        for hive in &data.hivescan_hives {
            let offset_lower = hive.offset.to_lowercase();
            let path_lower = hive.path.to_lowercase();

            // If hive offset isn't in hivelist, it's potentially hidden
            if !hivelist_offsets.contains(&offset_lower)
                && !hivelist_paths.contains(&path_lower)
                && !path_lower.is_empty()
            {
                let mut finding = create_finding(
                    self,
                    format!("Hidden registry hive: {}", hive.path),
                    format!(
                        "Registry hive '{}' at offset {} was found by hivescan (memory scanning) \
                        but is NOT in hivelist (kernel linked list). This may indicate a rootkit \
                        is hiding a registry hive used for persistence.",
                        hive.path, hive.offset
                    ),
                    vec![Evidence {
                        source_plugin: "hivescan vs hivelist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Offset:{} Path:{}", hive.offset, hive.path),
                    }],
                );
                finding.confidence = 0.88;
                findings.push(finding);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR006: DLL Injection – Handle + Malfind + DLL Correlation
// ---------------------------------------------------------------------------
