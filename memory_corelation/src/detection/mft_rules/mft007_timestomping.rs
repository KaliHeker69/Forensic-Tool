//! MFT007 – TimestompingDetectionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::mft::MftEntry;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Rule for detecting potential timestomping
pub struct TimestompingDetectionRule;

impl DetectionRule for TimestompingDetectionRule {
    fn id(&self) -> &str {
        "MFT007"
    }

    fn name(&self) -> &str {
        "Timestomping Detection"
    }

    fn description(&self) -> &str {
        "Detects potential timestamp manipulation by comparing $SI and $FN timestamps"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1070.006")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        use std::collections::HashMap;

        // Group entries by record number to compare $SI vs $FN
        let mut by_record: HashMap<u64, Vec<&MftEntry>> = HashMap::new();
        for entry in &data.mft_entries {
            if let Some(record_num) = entry.record_number {
                by_record.entry(record_num).or_default().push(entry);
            }
        }

        for (record_num, entries) in by_record {
            if entries.len() < 2 {
                continue;
            }

            let si_entry = entries.iter().find(|e| {
                e.attribute_type
                    .as_ref()
                    .map(|a| a.contains("STANDARD_INFORMATION"))
                    .unwrap_or(false)
            });

            let fn_entry = entries.iter().find(|e| {
                e.attribute_type
                    .as_ref()
                    .map(|a| a.contains("FILE_NAME"))
                    .unwrap_or(false)
            });

            if let (Some(si), Some(fn_)) = (si_entry, fn_entry) {
                if let (Some(si_created), Some(fn_created)) = 
                    (si.parse_created(), fn_.parse_created()) 
                {
                    let diff = (si_created - fn_created).num_seconds().abs();
                    
                    if diff > 86400 {
                        let filename = si.filename.as_deref().unwrap_or("unknown");
                        findings.push(create_finding(
                            self,
                            format!("Potential timestomping: {}", filename),
                            format!(
                                "$STANDARD_INFORMATION and $FILE_NAME timestamps differ by {} hours. \
                                This indicates potential timestamp manipulation. File: {} (Record: {})",
                                diff / 3600, filename, record_num
                            ),
                            vec![Evidence {
                                source_plugin: "mftscan".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!("Filename:{} RecordNum:{} TimeDiff:{}h", filename, record_num, diff / 3600),
                            }],
                        ));
                    }
                }
            }
        }

        findings
    }
}

// MFT-based detection rules for identifying suspicious filesystem activity

