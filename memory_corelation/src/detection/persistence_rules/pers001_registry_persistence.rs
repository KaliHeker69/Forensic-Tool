//! PERS001 – RegistryPersistenceRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect registry-based persistence mechanisms
pub struct RegistryPersistenceRule;

impl DetectionRule for RegistryPersistenceRule {
    fn id(&self) -> &str {
        "PERS001"
    }

    fn name(&self) -> &str {
        "Registry Persistence"
    }

    fn description(&self) -> &str {
        "Detects persistence mechanisms in registry Run keys and other autostart locations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1547.001") // Boot or Logon Autostart: Registry Run Keys
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for key in engine.find_persistence_keys() {
            let has_data = key.data.as_ref().map(|d| !d.trim().is_empty()).unwrap_or(false);

            let severity = if key.has_obfuscated_data() {
                Severity::Critical
            } else if key.has_executable_data() {
                Severity::High
            } else if has_data {
                Severity::Medium
            } else {
                // Key exists in user hive but no data visible
                Severity::Low
            };

            let mut finding = create_finding(
                self,
                format!("Registry persistence: {}", key.base_name()),
                format!(
                    "Persistence mechanism detected in registry key '{}' with value: {}",
                    key.key,
                    key.data.as_deref().unwrap_or("-")
                ),
                vec![Evidence {
                    source_plugin: "printkey".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "{} = {}",
                        key.key,
                        key.data.as_deref().unwrap_or("")
                    ),
                }],
            );
            finding.severity = severity;
            finding.timestamp = key.last_write;
            finding.related_files = key.data.clone().into_iter().collect();

            if key.has_obfuscated_data() {
                finding.confidence = 0.95;
            } else {
                finding.confidence = 0.75;
            }

            findings.push(finding);
        }

        findings
    }
}
