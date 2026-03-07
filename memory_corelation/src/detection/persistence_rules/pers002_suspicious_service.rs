//! PERS002 – SuspiciousServiceRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious Windows services
pub struct SuspiciousServiceRule {
    blacklist: crate::config::BlacklistConfig,
}

impl SuspiciousServiceRule {
    pub fn new() -> Self {
        let blacklist = crate::config::BlacklistConfig::load_from_file("config/blacklist.json")
            .unwrap_or_default();
        Self { blacklist }
    }
}

impl DetectionRule for SuspiciousServiceRule {
    fn id(&self) -> &str {
        "PERS002"
    }

    fn name(&self) -> &str {
        "Suspicious Service"
    }

    fn description(&self) -> &str {
        "Detects Windows services with suspicious characteristics (path, name, binary)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1543.003") // Create or Modify System Process: Windows Service
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        use std::collections::HashSet;
        
        let mut findings = Vec::new();
        let mut seen_services: HashSet<String> = HashSet::new();

        for svc in &data.services {
            // Deduplicate by service name (case-insensitive)
            let svc_key = svc.name.to_lowercase();
            if seen_services.contains(&svc_key) {
                continue;
            }
            
            let mut sus_reasons = Vec::new();

            if let Some(path) = &svc.binary_path {
                let lower_path = path.to_lowercase();
                
                // Known-safe service paths that should override blacklist matches
                let safe_service_paths = [
                    "\\microsoft\\windows defender\\",
                    "\\windows defender\\",
                    "\\windows defender advanced threat protection\\",
                    "\\microsoft\\office\\",
                    "\\common files\\microsoft shared\\clicktorun\\",
                ];
                
                let is_known_safe = safe_service_paths.iter().any(|sp| lower_path.contains(sp));
                
                if !is_known_safe && self.blacklist.is_suspicious(path) {
                    sus_reasons.push("binary in suspicious location");
                }
            }
            if svc.is_suspicious_name() {
                sus_reasons.push("suspicious service name");
            }
            if svc.has_suspicious_execution() {
                sus_reasons.push("suspicious execution pattern");
            }

            if !sus_reasons.is_empty() {
                // Mark as seen even if suspicious (to prevent duplicates)
                seen_services.insert(svc_key);
                
                let severity = if svc.has_suspicious_execution() {
                    Severity::Critical
                } else if sus_reasons.len() >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut finding = create_finding(
                    self,
                    format!("Suspicious service: {}", svc.name),
                    format!(
                        "Service '{}' has suspicious characteristics: {}. Binary: {}",
                        svc.name,
                        sus_reasons.join(", "),
                        svc.binary_path.as_deref().unwrap_or("-")
                    ),
                    vec![Evidence {
                        source_plugin: "svcscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!(
                            "Name: {} Binary: {}",
                            svc.name,
                            svc.binary_path.as_deref().unwrap_or("-")
                        ),
                    }],
                );
                finding.severity = severity;
                finding.related_pids = svc.pid.as_ref().and_then(|p| p.parse().ok()).into_iter().collect();
                finding.related_files = svc.binary_path.clone().into_iter().collect();
                finding.confidence = 0.7 + (sus_reasons.len() as f32 * 0.1);
                findings.push(finding);
            }
        }

        findings
    }
}
