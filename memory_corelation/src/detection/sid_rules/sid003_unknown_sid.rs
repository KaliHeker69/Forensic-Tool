//! SID003 – UnknownSidRule
use std::collections::HashMap;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::models::security::SidInfo;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect unknown/suspicious SIDs attached to processes
pub struct UnknownSidRule;

impl DetectionRule for UnknownSidRule {
    fn id(&self) -> &str {
        "SID003"
    }

    fn name(&self) -> &str {
        "Unknown SID Detection"
    }

    fn description(&self) -> &str {
        "Detects processes with unresolvable or suspicious SIDs"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1134.001")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Group SIDs by PID, look for "unknown" names
        let mut sids_by_pid: HashMap<u32, Vec<&SidInfo>> = HashMap::new();
        for sid in &data.sids {
            sids_by_pid.entry(sid.pid).or_default().push(sid);
        }

        for (pid, sids) in &sids_by_pid {
            let proc_name = sids.first().map(|s| s.process.as_str()).unwrap_or("unknown");
            
            let unknown_sids: Vec<&&SidInfo> = sids
                .iter()
                .filter(|s| {
                    s.has_suspicious_name()
                        && !s.is_integrity_level()
                        && s.is_domain_user()
                })
                .collect();

            let lower_name = proc_name.to_lowercase();
            let likely_service_noise = ["dashost", "runtimebroker", "search", "wmi", "svchost"]
                .iter()
                .any(|p| lower_name.contains(p));

            let min_unknown_threshold = if likely_service_noise { 6 } else { 4 };

            if unknown_sids.len() >= min_unknown_threshold {
                let sid_list: Vec<String> = unknown_sids
                    .iter()
                    .take(5)
                    .map(|s| s.sid.clone())
                    .collect();

                let mut finding = create_finding(
                    self,
                    format!(
                        "{} (PID {}) has {} unresolvable SIDs",
                        proc_name, pid, unknown_sids.len()
                    ),
                    format!(
                        "Process '{}' (PID {}) has {} SIDs that could not be resolved to names. \
                        This may indicate deleted accounts, cross-domain tokens, or token manipulation. \
                        SIDs: {}",
                        proc_name, pid, unknown_sids.len(), sid_list.join(", ")
                    ),
                    vec![Evidence {
                        source_plugin: "getsids".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("PID:{} UnknownSIDs:{}", pid, sid_list.join(",")),
                    }],
                );
                finding.related_pids = vec![*pid];
                finding.confidence = if unknown_sids.len() >= 8 { 0.75 } else { 0.60 };
                if unknown_sids.len() >= 8 {
                    finding.severity = Severity::High;
                } else {
                    finding.severity = Severity::Low;
                }
                findings.push(finding);
            }
        }

        findings
    }
}

pub fn is_expected_low_integrity_system_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    let known_low = [
        "fontdrvhost.exe",
        "fontdrvhost.ex",
        "fontdrvhost",
        "runtimebroker.exe",
        "runtimebroker",
    ];

    known_low
        .iter()
        .any(|p| lower.contains(p) || p.starts_with(&lower) || lower.starts_with(p))
}
