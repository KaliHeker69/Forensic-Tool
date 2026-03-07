//! PROC006 – AdvancedCommandLineRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect advanced command line threats (credential access, persistence, defense evasion)
pub struct AdvancedCommandLineRule;

impl DetectionRule for AdvancedCommandLineRule {
    fn id(&self) -> &str {
        "PROC006"
    }

    fn name(&self) -> &str {
        "Advanced Command Line Threat"
    }

    fn description(&self) -> &str {
        "Detects credential access, persistence, defense evasion, and network activity in command lines"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1059") // Command and Scripting Interpreter
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cmdline in &data.cmdlines {
            if cmdline.is_whitelisted_process() {
                continue;
            }

            let mut threats = Vec::new();

            if cmdline.attempts_credential_access() {
                threats.push(("Credential Access", Severity::Critical, "T1003"));
            }
            if cmdline.attempts_persistence() {
                threats.push(("Persistence", Severity::High, "T1547"));
            }
            if cmdline.attempts_defense_evasion() {
                threats.push(("Defense Evasion", Severity::High, "T1562"));
            }
            if cmdline.is_obfuscated() {
                threats.push(("Obfuscation", Severity::Medium, "T1027"));
            }
            if cmdline.has_network_activity() && cmdline.has_suspicious_flags() {
                threats.push(("Suspicious Download", Severity::High, "T1105"));
            }
            if cmdline.has_suspicious_process_chain() {
                threats.push(("Process Chain", Severity::Medium, "T1059"));
            }

            if !threats.is_empty() {
                // Use highest severity from detected threats
                let max_severity = threats
                    .iter()
                    .map(|(_, s, _)| *s)
                    .max()
                    .unwrap_or(Severity::Medium);

                let threat_names: Vec<_> = threats.iter().map(|(n, _, _)| *n).collect();
                let mitre_ids: Vec<_> = threats.iter().map(|(_, _, m)| *m).collect();

                let mut finding = create_finding(
                    self,
                    format!(
                        "Advanced threat in {} (PID:{}): {}",
                        cmdline.process,
                        cmdline.pid,
                        threat_names.join(", ")
                    ),
                    format!(
                        "Command line exhibits {} threat indicators: {}",
                        threats.len(),
                        threat_names.join(", ")
                    ),
                    vec![Evidence {
                        source_plugin: "cmdline".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: cmdline.args.chars().take(200).collect(),
                    }],
                );
                finding.severity = max_severity;
                finding.mitre_attack = Some(mitre_ids.join(", "));
                finding.related_pids = vec![cmdline.pid];
                finding.confidence = 0.85 + (threats.len() as f32 * 0.03).min(0.12);
                findings.push(finding);
            }
        }


        findings
    }
}
