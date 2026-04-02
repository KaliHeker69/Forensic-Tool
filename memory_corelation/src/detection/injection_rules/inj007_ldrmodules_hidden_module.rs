//! INJ007 – LdrModulesHiddenModuleRule
use std::collections::HashMap;

use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect hidden/unlinked modules from windows.ldrmodules and correlate with malfind.
pub struct LdrModulesHiddenModuleRule;

impl DetectionRule for LdrModulesHiddenModuleRule {
    fn id(&self) -> &str {
        "INJ007"
    }

    fn name(&self) -> &str {
        "LdrModules Hidden Module Detection"
    }

    fn description(&self) -> &str {
        "Detects modules hidden from PEB loader lists and correlates with malfind memory regions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.001")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.ldrmodules.is_empty() {
            return findings;
        }

        let mut malfind_ranges: HashMap<u32, Vec<(u64, u64)>> = HashMap::new();
        for mf in &data.malfind {
            if let (Some(start), Some(end)) = (parse_hex_addr(&mf.start), parse_hex_addr(&mf.end)) {
                malfind_ranges.entry(mf.pid).or_default().push((start, end));
            }
        }

        let mut hidden_count: HashMap<u32, usize> = HashMap::new();

        for module in &data.ldrmodules {
            let is_hidden = module.is_hidden_from_peb();
            let is_unlinked = module.is_unlinked();
            if !is_hidden && !is_unlinked {
                continue;
            }

            let overlap = malfind_ranges
                .get(&module.pid)
                .map(|ranges| ranges.iter().any(|(s, e)| module.base >= *s && module.base < *e))
                .unwrap_or(false);

            let path = module.mapped_path_or_empty();
            let no_path = path.is_empty() || path == "-";
            let suspicious_path = module.has_suspicious_path();

            let mut finding = create_finding(
                self,
                format!(
                    "Suspicious module visibility anomaly in {} (PID:{})",
                    module.process, module.pid
                ),
                format!(
                    "Module at base 0x{:x} is {} (InLoad={:?}, InInit={:?}, InMem={:?}). \
                    MappedPath='{}'.{}{}",
                    module.base,
                    if is_hidden {
                        "hidden from all PEB loader lists"
                    } else {
                        "partially unlinked from loader lists"
                    },
                    module.in_load,
                    module.in_init,
                    module.in_mem,
                    if no_path { "(empty)" } else { path },
                    if overlap {
                        " Overlaps a malfind suspicious memory region."
                    } else {
                        ""
                    },
                    if suspicious_path {
                        " Path context is suspicious for reflective or side-loaded injection."
                    } else {
                        ""
                    },
                ),
                vec![Evidence {
                    source_plugin: if overlap {
                        "ldrmodules+malfind".to_string()
                    } else {
                        "ldrmodules".to_string()
                    },
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "PID:{} Base:0x{:x} InLoad:{:?} InInit:{:?} InMem:{:?} Path:{} OverlapMalfind:{}",
                        module.pid,
                        module.base,
                        module.in_load,
                        module.in_init,
                        module.in_mem,
                        if no_path { "(empty)" } else { path },
                        overlap
                    ),
                }],
            );

            finding.related_pids = vec![module.pid];
            if !no_path {
                finding.related_files.push(path.to_string());
            }

            finding.severity = if overlap || (is_hidden && no_path) {
                Severity::Critical
            } else if is_hidden {
                Severity::High
            } else {
                Severity::Medium
            };

            finding.confidence = if overlap {
                0.97
            } else if is_hidden && suspicious_path {
                0.90
            } else if is_hidden {
                0.82
            } else {
                0.72
            };

            *hidden_count.entry(module.pid).or_insert(0) += 1;
            findings.push(finding);
        }

        // Add one aggregate finding per process with multiple hidden modules to improve analyst triage.
        for (pid, count) in hidden_count {
            if count < 3 {
                continue;
            }
            let process_name = data
                .ldrmodules
                .iter()
                .find(|m| m.pid == pid)
                .map(|m| m.process.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let mut agg = create_finding(
                self,
                format!(
                    "{} hidden/unlinked modules in {} (PID:{})",
                    count, process_name, pid
                ),
                format!(
                    "Process '{}' (PID {}) has {} ldrmodules anomalies. \
                    Multiple hidden or unlinked modules significantly increases confidence of loader tampering or reflective injection.",
                    process_name, pid, count
                ),
                vec![Evidence {
                    source_plugin: "ldrmodules".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("PID:{} HiddenOrUnlinkedModules:{}", pid, count),
                }],
            );
            agg.related_pids = vec![pid];
            agg.severity = if count >= 6 { Severity::Critical } else { Severity::High };
            agg.confidence = if count >= 6 { 0.95 } else { 0.88 };
            findings.push(agg);
        }

        findings
    }
}

fn parse_hex_addr(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hex = trimmed.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).or_else(|_| trimmed.parse::<u64>()).ok()
}
