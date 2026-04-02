//! XCOR001 – ThreadInMalfindRegionRule
use super::xcor006_dll_injection_handle_correlation::parse_hex_addr;
use std::collections::HashMap;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Cross-correlate thread start addresses with malfind suspicious regions.
/// A thread starting inside a malfind-detected region is very strong evidence
/// of injected code that is actively executing.
pub struct ThreadInMalfindRegionRule;

impl DetectionRule for ThreadInMalfindRegionRule {
    fn id(&self) -> &str {
        "XCOR001"
    }

    fn name(&self) -> &str {
        "Thread Executing in Injected Region"
    }

    fn description(&self) -> &str {
        "Detects threads whose start address falls within a malfind-detected suspicious memory region"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build map of malfind regions per PID: PID -> Vec<(start_addr, end_addr, protection)>
        let mut malfind_regions: HashMap<u32, Vec<(u64, u64, String)>> = HashMap::new();
        for mf in &data.malfind {
            let start = parse_hex_addr(&mf.start);
            let end = parse_hex_addr(&mf.end);
            if let (Some(s), Some(e)) = (start, end) {
                malfind_regions
                    .entry(mf.pid)
                    .or_default()
                    .push((s, e, mf.protection.clone()));
            }
        }

        if malfind_regions.is_empty() {
            return findings;
        }

        // Check each thread's start address against malfind regions for same PID
        for thread in &data.threads {
            if let Some(regions) = malfind_regions.get(&thread.pid) {
                // Check kernel start address
                if let Some(start_addr) = thread.start_address {
                    for (region_start, region_end, protection) in regions {
                        if start_addr >= *region_start && start_addr <= *region_end {
                            let mut finding = create_finding(
                                self,
                                format!(
                                    "Thread TID {} executing in injected memory (PID {})",
                                    thread.tid, thread.pid
                                ),
                                format!(
                                    "Thread TID {} in PID {} has start address {:#x} which falls within \
                                    a malfind-detected suspicious memory region ({:#x}-{:#x}, {}). \
                                    This is strong evidence of injected code that is actively executing.",
                                    thread.tid, thread.pid, start_addr,
                                    region_start, region_end, protection
                                ),
                                vec![
                                    Evidence {
                                        source_plugin: "thrdscan+malfind".to_string(),
                                        source_file: String::new(),
                                        line_number: None,
                                        data: format!(
                                            "TID:{} StartAddr:{:#x} MalfindRegion:{:#x}-{:#x} Protection:{}",
                                            thread.tid, start_addr, region_start, region_end, protection
                                        ),
                                    },
                                ],
                            );
                            finding.related_pids = vec![thread.pid];
                            finding.confidence = 0.95;
                            findings.push(finding);
                            break;
                        }
                    }
                }

                // Check Win32 start address
                if let Some(win32_addr) = thread.win32_start_address {
                    for (region_start, region_end, protection) in regions {
                        if win32_addr >= *region_start && win32_addr <= *region_end {
                            // Check we didn't already flag this thread via kernel address
                            let already_flagged = findings.iter().any(|f| {
                                f.related_pids.contains(&thread.pid)
                                    && f.title.contains(&format!("TID {}", thread.tid))
                            });
                            if already_flagged {
                                break;
                            }

                            let mut finding = create_finding(
                                self,
                                format!(
                                    "Thread TID {} Win32 start in injected memory (PID {})",
                                    thread.tid, thread.pid
                                ),
                                format!(
                                    "Thread TID {} in PID {} has Win32 start address {:#x} within \
                                    malfind region ({:#x}-{:#x}, {}).",
                                    thread.tid, thread.pid, win32_addr,
                                    region_start, region_end, protection
                                ),
                                vec![Evidence {
                                    source_plugin: "thrdscan+malfind".to_string(),
                                    source_file: String::new(),
                                    line_number: None,
                                    data: format!(
                                        "TID:{} Win32Addr:{:#x} Region:{:#x}-{:#x}",
                                        thread.tid, win32_addr, region_start, region_end
                                    ),
                                }],
                            );
                            finding.related_pids = vec![thread.pid];
                            finding.confidence = 0.93;
                            findings.push(finding);
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// XCOR002: Privilege + Injection Cross-Reference
// ---------------------------------------------------------------------------
