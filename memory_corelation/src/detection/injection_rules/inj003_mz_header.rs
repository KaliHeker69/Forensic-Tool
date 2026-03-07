//! INJ003 – MzHeaderRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect MZ headers in memory (PE files)
pub struct MzHeaderRule;

impl DetectionRule for MzHeaderRule {
    fn id(&self) -> &str {
        "INJ003"
    }

    fn name(&self) -> &str {
        "MZ Header in Memory"
    }

    fn description(&self) -> &str {
        "Detects PE file headers in suspicious memory regions indicating reflective loading"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1620") // Reflective Code Loading
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Processes that legitimately have MZ headers in non-module memory
        // Use prefix matching to handle Volatility's 15-char name truncation
        // NOTE: lsass is NOT exempted — MZ headers in lsass indicate DLL injection (T1003)
        let mz_exempt_prefixes = [
            "csrss",          // Windows subsystem process
            "msmpeng",        // Defender scanning engine
            "mssense",        // ATP sensor
            "svchost",        // Multiple services with COM DLLs
        ];

        for mal in &data.malfind {
            if mal.has_mz_header() {
                let lower_proc = mal.process.to_lowercase();
                if mz_exempt_prefixes.iter().any(|p| lower_proc.starts_with(p)) {
                    continue;
                }
                let mut finding = create_finding(
                    self,
                    format!("PE file in memory: {} (PID:{})", mal.process, mal.pid),
                    format!(
                        "PE file (MZ header) detected in process {} memory at {}. \
                         This indicates reflective DLL injection or process hollowing.",
                        mal.process, mal.start
                    ),
                    vec![Evidence {
                        source_plugin: "malfind".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: mal
                            .hexdump
                            .as_ref()
                            .map(|h| h.chars().take(100).collect())
                            .unwrap_or_default(),
                    }],
                );
                finding.related_pids = vec![mal.pid];
                finding.confidence = 0.95;
                findings.push(finding);
            }
        }

        findings
    }
}

// Code injection detection rules

