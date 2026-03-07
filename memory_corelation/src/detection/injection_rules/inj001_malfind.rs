//! INJ001 – MalfindDetectionRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect malfind results indicating code injection
pub struct MalfindDetectionRule;

impl DetectionRule for MalfindDetectionRule {
    fn id(&self) -> &str {
        "INJ001"
    }

    fn name(&self) -> &str {
        "Malfind Detection"
    }

    fn description(&self) -> &str {
        "Detects potentially injected code found by the malfind plugin"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055") // Process Injection
    }

    fn detect(&self, _data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Processes known to produce high malfind counts legitimately
        // Use prefix matching to handle Volatility's 15-char name truncation
        let known_high_malfind_processes = [
            "msmpeng",       // Windows Defender - JIT scanning engine
            "mssense",       // Defender ATP
            "nissrv",        // NIS service (Defender)
            "smartscreen",   // SmartScreen uses .NET JIT
        ];

        for summary in engine.injection_analysis() {
            if summary.risk_score < 30 {
                continue;
            }

            let lower_name = summary.process_name.to_lowercase();

            // Skip known high-malfind processes (prefix match for truncated names)
            if known_high_malfind_processes.iter().any(|p| lower_name.starts_with(p)) {
                continue;
            }

            // Downgrade lsass MZ headers - SSPs are legitimately loaded DLLs
            // BUT: if lsass has MZ headers, still report at Medium (real injections
            // like inject.x64.exe produce MZ headers in lsass memory)
            let is_lsass = lower_name == "lsass.exe" || lower_name.starts_with("lsass");
            if is_lsass && summary.mz_headers_found == 0 && summary.shellcode_patterns == 0 {
                // lsass with only RWX regions and no MZ/shellcode = likely SSP loading
                continue;
            }

            let severity = if summary.risk_score >= 80 {
                Severity::Critical
            } else if summary.risk_score >= 60 {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut indicators = Vec::new();
            if summary.mz_headers_found > 0 {
                indicators.push(format!("{} MZ headers", summary.mz_headers_found));
            }
            if summary.shellcode_patterns > 0 {
                indicators.push(format!("{} shellcode patterns", summary.shellcode_patterns));
            }
            if summary.rwx_regions > 0 {
                indicators.push(format!("{} RWX regions", summary.rwx_regions));
            }
            if !summary.yara_matches.is_empty() {
                indicators.push(format!("YARA: {}", summary.yara_matches.join(", ")));
            }

            let mut finding = create_finding(
                self,
                format!(
                    "Code injection in {} (PID:{})",
                    summary.process_name, summary.pid
                ),
                format!(
                    "Process {} shows {} injection indicators: {}",
                    summary.process_name,
                    summary.malfind_count,
                    indicators.join(", ")
                ),
                vec![Evidence {
                    source_plugin: "malfind".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "Risk score: {}/100, {} suspicious regions",
                        summary.risk_score, summary.malfind_count
                    ),
                }],
            );
            finding.severity = severity;
            finding.related_pids = vec![summary.pid];
            finding.confidence = (summary.risk_score as f32) / 100.0;
            findings.push(finding);
        }

        findings
    }
}
