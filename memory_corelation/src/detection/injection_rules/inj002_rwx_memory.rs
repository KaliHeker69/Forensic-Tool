//! INJ002 – RwxMemoryRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect RWX memory regions
pub struct RwxMemoryRule;

impl DetectionRule for RwxMemoryRule {
    fn id(&self) -> &str {
        "INJ002"
    }

    fn name(&self) -> &str {
        "RWX Memory Region"
    }

    fn description(&self) -> &str {
        "Detects memory regions with read-write-execute permissions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.001") // Process Injection: DLL Injection
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // JIT-based processes that legitimately create RWX regions
        let jit_processes = [
            "msmpeng.exe",    // Windows Defender
            "mssense.exe",    // Defender ATP
            "chrome.exe",     // V8 JIT
            "msedge.exe",     // V8 JIT
            "firefox.exe",    // SpiderMonkey JIT
            "java.exe",       // JVM JIT
            "javaw.exe",
            "node.exe",       // V8 JIT
            "dotnet.exe",     // CLR JIT
            "w3wp.exe",       // ASP.NET JIT
            "powershell.exe", // CLR JIT
            "pwsh.exe",       // CLR JIT
            "smartscreen",   // SmartScreen uses .NET JIT (may be truncated)
            "nissrv",         // Defender NIS (may be truncated)
        ];

        for mal in &data.malfind {
            if mal.is_rwx() && !mal.has_mz_header() && !mal.has_shellcode_patterns() {
                // Skip JIT-based processes — RWX is expected
                let lower_proc = mal.process.to_lowercase();
                if jit_processes.iter().any(|p| lower_proc.contains(p) || p.starts_with(&*lower_proc) || lower_proc.starts_with(p)) {
                    continue;
                }

                // Lower confidence RWX detection (no clear indicators)
                let mut finding = create_finding(
                    self,
                    format!("RWX memory in {} (PID:{})", mal.process, mal.pid),
                    format!(
                        "Process {} has RWX memory region at {} ({}) which may indicate code injection",
                        mal.process, mal.start, mal.protection
                    ),
                    vec![Evidence {
                        source_plugin: "malfind".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("{} - {} [{}]", mal.start, mal.end, mal.protection),
                    }],
                );
                finding.related_pids = vec![mal.pid];
                finding.confidence = 0.6;
                findings.push(finding);
            }
        }

        findings
    }
}
