//! INJ005 – VadInjectionRule
use std::collections::HashMap;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect potential code injection via VAD (Virtual Address Descriptor) analysis
/// RWX private memory without file backing is a strong injection indicator
pub struct VadInjectionRule;

impl DetectionRule for VadInjectionRule {
    fn id(&self) -> &str {
        "INJ005"
    }

    fn name(&self) -> &str {
        "VAD-Based Injection Detection"
    }

    fn description(&self) -> &str {
        "Detects unbacked executable memory regions in process VADs indicating code injection"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.012") // Process Hollowing
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // JIT/CLR processes that legitimately create RWX private VADs
        let jit_processes = [
            "msmpeng", "mssense", "chrome", "msedge", "firefox",
            "java", "javaw", "node", "dotnet", "w3wp",
            "powershell", "pwsh", "smartscreen", "nissrv",
        ];

        // Count suspicious VADs per process
        let mut sus_vads_per_pid: HashMap<u32, Vec<&crate::models::malware::VadInfo>> = HashMap::new();

        for vad in &data.vads {
            // Only interested in executable memory
            if !vad.is_executable() {
                continue;
            }

            // Skip JIT processes
            let lower_proc = vad.process.to_lowercase();
            if jit_processes.iter().any(|p| lower_proc.starts_with(p) || lower_proc.contains(p)) {
                continue;
            }

            // Skip file-backed VADs (legitimate DLL mappings)
            if vad.file.is_some() {
                continue;
            }

            // Private memory + executable = suspicious
            let is_private = vad.private_memory.as_ref()
                .map(|s| s == "1" || s.to_lowercase() == "true")
                .unwrap_or(false);

            if is_private {
                sus_vads_per_pid.entry(vad.pid).or_default().push(vad);
            }
        }

        // Generate findings for processes with suspicious VAD patterns
        for (pid, vads) in sus_vads_per_pid {
            if vads.is_empty() {
                continue;
            }

            let process_name = vads[0].process.clone();

            // Skip if only 1 region (many processes have a single RWX region from runtime allocators)
            // unless it's in a sensitive process
            let lower_proc = process_name.to_lowercase();
            let is_sensitive = lower_proc == "lsass.exe" || lower_proc == "csrss.exe"
                || lower_proc == "winlogon.exe" || lower_proc == "services.exe";

            if vads.len() == 1 && !is_sensitive {
                continue;
            }

            let rwx_count = vads.iter()
                .filter(|v| v.is_writable() && v.is_executable())
                .count();

            let severity = if is_sensitive {
                Severity::Critical
            } else if rwx_count >= 3 {
                Severity::High
            } else {
                Severity::Medium
            };

            let vad_details: Vec<String> = vads.iter().take(5).map(|v| {
                format!("{} - {} [{}] Tag:{}", v.start, v.end, v.protection, v.tag)
            }).collect();

            let mut finding = create_finding(
                self,
                format!("Suspicious VADs in {} (PID:{}): {} unbacked executable regions",
                    process_name, pid, vads.len()),
                format!(
                    "Process '{}' (PID {}) has {} private executable memory regions without file backing. \
                    {} of these are RWX (read-write-execute). This pattern indicates code injection \
                    or shellcode execution.\n\nRegions:\n{}",
                    process_name, pid, vads.len(), rwx_count,
                    vad_details.join("\n")
                ),
                vec![Evidence {
                    source_plugin: "vadinfo".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("Process:{} PID:{} SuspiciousVADs:{} RWX:{}",
                        process_name, pid, vads.len(), rwx_count),
                }],
            );
            finding.severity = severity;
            finding.related_pids = vec![pid];
            finding.confidence = if is_sensitive { 0.90 } else { 0.70 };
            findings.push(finding);
        }

        findings
    }
}
