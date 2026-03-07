//! HNDL001 – HandleMutexAnalysisRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Analyze process handles for suspicious patterns:
/// - Known malware mutexes
/// - Unusual process handles to sensitive targets
/// - File handles to suspicious paths
pub struct HandleMutexAnalysisRule;

impl DetectionRule for HandleMutexAnalysisRule {
    fn id(&self) -> &str {
        "HNDL001"
    }

    fn name(&self) -> &str {
        "Handle and Mutex Analysis"
    }

    fn description(&self) -> &str {
        "Analyzes process handles for malware mutexes, suspicious process access, and anomalous handle patterns"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1106") // Native API
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.handles.is_empty() {
            return findings;
        }

        // Known malware mutex patterns
        let malware_mutexes = [
            "dcratsrmtx", "asyncmutex", "remcos", "njrat",
            "quasarserver", "warzone", "orcusrat", "darkcometmtx",
            "poisonivy", "gh0st", "blackshades", "xtreme",
            "netwirespmtx", "havocspmutex", "cobaltstrike",
            "meterpreter",
        ];

        // Suspicious mutex patterns (regex-like name patterns)
        let suspicious_mutex_patterns = [
            "global\\", "_sl_mhckv", "\\basenamdobject",
            "mutex_inject", "shellcodemtx", "loader_mutex",
        ];

        // Track handles per process for anomaly detection
        let mut process_handles: HashMap<u32, Vec<&crate::models::files::HandleInfo>> = HashMap::new();
        let mut mutex_findings: HashSet<(u32, String)> = HashSet::new();

        for handle in &data.handles {
            process_handles.entry(handle.pid).or_default().push(handle);

            // Check for known malware mutexes
            if handle.is_mutex_handle() {
                let name_lower = handle.name.as_deref().unwrap_or("").to_lowercase();

                let is_known_malware = malware_mutexes.iter()
                    .any(|m| name_lower.contains(m));

                let is_suspicious = suspicious_mutex_patterns.iter()
                    .any(|p| name_lower.contains(p));

                if is_known_malware {
                    let key = (handle.pid, name_lower.clone());
                    if mutex_findings.insert(key) {
                        let mut finding = create_finding(
                            self,
                            format!("Known malware mutex: {} in {} (PID:{})",
                                handle.name.as_deref().unwrap_or("?"), handle.process, handle.pid),
                            format!(
                                "Process '{}' (PID {}) holds a mutex matching known malware: '{}'. \
                                This is a strong indicator of malware infection.",
                                handle.process, handle.pid,
                                handle.name.as_deref().unwrap_or("?")
                            ),
                            vec![Evidence {
                                source_plugin: "handles".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!("Mutex: {} PID: {} Process: {}",
                                    handle.name.as_deref().unwrap_or("?"), handle.pid, handle.process),
                            }],
                        );
                        finding.severity = Severity::Critical;
                        finding.related_pids = vec![handle.pid];
                        finding.confidence = 0.95;
                        findings.push(finding);
                    }
                } else if is_suspicious && !name_lower.is_empty() {
                    let key = (handle.pid, name_lower.clone());
                    if mutex_findings.insert(key) {
                        let mut finding = create_finding(
                            self,
                            format!("Suspicious mutex: {} in {} (PID:{})",
                                handle.name.as_deref().unwrap_or("?"), handle.process, handle.pid),
                            format!(
                                "Process '{}' (PID {}) holds a mutex with suspicious naming pattern: '{}'.",
                                handle.process, handle.pid,
                                handle.name.as_deref().unwrap_or("?")
                            ),
                            vec![Evidence {
                                source_plugin: "handles".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!("Mutex: {} PID: {} Process: {}",
                                    handle.name.as_deref().unwrap_or("?"), handle.pid, handle.process),
                            }],
                        );
                        finding.severity = Severity::Medium;
                        finding.related_pids = vec![handle.pid];
                        finding.confidence = 0.70;
                        findings.push(finding);
                    }
                }
            }

            // Check for file handles to suspicious paths
            if handle.is_file_handle() {
                let name_lower = handle.name.as_deref().unwrap_or("").to_lowercase();
                
                // Only flag truly sensitive credential/security files
                // Use end-of-path matching to avoid FPs with \systemprofile\ etc.
                let is_sensitive = name_lower.ends_with("\\config\\sam")
                    || name_lower.ends_with("\\config\\security")
                    || name_lower.ends_with("\\config\\system")
                    || name_lower.contains("\\ntds.dit")
                    || name_lower.contains("\\lsass.dmp")
                    || name_lower.contains("\\procdump")
                    || name_lower.contains("\\mimikatz")
                    || name_lower.contains("\\sam.save")
                    || name_lower.contains("\\security.save")
                    || name_lower.contains("\\system.save")
                    || name_lower.contains("\\sam.bak")
                    || name_lower.contains("\\security.bak");

                let proc_lower = handle.process.to_lowercase();
                let is_system = proc_lower == "system" || proc_lower == "lsass.exe"
                    || proc_lower == "svchost.exe" || proc_lower == "services.exe"
                    || proc_lower == "smss.exe" || proc_lower == "csrss.exe";

                if !is_system && is_sensitive {
                    let mut finding = create_finding(
                        self,
                        format!("Sensitive file access: {} by {} (PID:{})",
                            handle.name.as_deref().unwrap_or("?"), handle.process, handle.pid),
                        format!(
                            "Process '{}' (PID {}) has a file handle to sensitive path: '{}'. \
                            This may indicate credential theft or system data exfiltration.",
                            handle.process, handle.pid,
                            handle.name.as_deref().unwrap_or("?")
                        ),
                        vec![Evidence {
                            source_plugin: "handles".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("File: {} PID: {} Process: {}",
                                handle.name.as_deref().unwrap_or("?"), handle.pid, handle.process),
                        }],
                    );
                    finding.severity = Severity::High;
                    finding.related_pids = vec![handle.pid];
                    finding.related_files = handle.name.clone().into_iter().collect();
                    finding.confidence = 0.80;
                    findings.push(finding);
                }
            }
        }

        // Anomaly: processes with excessive handle counts (potential handle leaks or enumeration)
        for (pid, handles) in &process_handles {
            let process_name = handles.first().map(|h| h.process.as_str()).unwrap_or("?");
            let proc_lower = process_name.to_lowercase();

            // Count process-type handles (access to other processes)
            let process_handles_count = handles.iter()
                .filter(|h| h.handle_type.to_lowercase() == "process")
                .count();

            // Flag processes with many process handles (potential process enumeration)
            if process_handles_count > 50 {
                let is_system = proc_lower == "system" || proc_lower == "csrss.exe"
                    || proc_lower == "svchost.exe" || proc_lower == "lsass.exe"
                    || proc_lower == "services.exe" || proc_lower == "wininit.exe"
                    || proc_lower == "smss.exe";

                if !is_system {
                    let mut finding = create_finding(
                        self,
                        format!("Excessive process handles: {} (PID:{}) has {} process handles",
                            process_name, pid, process_handles_count),
                        format!(
                            "Process '{}' (PID {}) holds {} handles to other processes. \
                            This is unusual and may indicate process enumeration or injection preparation.",
                            process_name, pid, process_handles_count
                        ),
                        vec![Evidence {
                            source_plugin: "handles".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("Process: {} PID: {} ProcessHandles: {}",
                                process_name, pid, process_handles_count),
                        }],
                    );
                    finding.severity = Severity::Medium;
                    finding.related_pids = vec![*pid];
                    finding.confidence = 0.65;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
