//! PROC010 – SystemProcessMasqueradingRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect system processes running from unexpected locations
pub struct SystemProcessMasqueradingRule;

impl DetectionRule for SystemProcessMasqueradingRule {
    fn id(&self) -> &str {
        "PROC010"
    }

    fn name(&self) -> &str {
        "System Process Masquerading"
    }

    fn description(&self) -> &str {
        "Detects system processes (e.g., svchost.exe, lsass.exe) running from unexpected directories, indicating masquerading."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1036.005") // Masquerading: Match Legitimate Name
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let nodes = engine.build_process_nodes();

        // Build a map from PID -> executable full path from dlllist
        // (first DLL entry where name matches process name is the main executable)
        let exe_paths: std::collections::HashMap<u32, &str> = data.dlls
            .iter()
            .filter(|dll| dll.name.to_lowercase() == dll.process.to_lowercase())
            .map(|dll| (dll.pid, dll.path.as_str()))
            .collect();

        for node in nodes {
            // Only check if name looks like a critical system process
            if node.is_critical_system_process() {
                // Get actual path from dlllist (more reliable than cmdline)
                let actual_path_opt = exe_paths.get(&node.pid)
                    .copied()
                    .or_else(|| node.cmdline.as_deref());
                
                // If we don't know the path, we can't determine masquerading
                if actual_path_opt.is_none() || actual_path_opt == Some("-") || actual_path_opt == Some("Path not available - check dlllist/filescan manually") {
                    continue;
                }
                
                let actual_path = actual_path_opt.unwrap();
                
                // Check if path is legitimate based on actual path
                let path_lower = actual_path.to_lowercase();
                
                // Skip if path is clearly invalid/empty/placeholder
                if path_lower.len() < 3 || path_lower == "unknown" {
                    continue;
                }

                // Skip Volatility error messages that appear as paths
                if path_lower.contains("required memory at") || path_lower.contains("is not valid") {
                    continue;
                }

                // Skip bare process names with no path separator (cmdline fallback with no path info)
                if !actual_path.contains('\\') && !actual_path.contains('/') {
                    continue;
                }

                let is_legitimate = match node.name.to_lowercase().as_str() {
                    "lsass.exe" | "services.exe" | "smss.exe" | "csrss.exe" 
                    | "winlogon.exe" | "wininit.exe" => {
                        path_lower.contains("\\system32\\") || path_lower.contains("\\windows\\system32\\")
                    }
                    "svchost.exe" => {
                        path_lower.contains("\\system32\\") || path_lower.contains("\\syswow64\\")
                    }
                    "explorer.exe" => {
                        path_lower.contains("\\windows\\") && !path_lower.contains("\\temp\\")
                    }
                    _ => true,
                };
                
                if !is_legitimate {
                    let expected_path = node.expected_path();
                    let parent = node.parent_name.as_deref().unwrap_or("Unknown");
                    let session = node.session_id.as_deref().unwrap_or("N/A");
                    let create_time = node.create_time
                        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());
                    
                    let mut finding = create_finding(
                        self,
                        format!("Masquerading detected: {} running from unexpected path", node.name),
                        format!(
                            "Process {} (PID:{}) is running from '{}', expected path is '{}'. \
                             This typically indicates malware masquerading as a legitimate system process.\n\n\
                             Command Line: {}\n\n\
                             Investigation steps:\n\
                             1. Verify the actual file path using 'filescan' or 'dumpfiles'\n\
                             2. Check parent process '{}' for signs of compromise\n\
                             3. Compare file hash against known-good Windows binaries\n\
                             4. Review session {} - critical system processes should run in session 0",
                            node.name, node.pid, actual_path, expected_path, 
                            node.cmdline.as_deref().unwrap_or("N/A"),
                            parent, session
                        ),
                        vec![
                            Evidence {
                                source_plugin: "pslist".to_string(),
                                source_file: "".to_string(),
                                line_number: None,
                                data: format!("Process: {} | PID: {} | PPID: {}", node.name, node.pid, node.parent_pid),
                            },
                            Evidence {
                                source_plugin: "dlllist".to_string(),
                                source_file: "".to_string(),
                                line_number: None,
                                data: format!("Actual Path: {}", actual_path),
                            },
                            Evidence {
                                source_plugin: "analysis".to_string(),
                                source_file: "".to_string(),
                                line_number: None,
                                data: format!("Expected Path: {}", expected_path),
                            },
                            Evidence {
                                source_plugin: "process_tree".to_string(),
                                source_file: "".to_string(),
                                line_number: None,
                                data: format!("Parent: {} | Session: {} | Created: {}", parent, session, create_time),
                            },
                        ],
                    );
                    
                    finding.related_pids = vec![node.pid, node.parent_pid];
                    finding.confidence = 0.95;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

// Process-related detection rules

