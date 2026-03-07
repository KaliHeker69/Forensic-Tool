//! PROC001 – OrphanedProcessRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect orphaned processes (PPID doesn't exist)
pub struct OrphanedProcessRule;

impl DetectionRule for OrphanedProcessRule {
    fn id(&self) -> &str {
        "PROC001"
    }

    fn name(&self) -> &str {
        "Orphaned Process Detection"
    }

    fn description(&self) -> &str {
        "Detects processes whose parent process ID doesn't exist, which may indicate DKOM manipulation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014") // Rootkit
    }

    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build map of terminated processes from psscan
        let terminated_parents: std::collections::HashMap<u32, &crate::models::process::ProcessInfo> = data.processes
            .iter()
            .filter(|p| p.source == crate::models::process::ProcessSource::PsScan)
            .map(|p| (p.pid, p))
            .collect();

        // Boot orphans: smss.exe spawns these then exits, so they legitimately have no parent
        let known_boot_orphans = ["csrss.exe", "wininit.exe", "winlogon.exe"];

        for proc in engine.find_orphaned_processes() {
            // Skip system processes that legitimately have no parent
            if proc.ppid == 0 || proc.pid == 0 || proc.pid == 4 {
                continue;
            }
            
            // Check if parent exists in terminated list
            let parent_in_psscan = terminated_parents.get(&proc.ppid);

            // Lookup cmdlines
            let proc_cmdline = data.cmdlines.iter()
                .find(|c| c.pid == proc.pid)
                .map(|c| c.args.clone())
                .unwrap_or_else(|| "N/A".to_string());
                
            let parent_cmdline = data.cmdlines.iter()
                .find(|c| c.pid == proc.ppid)
                .map(|c| c.args.clone())
                .unwrap_or_else(|| "N/A".to_string());

            let (severity, description, confidence, title_suffix) = if let Some(parent) = parent_in_psscan {
                let exit_time = parent.exit_time.map(|t| t.to_string()).unwrap_or("Unknown".to_string());
                (
                    Severity::Info,
                    format!(
                        "Process {} has parent PID {} which is not in the active process list, \
                        but was found in psscan (terminated at {}). This indicates a legitimate orphaned process.\n\
                        \nProcess Cmdline: {}\nParent Cmdline: {}",
                        proc.name, proc.ppid, exit_time, proc_cmdline, parent_cmdline
                    ),
                    0.60,
                    " (Legitimate)"
                )
            } else {
                let lower_name = proc.name.to_lowercase();
                let is_boot_orphan = known_boot_orphans.iter().any(|b| lower_name == *b);
                
                if is_boot_orphan {
                    // Normal Windows boot behavior: smss.exe spawns these then terminates
                    (
                        Severity::Info,
                        format!(
                            "Process {} (PID:{}) has parent PID {} which no longer exists. \
                            This is normal Windows boot behavior — smss.exe spawns this process then exits.\n\
                            \nProcess Cmdline: {}\nParent Cmdline: {}",
                            proc.name, proc.pid, proc.ppid, proc_cmdline, parent_cmdline
                        ),
                        0.20,
                        " (Boot Orphan)"
                    )
                } else {
                    // Common user-space applications whose parent (typically explorer.exe) has exited
                    let user_apps = [
                        "firefox", "chrome", "msedge", "onedrive", "teams", "outlook",
                        "slack", "discord", "spotify", "code", "notepad", "calc",
                        "mspaint", "wordpad", "thunderbird", "brave", "vivaldi",
                        "opera", "iexplore", "microsoftedge",
                    ];
                    let is_user_app = user_apps.iter().any(|app| lower_name.starts_with(app));
                    
                    if is_user_app {
                        (
                            Severity::Info,
                            format!(
                                "User application {} (PID:{}) has parent PID {} which no longer exists. \
                                This is common when the parent process (e.g., explorer.exe) has restarted.\n\
                                \nProcess Cmdline: {}\nParent Cmdline: {}",
                                proc.name, proc.pid, proc.ppid, proc_cmdline, parent_cmdline
                            ),
                            0.30,
                            " (User App)"
                        )
                    } else {
                        (
                            Severity::High,
                            format!(
                                "Process {} has parent PID {} which does not exist in pslist OR psscan. \
                                This suggests the parent process was hidden or removed from process structures, \
                                indicating potential rootkit/DKOM activity.\n\
                                \nProcess Cmdline: {}\nParent Cmdline: {}",
                                proc.name, proc.ppid, proc_cmdline, parent_cmdline
                            ),
                            0.85,
                            ""
                        )
                    }
                }
            };

            let mut finding = create_finding(
                self,
                format!("Orphaned process: {} (PID:{}){}", proc.name, proc.pid, title_suffix),
                description,
                vec![Evidence {
                    source_plugin: "pslist".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("PID:{} PPID:{} Name:{}", proc.pid, proc.ppid, proc.name),
                }],
            );
            
            if let Some(parent) = parent_in_psscan {
                 finding.evidence.push(Evidence {
                    source_plugin: "psscan".to_string(),
                    source_file: "".to_string(),
                    line_number: None,
                    data: format!("Parent PID:{} Name:{} Exit: {:?}", parent.pid, parent.name, parent.exit_time),
                });
            }
            
            finding.severity = severity;
            finding.confidence = confidence;
            finding.related_pids = vec![proc.pid];
            finding.timestamp = proc.create_time;
            findings.push(finding);
        }

        findings
    }
}
