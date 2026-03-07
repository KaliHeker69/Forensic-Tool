//! Module 1: Process Integrity
//!
//! Detects hidden processes via pslist vs psscan set-diff
//! and timestamp integrity checks.

use std::collections::HashSet;

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Evidence, Finding, Severity};

/// Weight constants from Combined_Analysis_Logic.md
const WEIGHT_HIDDEN_PROCESS_RUNNING: i32 = 40;
const WEIGHT_TIMESTAMP_TAMPERED: i32 = 25;
const WEIGHT_REMNANT_PROCESS: i32 = 5; // Lower weight for exited processes

pub struct ProcessIntegrityModule;

impl PipelineModule for ProcessIntegrityModule {
    fn id(&self) -> &str {
        "1_process_integrity"
    }
    
    fn name(&self) -> &str {
        "Process Integrity"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Step 1: Hidden process detection (psscan - pslist)
        let pslist_pids: HashSet<u32> = ctx.data.pslist_processes
            .iter()
            .map(|p| p.pid)
            .collect();
        
        let psscan_pids: HashSet<u32> = ctx.data.psscan_processes
            .iter()
            .map(|p| p.pid)
            .collect();
        
        // Hidden = in psscan but not in pslist
        let hidden_pids: HashSet<u32> = psscan_pids.difference(&pslist_pids).copied().collect();
        
        for &pid in &hidden_pids {
            // Find the psscan entry
            if let Some(proc) = ctx.data.psscan_processes.iter().find(|p| p.pid == pid) {
                let is_running = proc.exit_time.is_none();
                
                let (weight, title, description) = if is_running {
                    (
                        WEIGHT_HIDDEN_PROCESS_RUNNING,
                        format!("Hidden process: {} (PID {})", proc.name, pid),
                        format!(
                            "Process '{}' (PID {}) is present in psscan but absent from pslist. \
                            This indicates DKOM (Direct Kernel Object Manipulation) — the process \
                            is actively running but has been unlinked from the process list. \
                            This is a strong rootkit indicator.",
                            proc.name, pid
                        ),
                    )
                } else {
                    (
                        WEIGHT_REMNANT_PROCESS,
                        format!("Remnant process: {} (PID {})", proc.name, pid),
                        format!(
                            "Exited process '{}' (PID {}) found in psscan but not pslist. \
                            This is a remnant EPROCESS structure — forensic evidence only.",
                            proc.name, pid
                        ),
                    )
                };
                
                let finding = Finding {
                    id: format!("PROC_INTEG_{}", pid),
                    rule_id: "MOD1_HIDDEN".to_string(),
                    rule_name: "Hidden Process Detection".to_string(),
                    title: title.clone(),
                    description,
                    severity: if is_running { Severity::Critical } else { Severity::Info },
                    confidence: if is_running { 0.95 } else { 0.60 },
                    mitre_attack: Some("T1014".to_string()), // Rootkit
                    related_pids: vec![pid],
                    related_files: vec![],
                    evidence: vec![Evidence {
                        source_plugin: "psscan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("PID {} | Name: {} | ExitTime: {:?}", pid, proc.name, proc.exit_time),
                    }],
                    ..Default::default()
                };
                
                ctx.add_finding(pid, finding, weight, self.id());
                
                if is_running {
                    ctx.flag_injection(pid); // Hidden processes are suspicious
                }
            }
        }
        
        // Step 2: Timestamp integrity check
        // Compare CreateTime between pslist and psscan for same PID
        for pslist_proc in &ctx.data.pslist_processes {
            if let Some(psscan_proc) = ctx.data.psscan_processes
                .iter()
                .find(|p| p.pid == pslist_proc.pid)
            {
                if let (Some(pslist_time), Some(psscan_time)) = 
                    (&pslist_proc.create_time, &psscan_proc.create_time)
                {
                    if pslist_time != psscan_time {
                        let finding = Finding {
                            id: format!("TIMESTAMP_{}", pslist_proc.pid),
                            rule_id: "MOD1_TIMESTAMP".to_string(),
                            rule_name: "Timestamp Integrity".to_string(),
                            title: format!("Timestamp tampered: {} (PID {})", pslist_proc.name, pslist_proc.pid),
                            description: format!(
                                "Process '{}' (PID {}) has different CreateTime values between \
                                pslist ({:?}) and psscan ({:?}). This indicates timestamp manipulation.",
                                pslist_proc.name, pslist_proc.pid, pslist_time, psscan_time
                            ),
                            severity: Severity::High,
                            confidence: 0.85,
                            mitre_attack: Some("T1070.006".to_string()), // Timestomp
                            related_pids: vec![pslist_proc.pid],
                            related_files: vec![],
                            evidence: vec![Evidence {
                                source_plugin: "pslist/psscan".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!(
                                    "pslist CreateTime: {:?} | psscan CreateTime: {:?}",
                                    pslist_time, psscan_time
                                ),
                            }],
                            ..Default::default()
                        };
                        
                        ctx.add_finding(pslist_proc.pid, finding, WEIGHT_TIMESTAMP_TAMPERED, self.id());
                    }
                }
            }
        }
        
        ctx
    }
}
