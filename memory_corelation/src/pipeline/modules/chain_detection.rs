//! Module 7: Cross-Layer Chain Detection
//!
//! Runs AFTER all individual modules. Looks for multi-step attack
//! patterns where findings from different modules on the same PID
//! form a known attack chain. Adds bonus weights for confirmed chains.

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;

// Chain bonus weights
const BONUS_CREDENTIAL_CHAIN: i32 = 15;
const BONUS_HOLLOWING_CHAIN: i32 = 10;
const BONUS_PERSISTENCE_CHAIN: i32 = 10;
const BONUS_LATERAL_CHAIN: i32 = 10;

pub struct ChainDetectionModule;

impl PipelineModule for ChainDetectionModule {
    fn id(&self) -> &str {
        "7_chain_detection"
    }
    
    fn name(&self) -> &str {
        "Cross-Layer Chain Detection"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Get sets of PIDs flagged by each module
        let injection_pids = ctx.injection_flagged_pids.clone();
        let cred_pids = ctx.credential_flagged_pids.clone();
        let cmdline_pids = ctx.cmdline_anomaly_pids.clone();
        let network_pids = ctx.network_pids.clone();
        
        // ── Chain A: Credential Dumping ──
        // Trigger: handle to lsass (credential_flagged_pids)
        // Bonus if ALSO: injection OR cmdline anomaly
        for &pid in &cred_pids {
            let has_injection = injection_pids.contains(&pid);
            let has_cmdline = cmdline_pids.contains(&pid);
            
            // Get DLL findings for this PID
            let has_dll_finding = ctx.pid_evidence.get(&pid)
                .map(|e| e.flagged_by_modules.contains("4_injection_dll"))
                .unwrap_or(false);
            
            if has_injection || has_cmdline || has_dll_finding {
                ctx.add_chain_bonus(pid, "CREDENTIAL_DUMPING", BONUS_CREDENTIAL_CHAIN);
            }
        }
        
        // ── Chain B: Process Hollowing ──
        // Requires: injection (HOLLOWED_PE type) + cmdline anomaly + legitimate name
        for &pid in &injection_pids {
            let has_cmdline = cmdline_pids.contains(&pid);
            
            // Check if this PID has a HOLLOWED_PE finding
            let has_hollowed = ctx.pid_evidence.get(&pid)
                .map(|e| e.findings.iter().any(|f| 
                    f.rule_id.contains("HOLLOWED") || f.title.contains("HOLLOWED")
                ))
                .unwrap_or(false);
            
            // Check if process has a legitimate-looking name but is flagged
            let proc_name = ctx.get_process_name(pid);
            let looks_legit = proc_name
                .map(|n| {
                    let n = n.to_lowercase();
                    n == "svchost.exe" || n == "rundll32.exe" || n == "dllhost.exe" ||
                    n == "csrss.exe" || n == "services.exe" || n == "explorer.exe"
                })
                .unwrap_or(false);
            
            if has_hollowed && has_cmdline && looks_legit {
                ctx.add_chain_bonus(pid, "PROCESS_HOLLOWING", BONUS_HOLLOWING_CHAIN);
            }
        }
        
        // ── Chain C: Persistence Installation ──
        // Requires: service finding + (cmdline anomaly OR hidden hive)
        let service_pids: Vec<u32> = ctx.pid_evidence.iter()
            .filter(|(_pid, e)| e.flagged_by_modules.contains("5_persistence"))
            .map(|(&pid, _)| pid)
            .collect();
        
        let has_hidden_hive = ctx.global_findings.iter()
            .any(|f| f.rule_id.contains("HIDDEN_HIVE"));
        
        for pid in service_pids {
            let has_cmdline = cmdline_pids.contains(&pid);
            
            if has_cmdline || has_hidden_hive {
                ctx.add_chain_bonus(pid, "PERSISTENCE_INSTALLATION", BONUS_PERSISTENCE_CHAIN);
            }
        }
        
        // ── Chain D: Lateral Movement / Recon ──
        // Requires: recon command + anomalous parent + network activity
        let recon_pids: Vec<u32> = ctx.pid_evidence.iter()
            .filter(|(_pid, e)| e.findings.iter().any(|f| 
                f.rule_id.contains("RECON") || f.title.contains("Recon")
            ))
            .map(|(&pid, _)| pid)
            .collect();
        
        for pid in recon_pids {
            let has_network = network_pids.contains(&pid);
            let has_parent_finding = ctx.pid_evidence.get(&pid)
                .map(|e| e.findings.iter().any(|f| 
                    f.rule_id.contains("PARENT") || f.rule_id.contains("MOD3B")
                ))
                .unwrap_or(false);
            
            if has_network && has_parent_finding {
                ctx.add_chain_bonus(pid, "LATERAL_MOVEMENT", BONUS_LATERAL_CHAIN);
            }
        }
        
        ctx
    }
}
