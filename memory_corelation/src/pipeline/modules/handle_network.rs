//! Module 6: Handle & Network Analysis
//!
//! 6a: Cross-process handle checks (lsass focus)
//! 6b: Mutex & suspicious file/pipe handles
//! 6c: Network-process correlation

use std::collections::HashMap;

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Evidence, Finding, Severity};

// Weight constants
const WEIGHT_LSASS_HANDLE: i32 = 30;
const WEIGHT_SENSITIVE_HANDLE: i32 = 15;
const WEIGHT_SUSPICIOUS_PIPE: i32 = 15;
const WEIGHT_TEMP_FILE_HANDLE: i32 = 10;

/// Legitimate processes that may hold handles to lsass
const LSASS_HANDLE_ALLOWLIST: &[&str] = &[
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "svchost.exe",

    // security tooling
    "msmpeng.exe",
    "mpcmdrun.exe",
    "mrt.exe",
    "nissrv.exe",
    "securityhealthservice.exe",

    // system / maintenance
    "trustedinstaller.exe",
    "taskhostw.exe",
    "sihost.exe",
    "wermgr.exe",
    "lsm.exe",
];


/// Known legitimate named pipes
const LEGITIMATE_PIPES: &[&str] = &[
    "\\lsass",
    "\\lsarpc",
    "\\samr",
    "\\samrsvc",
    "\\scerpc",
    "\\ntsvcs",
    "\\ntsvcsrpc",
    "\\srvsvc",
    "\\wkssvc",
    "\\wkssvc_rpc",
    "\\browser",
    "\\spoolss",
    "\\netlogon",
    "\\netlogonrpc",
    "\\winreg",
    "\\atsvc",
    "\\eventlog",
    "\\eventlogrpc",
    "\\epmapper",
    "\\svcctl",
];


/// Sensitive processes to monitor handle access to
const SENSITIVE_PROCESSES: &[&str] = &[
    "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe",
    "explorer.exe",
    "svchost.exe",
    "taskmgr.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "conhost.exe",
];

pub struct HandleNetworkModule;

impl PipelineModule for HandleNetworkModule {
    fn id(&self) -> &str {
        "6_handle_network"
    }
    
    fn name(&self) -> &str {
        "Handle & Network Analysis"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        let proc_names: HashMap<u32, &str> = ctx.data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        // ── 6a: Cross-Process Handle Checks ──
        if let Some(lsass_pid) = ctx.lsass_pid {
            for handle in &ctx.data.handles {
                // Check for handles TO lsass
                if handle.handle_type.to_lowercase() == "process" {
                    // The handle name/details might contain the target PID or process name
                    let details = handle.name.as_deref().unwrap_or("");
                    let details_lower = details.to_lowercase();
                    
                    // Check if this handle targets lsass
                    let targets_lsass = details_lower.contains("lsass") 
                        || details.contains(&lsass_pid.to_string());
                    
                    if targets_lsass && handle.pid != lsass_pid {
                        let holder_name = proc_names.get(&handle.pid)
                            .copied()
                            .unwrap_or("unknown");
                        
                        // Skip allowlisted holders
                        if LSASS_HANDLE_ALLOWLIST.iter()
                            .any(|&a| holder_name.to_lowercase() == a) {
                            continue;
                        }
                        
                        let finding = Finding {
                            id: format!("LSASS_HANDLE_{}", handle.pid),
                            rule_id: "MOD6A_LSASS_HANDLE".to_string(),
                            rule_name: "Cross-Process Handle to LSASS".to_string(),
                            title: format!("Cross-process handle to lsass: {} (PID {})", holder_name, handle.pid),
                            description: format!(
                                "Process '{}' (PID {}) holds a Process handle targeting lsass \
                                (PID {}). This is a strong indicator of credential dumping. \
                                Granted access: {}",
                                holder_name, handle.pid, lsass_pid, handle.granted_access
                            ),
                            severity: Severity::Critical,
                            confidence: 0.90,
                            mitre_attack: Some("T1003.001".to_string()),
                            related_pids: vec![handle.pid, lsass_pid],
                            evidence: vec![Evidence {
                                source_plugin: "handles".to_string(),
                                source_file: String::new(),
                                line_number: None,
                                data: format!(
                                    "Holder: {} (PID {}) | Target: lsass (PID {}) | Access: {}",
                                    holder_name, handle.pid, lsass_pid, handle.granted_access
                                ),
                            }],
                            ..Default::default()
                        };
                        
                        ctx.add_finding(handle.pid, finding, WEIGHT_LSASS_HANDLE, self.id());
                        ctx.flag_credential_access(handle.pid);
                    }
                }
            }
        }
        
        // Check handles to other sensitive processes
        for handle in &ctx.data.handles {
            if handle.handle_type.to_lowercase() != "process" {
                continue;
            }
            
            let details = handle.name.as_deref().unwrap_or("").to_lowercase();
            
            for &sensitive in SENSITIVE_PROCESSES {
                if sensitive == "lsass.exe" {
                    continue; // Already handled above
                }
                
                if details.contains(&sensitive.replace(".exe", "")) {
                    let holder_name = proc_names.get(&handle.pid).copied().unwrap_or("unknown");
                    let holder_lower = holder_name.to_lowercase();
                    
                    // Skip if holder IS the sensitive process
                    if holder_lower == sensitive {
                        continue;
                    }
                    
                    // Skip system processes
                    if LSASS_HANDLE_ALLOWLIST.iter().any(|&a| holder_lower == a) {
                        continue;
                    }
                    
                    let finding = Finding {
                        id: format!("SENSITIVE_HANDLE_{}_{}", handle.pid, sensitive.replace('.', "_")),
                        rule_id: "MOD6A_SENSITIVE".to_string(),
                        rule_name: "Sensitive Process Handle".to_string(),
                        title: format!("Handle to {}: {} (PID {})", sensitive, holder_name, handle.pid),
                        description: format!(
                            "Process '{}' (PID {}) holds a handle to sensitive process '{}'. \
                            This may indicate process manipulation.",
                            holder_name, handle.pid, sensitive
                        ),
                        severity: Severity::Medium,
                        confidence: 0.70,
                        mitre_attack: Some("T1003".to_string()),
                        related_pids: vec![handle.pid],
                        ..Default::default()
                    };
                    
                    ctx.add_finding(handle.pid, finding, WEIGHT_SENSITIVE_HANDLE, self.id());
                }
            }
        }
        
        // ── 6b: Suspicious Pipe and File Handles ──
        for handle in &ctx.data.handles {
            let handle_type = handle.handle_type.to_lowercase();
            let name = handle.name.as_deref().unwrap_or("");
            let name_lower = name.to_lowercase();
            
            // Named pipe check
            if handle_type == "file" && name_lower.contains("\\pipe\\") {
                let pipe_name = name.rsplit("\\pipe\\").next().unwrap_or("");
                
                // Skip legitimate pipes
                if LEGITIMATE_PIPES.iter().any(|&p| name_lower.contains(p)) {
                    continue;
                }
                
                // Flag suspicious pipes
                if !pipe_name.is_empty() {
                    let holder_name = proc_names.get(&handle.pid).copied().unwrap_or("unknown");
                    
                    let finding = Finding {
                        id: format!("PIPE_{}_{}", handle.pid, pipe_name.chars().take(20).collect::<String>()),
                        rule_id: "MOD6B_PIPE".to_string(),
                        rule_name: "Suspicious Named Pipe".to_string(),
                        title: format!("Named pipe: {} (PID {})", pipe_name, handle.pid),
                        description: format!(
                            "Process '{}' (PID {}) holds a handle to named pipe '{}'. \
                            Named pipes can be used for C2 communication.",
                            holder_name, handle.pid, name
                        ),
                        severity: Severity::Low,
                        confidence: 0.60,
                        mitre_attack: Some("T1071".to_string()),
                        related_pids: vec![handle.pid],
                        ..Default::default()
                    };
                    
                    ctx.add_finding(handle.pid, finding, WEIGHT_SUSPICIOUS_PIPE, self.id());
                }
            }
            
            // Temp file handle check
            if handle_type == "file" {
                let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"];
                let is_temp = suspicious_paths.iter().any(|&p| name_lower.contains(p));
                
                if is_temp && (name_lower.ends_with(".exe") || name_lower.ends_with(".dll")) {
                    let holder_name = proc_names.get(&handle.pid).copied().unwrap_or("unknown");
                    
                    let finding = Finding {
                        id: format!("TEMP_FILE_{}_{}", handle.pid, name.chars().take(30).collect::<String>()),
                        rule_id: "MOD6B_TEMP".to_string(),
                        rule_name: "Executable in Temp".to_string(),
                        title: format!("Handle to temp executable: PID {}", handle.pid),
                        description: format!(
                            "Process '{}' (PID {}) holds a file handle to '{}'.",
                            holder_name, handle.pid, name
                        ),
                        severity: Severity::Low,
                        confidence: 0.55,
                        mitre_attack: Some("T1564.001".to_string()),
                        related_pids: vec![handle.pid],
                        related_files: vec![name.to_string()],
                        ..Default::default()
                    };
                    
                    ctx.add_finding(handle.pid, finding, WEIGHT_TEMP_FILE_HANDLE, self.id());
                }
            }
        }
        
        // ── 6c: Network correlation is pre-computed in ctx.network_pids ──
        // Used by other modules (Module 3C, Module 7)
        
        ctx
    }
}
