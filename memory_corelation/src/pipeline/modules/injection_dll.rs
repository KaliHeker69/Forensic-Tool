//! Module 4: Injection & DLL Analysis
//!
//! 4a: malfind → vadinfo → dlllist injection chain
//! 4b: DLL integrity per process

use std::collections::{HashMap, HashSet};

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Evidence, Finding, Severity};

// Weight constants
const WEIGHT_HOLLOWED_PE: i32 = 35;
const WEIGHT_SHELLCODE: i32 = 30;
const WEIGHT_PHANTOM_DLL: i32 = 30;
const WEIGHT_UNKNOWN_DLL_SENSITIVE: i32 = 30;
const WEIGHT_SUSPICIOUS_DLL_PATH: i32 = 20;
const WEIGHT_SYSTEM_PROC_INJECTION: i32 = 5; // Bonus for system process
// Hardcoded DLL lists removed in favor of config/whitelist.json

// Hardcoded paths removed. Uses config/blacklist.json

pub struct InjectionDllModule {
    whitelist: crate::config::WhitelistConfig,
    blacklist: crate::config::BlacklistConfig,
}

impl InjectionDllModule {
    pub fn new() -> Self {
        let whitelist = crate::config::WhitelistConfig::load_from_file("config/whitelist.json")
            .unwrap_or_default();
        let blacklist = crate::config::BlacklistConfig::load_from_file("config/blacklist.json")
            .unwrap_or_default();
        Self { whitelist, blacklist }
    }
}

impl PipelineModule for InjectionDllModule {
    fn id(&self) -> &str {
        "4_injection_dll"
    }
    
    fn name(&self) -> &str {
        "Injection & DLL Analysis"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Build DLL coverage map: PID -> list of (base, end) ranges
        let dll_ranges: HashMap<u32, Vec<(u64, u64)>> = {
            let mut map: HashMap<u32, Vec<(u64, u64)>> = HashMap::new();
            for dll in &ctx.data.dlls {
                let base_str = dll.base.trim_start_matches("0x");
                if let Ok(base) = u64::from_str_radix(base_str, 16) {
                    let size = dll.size.unwrap_or(0x1000);
                    map.entry(dll.pid).or_default().push((base, base + size));
                }
            }
            map
        };
        
        // Build proc name map
        let proc_names: HashMap<u32, &str> = ctx.data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        // Sensitive process PIDs
        let sensitive_procs: HashSet<u32> = ctx.data.processes
            .iter()
            .filter(|p| {
                let n = p.name.to_lowercase();
                n == "lsass.exe" || n == "winlogon.exe" || n == "csrss.exe" || 
                n == "services.exe" || n == "smss.exe" || n == "wininit.exe"
            })
            .map(|p| p.pid)
            .collect();
        
        // ── 4a: Injection Chain (malfind → vadinfo → dlllist) ──
        for mf in &ctx.data.malfind {
            let pid = mf.pid;
            let start = u64::from_str_radix(mf.start.trim_start_matches("0x"), 16).unwrap_or(0);
            
            // Check if MZ header present
            let has_mz = mf.hexdump.as_deref()
                .map(|h| {
                    let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                    clean.to_uppercase().starts_with("4D5A")
                })
                .unwrap_or(false);
            
            // Check if address is covered by any DLL
            let covered_by_dll = dll_ranges.get(&pid)
                .map(|ranges| ranges.iter().any(|(b, e)| start >= *b && start < *e))
                .unwrap_or(false);
            
            // Check if corresponding DLL exists on disk (via filescan)
            let dll_path = ctx.data.dlls
                .iter()
                .find(|d| {
                    d.pid == pid && {
                        let base = u64::from_str_radix(d.base.trim_start_matches("0x"), 16).unwrap_or(0);
                        let size = d.size.unwrap_or(0x1000);
                        start >= base && start < base + size
                    }
                })
                .map(|d| d.path.to_lowercase());
            
            let dll_on_disk = dll_path.as_ref()
                .map(|p| ctx.filescan_paths.iter().any(|f| f.contains(p) || p.contains(f)))
                .unwrap_or(false);
            
            // Classify injection type
            let (injection_type, weight, mitre) = if !covered_by_dll {
                if has_mz {
                    ("HOLLOWED_PE", WEIGHT_HOLLOWED_PE, "T1055.012")
                } else {
                    ("SHELLCODE", WEIGHT_SHELLCODE, "T1055")
                }
            } else if !dll_on_disk && dll_path.is_some() {
                ("PHANTOM_DLL", WEIGHT_PHANTOM_DLL, "T1055.001")
            } else {
                // Known DLL on disk - likely benign
                continue;
            };
            
            // Bonus for system process
            let weight = if sensitive_procs.contains(&pid) {
                weight + WEIGHT_SYSTEM_PROC_INJECTION
            } else {
                weight
            };
            
            let proc_name = proc_names.get(&pid).copied().unwrap_or("unknown");
            
            let finding = Finding {
                id: format!("INJECT_{}_{}", injection_type, pid),
                rule_id: format!("MOD4A_{}", injection_type),
                rule_name: format!("{} Injection", injection_type),
                title: format!("{} in {} (PID {})", injection_type, proc_name, pid),
                description: format!(
                    "{} injection detected in '{}' (PID {}). Address: 0x{:x}. \
                    Protection: {}. {}",
                    injection_type, proc_name, pid, start, mf.protection,
                    if has_mz { "Contains PE header (MZ)." } else { "" }
                ),
                severity: Severity::Critical,
                confidence: if has_mz { 0.90 } else { 0.80 },
                mitre_attack: Some(mitre.to_string()),
                related_pids: vec![pid],
                evidence: vec![Evidence {
                    source_plugin: "malfind".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("Start: {} End: {} Protection: {}", mf.start, mf.end, mf.protection),
                }],
                ..Default::default()
            };
            
            ctx.add_finding(pid, finding, weight, self.id());
            ctx.flag_injection(pid);
        }
        
        // ── 4b: DLL Integrity Per Process ──
        for proc in &ctx.data.processes {
            let pid = proc.pid;
            let proc_name = proc.name.to_lowercase();
            
            let dlls: Vec<_> = ctx.data.dlls.iter().filter(|d| d.pid == pid).collect();
            
            // Check 1: Sensitive process - unknown DLL?
            if let Some(known_dlls) = self.whitelist.get_allowed_dlls(&proc_name) {
                 for dll in &dlls {
                    let dll_name = dll.path.rsplit(['\\', '/']).next().unwrap_or("").to_lowercase();
                    
                    if !known_dlls.iter().any(|k| dll_name.eq_ignore_ascii_case(k)) {
                        // Unknown DLL in sensitive process
                        let path_lower = dll.path.to_lowercase();
                        let is_suspicious_path = self.blacklist.is_suspicious(&dll.path);
                        
                        // Skip if it's from System32 and not suspicious
                        if path_lower.contains("\\system32\\") && !is_suspicious_path {
                            continue;
                        }
                        
                        let finding = Finding {
                            id: format!("DLL_UNKNOWN_{}_{}", pid, dll_name.replace('.', "_")),
                            rule_id: "MOD4B_UNKNOWN_DLL".to_string(),
                            rule_name: "Unknown DLL in Sensitive Process".to_string(),
                            title: format!("Unknown DLL in {}: {}", proc.name, dll_name),
                            description: format!(
                                "DLL '{}' loaded in sensitive process '{}' (PID {}) is not in the \
                                expected DLL list. Full path: {}",
                                dll_name, proc.name, pid, dll.path
                            ),
                            severity: if is_suspicious_path { Severity::Critical } else { Severity::High },
                            confidence: if is_suspicious_path { 0.90 } else { 0.70 },
                            mitre_attack: Some("T1055.001".to_string()),
                            related_pids: vec![pid],
                            related_files: vec![dll.path.clone()],
                            ..Default::default()
                        };
                        
                        let w = if is_suspicious_path { WEIGHT_UNKNOWN_DLL_SENSITIVE } else { WEIGHT_SUSPICIOUS_DLL_PATH };
                        ctx.add_finding(pid, finding, w, self.id());
                    }
                }
            }
            
            // Check 2: Any process - DLL from suspicious path?
            for dll in &dlls {
                let _path_lower = dll.path.to_lowercase();
                
                // Use blacklist config
                let is_suspicious = self.blacklist.is_suspicious(&dll.path);

                if is_suspicious {
                    // Check external whitelist
                    if self.whitelist.is_whitelisted(&dll.path) {
                        continue;
                    }

                    let dll_name = dll.path.rsplit(['\\', '/']).next().unwrap_or("");
                        
                        let finding = Finding {
                            id: format!("DLL_SUSP_PATH_{}_{}", pid, dll_name.replace('.', "_")),
                            rule_id: "MOD4B_SUSP_PATH".to_string(),
                            rule_name: "DLL from Suspicious Path".to_string(),
                            title: format!("DLL from suspicious path in {}", proc.name),
                            description: format!(
                                "DLL '{}' loaded from suspicious location: {}",
                                dll_name, dll.path
                            ),
                            severity: Severity::Medium,
                            confidence: 0.70,
                            mitre_attack: Some("T1574.001".to_string()),
                            related_pids: vec![pid],
                            related_files: vec![dll.path.clone()],
                            ..Default::default()
                        };
                        
                        ctx.add_finding(pid, finding, WEIGHT_SUSPICIOUS_DLL_PATH, self.id());
                        break;
                    }
                }
            }
        
        ctx
    }
}
