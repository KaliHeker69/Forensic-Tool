//! Module 5: Persistence
//!
//! 5a: Registry persistence (results from Module 2)
//! 5b: Service validation chain (svcscan → filescan → pslist)

use std::collections::HashMap;

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Evidence, Finding, Severity};

// Weight constants
const WEIGHT_GHOST_SERVICE: i32 = 25;
const WEIGHT_SERVICE_HIJACKED: i32 = 25;
const WEIGHT_SERVICE_PID_MISSING: i32 = 15;
const WEIGHT_DORMANT_SERVICE: i32 = 10;
const WEIGHT_SUSPICIOUS_PATH: i32 = 15;

/// Suspicious binary path patterns
const SUSPICIOUS_PATHS: &[&str] = &[
    "\\temp\\", "\\tmp\\", "\\users\\", "\\appdata\\",
    "\\programdata\\", "\\downloads\\",
];

pub struct PersistenceModule;

impl PipelineModule for PersistenceModule {
    fn id(&self) -> &str {
        "5_persistence"
    }
    
    fn name(&self) -> &str {
        "Persistence"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // 5a: Registry persistence already handled in Module 2
        // Results are in ctx.global_findings
        
        // 5b: Service validation chain
        let proc_map: HashMap<u32, &str> = ctx.data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        let proc_paths: HashMap<u32, String> = ctx.data.cmdlines
            .iter()
            .map(|c| {
                let path = c.args.split_whitespace().next().unwrap_or("").to_lowercase();
                (c.pid, path)
            })
            .collect();
        
        for svc in &ctx.data.services {
            // Skip allowlisted services
            if ctx.allowlisted_services.contains(&svc.name) {
                continue;
            }
            
            let svc_binary = svc.binary_path.as_deref().unwrap_or("").to_lowercase();
            let svc_binary_normalized = normalize_path(&svc_binary);
            
            // Parse service PID from string to u32
            let svc_pid: Option<u32> = svc.pid.as_ref()
                .and_then(|s| s.parse::<u32>().ok());
            
            // Step 1: Does the binary exist on disk (in filescan)?
            let binary_exists = ctx.filescan_paths.iter()
                .any(|f| {
                    let f_norm = normalize_path(f);
                    f_norm.contains(&svc_binary_normalized) || svc_binary_normalized.contains(&f_norm)
                });
            
            if !binary_exists && !svc_binary.is_empty() && !svc_binary.starts_with("\\driver\\") {
                let finding = Finding {
                    id: format!("SVC_GHOST_{}", svc.name.replace(' ', "_")),
                    rule_id: "MOD5B_GHOST".to_string(),
                    rule_name: "Ghost Service".to_string(),
                    title: format!("Ghost service — binary missing: {}", svc.name),
                    description: format!(
                        "Service '{}' registered with path '{}', but no matching FILE_OBJECT \
                        found in filescan. This could indicate deleted-on-run malware.",
                        svc.name, svc_binary
                    ),
                    severity: Severity::High,
                    confidence: 0.75,
                    mitre_attack: Some("T1543.003".to_string()),
                    related_pids: svc_pid.into_iter().collect(),
                    related_files: vec![svc_binary.clone()],
                    ..Default::default()
                };
                
                if let Some(pid) = svc_pid {
                    ctx.add_finding(pid, finding, WEIGHT_GHOST_SERVICE, self.id());
                } else {
                    ctx.add_global_finding(finding);
                }
                continue;
            }
            
            // Step 2: Is the service running? Does its PID exist?
            if let Some(pid) = svc_pid {
                if !proc_map.contains_key(&pid) {
                    // PID in svcscan doesn't exist in pslist
                    let finding = Finding {
                        id: format!("SVC_PID_MISSING_{}", svc.name.replace(' ', "_")),
                        rule_id: "MOD5B_PID_MISSING".to_string(),
                        rule_name: "Service PID Missing".to_string(),
                        title: format!("Service PID mismatch: {} (PID {} not in pslist)", svc.name, pid),
                        description: format!(
                            "Service '{}' claims to be running at PID {}, but this PID \
                            is not found in pslist. The process may be hidden or stale.",
                            svc.name, pid
                        ),
                        severity: Severity::Medium,
                        confidence: 0.70,
                        mitre_attack: Some("T1543.003".to_string()),
                        related_pids: vec![pid],
                        ..Default::default()
                    };
                    ctx.add_finding(pid, finding, WEIGHT_SERVICE_PID_MISSING, self.id());
                } else {
                    // Step 3: Does the running process path match the service binary?
                    if let Some(proc_path) = proc_paths.get(&pid) {
                        let proc_norm = normalize_path(proc_path);
                        
                        // Check if paths match (accounting for various formats)
                        let paths_match = proc_norm.contains(&svc_binary_normalized) 
                            || svc_binary_normalized.contains(&proc_norm)
                            || paths_equivalent(&proc_norm, &svc_binary_normalized);
                        
                        if !paths_match && !proc_norm.is_empty() && !svc_binary_normalized.is_empty() {
                            let finding = Finding {
                                id: format!("SVC_HIJACK_{}", svc.name.replace(' ', "_")),
                                rule_id: "MOD5B_HIJACK".to_string(),
                                rule_name: "Service Binary Hijacked".to_string(),
                                title: format!("Service binary hijacked: {}", svc.name),
                                description: format!(
                                    "Service '{}' expects binary '{}', but PID {} is running '{}'. \
                                    This could indicate service binary manipulation.",
                                    svc.name, svc_binary, pid, proc_path
                                ),
                                severity: Severity::High,
                                confidence: 0.65,
                                mitre_attack: Some("T1574.002".to_string()),
                                related_pids: vec![pid],
                                related_files: vec![svc_binary.clone(), proc_path.clone()],
                                ..Default::default()
                            };
                            ctx.add_finding(pid, finding, WEIGHT_SERVICE_HIJACKED, self.id());
                        }
                    }
                }
            } else {
                // Service registered but not running
                // Only flag if binary path is suspicious
                let is_suspicious = SUSPICIOUS_PATHS.iter()
                    .any(|&p| svc_binary.contains(p));
                
                if is_suspicious {
                    let finding = Finding {
                        id: format!("SVC_DORMANT_{}", svc.name.replace(' ', "_")),
                        rule_id: "MOD5B_DORMANT".to_string(),
                        rule_name: "Dormant Service".to_string(),
                        title: format!("Dormant service with suspicious path: {}", svc.name),
                        description: format!(
                            "Service '{}' registered but not running. Binary path '{}' \
                            is in a suspicious location. May execute on reboot.",
                            svc.name, svc_binary
                        ),
                        severity: Severity::Low,
                        confidence: 0.60,
                        mitre_attack: Some("T1543.003".to_string()),
                        related_files: vec![svc_binary.clone()],
                        ..Default::default()
                    };
                    ctx.add_global_finding(finding);
                }
            }
        }
        
        ctx
    }
}

/// Normalize path for comparison
fn normalize_path(path: &str) -> String {
    let mut p = path.to_lowercase();
    
    // Remove common prefixes
    for prefix in &["\\??\\", "\\systemroot\\", "\\windows\\"] {
        if p.starts_with(prefix) {
            p = p[prefix.len()..].to_string();
        }
    }
    
    // Replace forward slashes
    p.replace('/', "\\")
        .trim_matches('\\')
        .to_string()
}

/// Check if two paths are equivalent (e.g., short vs long form)
fn paths_equivalent(a: &str, b: &str) -> bool {
    // Extract just filename for comparison
    let name_a = a.rsplit('\\').next().unwrap_or("");
    let name_b = b.rsplit('\\').next().unwrap_or("");
    
    if name_a.is_empty() || name_b.is_empty() {
        return false;
    }
    
    name_a == name_b
}
