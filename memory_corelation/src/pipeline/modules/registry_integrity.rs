//! Module 2: Registry Integrity
//!
//! Detects hidden registry hives via hivelist vs hivescan set-diff.

use std::collections::HashSet;

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Evidence, Finding, Severity};

/// Weight constants
const WEIGHT_HIDDEN_HIVE: i32 = 35;

pub struct RegistryIntegrityModule;

impl PipelineModule for RegistryIntegrityModule {
    fn id(&self) -> &str {
        "2_registry_integrity"
    }
    
    fn name(&self) -> &str {
        "Registry Integrity"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Get paths from hivelist (path is String, not Option<String>)
        let hivelist_paths: HashSet<String> = ctx.data.hives
            .iter()
            .map(|h| h.path.to_lowercase())
            .collect();
        
        // Get paths from hivescan
        let hivescan_paths: HashSet<String> = ctx.data.hivescan_hives
            .iter()
            .map(|h| h.path.to_lowercase())
            .collect();
        
        // Hidden = in hivescan but not in hivelist
        let hidden_paths: HashSet<&String> = hivescan_paths
            .iter()
            .filter(|p| !hivelist_paths.contains(*p))
            .collect();
        
        for path in hidden_paths {
            // Skip empty paths
            if path.is_empty() || path == "n/a" {
                continue;
            }
            
            // Whitelist legitimate transient hives
            // Delivery Optimization service creates dosvcState.dat which often appears unlinked
            let is_dosvc = path.to_lowercase().contains("dosvcstate.dat") || 
                           path.to_lowercase().contains("deliveryoptimization");
            
            if is_dosvc {
                // Downgrade to Info or skip
                let finding = Finding {
                    id: format!("HIVE_DOSVC_{}", path.chars().take(20).collect::<String>()),
                    rule_id: "MOD2_INFO_HIVE".to_string(),
                    rule_name: "Transient Registry Hive Detected".to_string(),
                    title: format!("delivery Optimization hive detected: {}", path),
                    description: format!(
                        "Registry hive '{}' is present in hivescan but absent from hivelist. \
                        This is typically a legitimate state file for the Delivery Optimization service (DoSvc) \
                        and not a malicious hidden hive.",
                        path
                    ),
                    severity: Severity::Info,
                    confidence: 0.95,
                    mitre_attack: None,
                    related_pids: vec![],
                    related_files: vec![path.clone()],
                    evidence: vec![Evidence {
                        source_plugin: "hivescan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Legitimate transient hive: {}", path),
                    }],
                    ..Default::default()
                };
                ctx.add_global_finding(finding);
                continue;
            }
            
            let finding = Finding {
                id: format!("HIVE_HIDDEN_{}", path.chars().take(20).collect::<String>()),
                rule_id: "MOD2_HIDDEN_HIVE".to_string(),
                rule_name: "Hidden Registry Hive".to_string(),
                title: format!("Hidden registry hive: {}", path),
                description: format!(
                    "Registry hive '{}' is present in hivescan but absent from hivelist. \
                    This indicates the hive has been unlinked from the kernel's hive list. \
                    Hidden hives are often used to conceal persistence keys (Run, Services, etc.).",
                    path
                ),
                severity: Severity::Critical,
                confidence: 0.90,
                mitre_attack: Some("T1014".to_string()), // Rootkit
                related_pids: vec![],
                related_files: vec![path.clone()],
                evidence: vec![Evidence {
                    source_plugin: "hivescan".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("Hidden hive path: {}", path),
                }],
                ..Default::default()
            };
            
            ctx.add_global_finding(finding);
        }
        
        // Also check for duplicate hive paths in hivescan (multiple offsets = suspicious)
        let mut path_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for hive in &ctx.data.hivescan_hives {
            let p = hive.path.to_lowercase();
            *path_counts.entry(p).or_insert(0) += 1;
        }
        
        for (path, count) in path_counts {
            if count > 1 && !path.is_empty() && path != "n/a" {
                let finding = Finding {
                    id: format!("HIVE_DUP_{}", path.chars().take(20).collect::<String>()),
                    rule_id: "MOD2_DUP_HIVE".to_string(),
                    rule_name: "Duplicate Registry Hive".to_string(),
                    title: format!("Duplicate hive offsets: {} ({} instances)", path, count),
                    description: format!(
                        "Registry hive '{}' appears at {} different memory offsets. \
                        This could indicate hive manipulation or forensic artifact remnants.",
                        path, count
                    ),
                    severity: Severity::Medium,
                    confidence: 0.70,
                    mitre_attack: Some("T1112".to_string()), // Modify Registry
                    related_pids: vec![],
                    related_files: vec![path.clone()],
                    evidence: vec![Evidence {
                        source_plugin: "hivescan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Path: {} | Count: {}", path, count),
                    }],
                    ..Default::default()
                };
                
                ctx.add_global_finding(finding);
            }
        }
        
        ctx
    }
}
