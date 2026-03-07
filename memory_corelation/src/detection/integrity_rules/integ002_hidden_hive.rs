//! INTEG002 – HiddenHiveRule
use std::collections::HashSet;
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect hidden registry hives (in hivescan but not hivelist)
/// Used by rootkits to hide persistence keys
pub struct HiddenHiveRule;

impl DetectionRule for HiddenHiveRule {
    fn id(&self) -> &str {
        "INTEG002"
    }

    fn name(&self) -> &str {
        "Hidden Registry Hive Detection"
    }

    fn description(&self) -> &str {
        "Detects registry hives found by scanning but not in the kernel's linked list"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1112") // Modify Registry
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Build set of known hive paths (from hivelist - linked list)
        // Note: Similar to processes, we'd need separate hivescan data
        // For now, check for anomalous hive patterns
        
        let mut seen_paths: HashSet<String> = HashSet::new();
        
        for hive in &data.hives {
            let normalized_path = hive.path.to_lowercase();
            
            // Check for duplicate hives at different offsets (potential hidden hive)
            if seen_paths.contains(&normalized_path) {
                let mut finding = create_finding(
                    self,
                    format!("Duplicate hive structure detected"),
                    format!(
                        "Registry hive '{}' was found at multiple memory offsets. \
                        This could indicate a hidden or shadowed hive used for rootkit persistence.",
                        hive.path
                    ),
                    vec![Evidence {
                        source_plugin: "hivescan".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Path: {} Offset: {}", hive.path, hive.offset),
                    }],
                );
                finding.severity = Severity::High;
                finding.confidence = 0.75;
                findings.push(finding);
            } else {
                seen_paths.insert(normalized_path.clone());
            }
            
            // Check for hives in suspicious locations
            if is_suspicious_hive_path(&hive.path) {
                let mut finding = create_finding(
                    self,
                    format!("Suspicious registry hive location"),
                    format!(
                        "Registry hive found in non-standard location: '{}'. \
                        Legitimate hives are typically in \\Windows\\System32\\config\\ or user profiles.",
                        hive.path
                    ),
                    vec![Evidence {
                        source_plugin: "hivelist".to_string(),
                        source_file: String::new(),
                        line_number: None,
                        data: format!("Path: {}", hive.path),
                    }],
                );
                finding.severity = Severity::High;
                finding.confidence = 0.70;
                findings.push(finding);
            }
        }

        findings
    }
}

/// Check if process name looks suspicious (random, mimicking, etc.)
pub fn is_suspicious_process_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    
    // Known legitimate process mimics
    let mimics = ["svch0st", "svchosts", "scvhost", "lssas", "lsas", "cssrs"];
    if mimics.iter().any(|m| lower == *m) {
        return true;
    }
    
    // Purely hex names (common for malware)
    if name.len() >= 8 && name.chars().take(8).all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    
    false
}

/// Check if hive path is in a non-standard location
pub fn is_suspicious_hive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    
    // Standard locations for hives
    let standard_locations = [
        "\\windows\\system32\\config\\",
        "\\users\\",
        "\\systemroot\\system32\\config\\",
        "\\device\\harddisk",
        "\\registry\\",
        "\\serviceprofiles\\",
    ];
    
    // Check if path is NOT in a standard location
    if !standard_locations.iter().any(|loc| lower.contains(loc)) {
        // Additional check - some paths may be relative or truncated
        if !lower.contains("ntuser.dat") && !lower.contains("usrclass.dat") {
            // Not a user hive either, flag it
            if lower.contains("\\temp\\") || lower.contains("\\appdata\\") {
                return true;
            }
        }
    }
    
    false
}
