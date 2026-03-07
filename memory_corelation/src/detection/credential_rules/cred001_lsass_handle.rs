//! CRED001 – LsassHandleRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect processes holding handles to lsass.exe
/// This is the primary indicator of credential dumping (T1003)
pub struct LsassHandleRule;

impl DetectionRule for LsassHandleRule {
    fn id(&self) -> &str {
        "CRED001"
    }

    fn name(&self) -> &str {
        "LSASS Process Handle Detection"
    }

    fn description(&self) -> &str {
        "Detects non-system processes holding handles to lsass.exe, indicating potential credential dumping"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1003") // OS Credential Dumping
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // First, find lsass PID
        let lsass_pids: HashSet<u32> = data.processes
            .iter()
            .filter(|p| p.name.to_lowercase() == "lsass.exe")
            .map(|p| p.pid)
            .collect();
        
        if lsass_pids.is_empty() {
            return findings; // No lsass found (unusual, but can't proceed)
        }
        
        // Build PID to process name map
        let pid_map: HashMap<u32, &str> = data.processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();
        
        // Whitelist of processes legitimately allowed to touch lsass
        let legitimate_holders = [
            "lsass.exe",
            "csrss.exe",
            "services.exe",
            "wininit.exe",
            "system",
            "smss.exe",
            "svchost.exe",
            "lsaiso.exe",    // Credential Guard
            "mrt.exe",       // Windows Malicious Software Removal Tool
            "mpcmdrun.exe",  // Windows Defender
            "msmpeng.exe",   // Windows Defender
        ];
        
        // Known credential dumping tools
        let known_dumpers = [
            "procdump", "procdump64", "mimikatz", "wce", "pwdump",
            "fgdump", "gsecdump", "secretsdump", "pypykatz", "nanodump",
            "handlekatz", "lsassy", "comsvcs", "sqldumper",
        ];
        
        // Track unique holder processes to avoid duplicate findings
        let mut seen_holders: HashSet<u32> = HashSet::new();
        
        for handle in &data.handles {
            // Check if this is a Process handle
            if handle.handle_type.to_lowercase() != "process" {
                continue;
            }
            
            // Check if the target is lsass (by name in handle details)
            let target_name = handle.name.as_deref().unwrap_or("").to_lowercase();
            let is_lsass_handle = target_name.contains("lsass") || 
                lsass_pids.iter().any(|&lsass_pid| {
                    target_name.contains(&format!("pid {}", lsass_pid)) ||
                    target_name.contains(&format!("\\{}", lsass_pid))
                });
            
            if !is_lsass_handle {
                continue;
            }
            
            // Skip if holder is lsass itself or a legitimate process
            let holder_name = handle.process.to_lowercase();
            if legitimate_holders.iter().any(|&l| holder_name.contains(l)) {
                continue;
            }
            
            // Skip if already reported this holder
            if seen_holders.contains(&handle.pid) {
                continue;
            }
            seen_holders.insert(handle.pid);
            
            // Determine severity based on holder process
            let is_known_dumper = known_dumpers.iter().any(|&d| holder_name.contains(d));
            
            // Parse and decode granted_access
            let access_mask = handle.granted_access.trim_start_matches("0x");
            let mask_u32 = u32::from_str_radix(access_mask, 16).unwrap_or(0);
            
            let mut permissions = Vec::new();
            if mask_u32 & 0x1000 != 0 { permissions.push("QUERY_LIMITED_INFO"); }
            if mask_u32 & 0x0400 != 0 { permissions.push("QUERY_INFO"); }
            if mask_u32 & 0x0020 != 0 { permissions.push("VM_WRITE"); }
            if mask_u32 & 0x0010 != 0 { permissions.push("VM_READ"); }
            if mask_u32 & 0x0008 != 0 { permissions.push("VM_OPERATION"); }
            if mask_u32 & 0x0002 != 0 { permissions.push("CREATE_THREAD"); }
            if mask_u32 & 0x1F0FFF == 0x1F0FFF { permissions.push("ALL_ACCESS"); }
            
            let perm_str = if permissions.is_empty() {
                "Unknown".to_string()
            } else {
                permissions.join(" | ")
            };
            
            // Check for dangerous combination (VM_READ + VM_WRITE is critical for dumping)
            let is_dangerous_access = (mask_u32 & 0x0010 != 0) && (mask_u32 & 0x0008 != 0); // VM_READ | VM_OPERATION
            
            let severity = if is_known_dumper || is_dangerous_access {
                Severity::Critical
            } else {
                Severity::High
            };
            
            let confidence = if is_known_dumper { 0.98 } else if is_dangerous_access { 0.90 } else { 0.70 };
            
            // Get holder process creation time for context
            let create_time = data.processes.iter()
                .find(|p| p.pid == handle.pid)
                .and_then(|p| p.create_time)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or("Unknown".to_string());
            
            let mut finding = create_finding(
                self,
                format!("Potential credential dump: {} accessing lsass", handle.process),
                format!(
                    "Process '{}' (PID {}) is holding a handle to lsass.exe. \
                    This is a strong indicator of credential dumping activity. \
                    \n\nGranted Access: {} ({})\n\
                    Decoded Rights: {}\n\
                    Holder Created: {}\n\
                    {}\n\n\
                    Analysis: A handle with VM_READ/VM_WRITE access allows reading LSASS memory to extract credentials.",
                    handle.process, handle.pid, handle.granted_access, mask_u32,
                    perm_str,
                    create_time,
                    if is_known_dumper { " [KNOWN CREDENTIAL DUMPING TOOL]" } else { "" }
                ),
                vec![
                    Evidence {
                        source_plugin: "handles".to_string(),
                        source_file: "".to_string(),
                        line_number: None,
                        data: format!(
                            "Holder: {} (PID {}) Target: lsass.exe Access: {} ({})",
                            handle.process, handle.pid, handle.granted_access, perm_str
                        ),
                    },
                    Evidence {
                        source_plugin: "pslist".to_string(),
                        source_file: "".to_string(),
                        line_number: None,
                        data: format!("Process Created: {}", create_time),
                    }
                ],
            );
            finding.severity = severity;
            finding.related_pids = vec![handle.pid];
            finding.confidence = confidence;
            findings.push(finding);
        }

        findings
    }
}
