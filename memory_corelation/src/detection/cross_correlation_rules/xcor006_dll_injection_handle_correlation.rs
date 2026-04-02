//! XCOR006 – DllInjectionHandleCorrelationRule
use std::collections::{HashMap, HashSet};
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Correlate process handles with injection artefacts to identify DLL injectors.
///
/// Classic DLL injection flow:
///   OpenProcess (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
///   → WriteProcessMemory
///   → CreateRemoteThread
///
/// This rule flags processes that:
///   (A) Hold open Process-type handles with write/exec access masks, AND
///   (B) Either (i) themselves show malfind hits (self-injection staging), OR
///              (ii) other processes that received malfind hits are running at
///                   the same time (cross-process injection).
///
/// Access mask constants used by DLL injection:
///   PROCESS_CREATE_THREAD   0x0002
///   PROCESS_VM_OPERATION    0x0008
///   PROCESS_VM_WRITE        0x0020
///   PROCESS_ALL_ACCESS      0x001F0FFF / 0x001FFFFF
pub struct DllInjectionHandleCorrelationRule;

impl DetectionRule for DllInjectionHandleCorrelationRule {
    fn id(&self) -> &str {
        "XCOR006"
    }

    fn name(&self) -> &str {
        "DLL Injection: Process Handle + Injection Indicators"
    }

    fn description(&self) -> &str {
        "Detects DLL injection by correlating process handles with write/exec access \
        against malfind regions in victim processes"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1055.001") // Process Injection: DLL Injection
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.handles.is_empty() {
            return findings;
        }

        // Expected system processes that legitimately hold cross-process handles
        let benign_handle_holders = [
            "system", "svchost.exe", "services.exe", "wininit.exe",
            "winlogon.exe", "csrss.exe", "smss.exe", "lsass.exe",
            "antimalware service executable", "msmpeng.exe", "mssense.exe",
            "nissrv.exe", "securityhealth",
        ];

        // Access mask bits indicating write/execute capability (DLL injection prereqs)
        const PROCESS_CREATE_THREAD: u64 = 0x0002;
        const PROCESS_VM_OPERATION: u64 = 0x0008;
        const PROCESS_VM_WRITE: u64 = 0x0020;
        const DANGEROUS_MASK: u64 =
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

        // PIDs with REAL injection indicators (MZ headers = actual DLL injection, not JIT)
        // Only count malfind hits with MZ headers as corroboration —
        // JIT regions (no MZ) in MsMpEng, .NET, browsers, etc. are not injection.
        let mut malfind_pids_with_mz: HashMap<u32, (String, usize)> = HashMap::new();
        for mf in &data.malfind {
            if mf.has_mz_header() {
                let entry = malfind_pids_with_mz
                    .entry(mf.pid)
                    .or_insert_with(|| (mf.process.clone(), 0));
                entry.1 += 1;
            }
        }

        // Also track ALL malfind PIDs for self-malfind check
        let mut all_malfind_pids: HashMap<u32, usize> = HashMap::new();
        for mf in &data.malfind {
            *all_malfind_pids.entry(mf.pid).or_insert(0) += 1;
        }

        // Process name lookup
        let proc_names: HashMap<u32, &str> = data
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        // Collect PIDs that hold dangerous Process-type handles
        // Map: injector_pid → Vec<(access_mask_str, target_name)>
        let mut injector_candidates: HashMap<u32, (String, Vec<(String, String)>)> =
            HashMap::new();

        for handle in &data.handles {
            if handle.handle_type.to_lowercase() != "process" {
                continue;
            }

            let proc_lower = handle.process.to_lowercase();
            if benign_handle_holders
                .iter()
                .any(|b| proc_lower.starts_with(b) || proc_lower.contains(b))
            {
                continue;
            }

            // Parse the granted access mask (hex string like "0x1F0FFF")
            let access_mask = {
                let s = handle.granted_access.trim();
                let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                u64::from_str_radix(hex, 16).unwrap_or(0)
            };

            // PROCESS_ALL_ACCESS or specific write/create-thread bits
            let is_dangerous = (access_mask & DANGEROUS_MASK) == DANGEROUS_MASK
                || access_mask >= 0x001F0000; // ALL_ACCESS variants

            if is_dangerous {
                let entry = injector_candidates
                    .entry(handle.pid)
                    .or_insert_with(|| (handle.process.clone(), Vec::new()));
                let target_name = handle
                    .name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                entry.1.push((handle.granted_access.clone(), target_name));
            }
        }

        if injector_candidates.is_empty() {
            return findings;
        }

        // Build a set of malfind PIDs with MZ headers for quick lookup
        let malfind_pid_set: HashSet<u32> = malfind_pids_with_mz.keys().copied().collect();

        // Known injection tool name prefixes (lowercase)
        let injection_tools = [
            "inject", "reflective", "hollower", "processhacker",
            "minjector", "dllinjector", "syringe", "cobalt",
        ];

        // Build parent→child lookup
        let child_of: HashMap<u32, u32> = data.processes.iter()
            .map(|p| (p.pid, p.ppid))
            .collect();

        // Try to extract target PIDs from handle names like "lsass.exe Pid 708"
        // Returns the target PID if parseable
        fn extract_target_pid(handle_name: &str) -> Option<u32> {
            let lower = handle_name.to_lowercase();
            if let Some(pos) = lower.find("pid") {
                let after = &handle_name[pos + 3..].trim_start();
                let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u32>().ok()
            } else {
                None
            }
        }

        for (injector_pid, (proc_name, dangerous_handles)) in &injector_candidates {
            let proc_lower = proc_name.to_lowercase();

            // Check if this injector itself has malfind hits (any kind for self)
            let _self_malfind = all_malfind_pids.get(injector_pid).copied().unwrap_or(0);
            // But only count MZ-header malfind for self too (JIT self-injection is noise)
            let self_mz_malfind = malfind_pids_with_mz.get(injector_pid).map(|(_, c)| *c).unwrap_or(0);

            // Check if any of this process's handle TARGETS have malfind hits
            let mut targets_with_malfind = Vec::new();
            let mut target_pids_all = Vec::new();
            for (_access, target_name) in dangerous_handles {
                if let Some(tpid) = extract_target_pid(target_name) {
                    target_pids_all.push(tpid);
                    if malfind_pid_set.contains(&tpid) {
                        targets_with_malfind.push((tpid, target_name.clone()));
                    }
                }
            }

            // Check if this is a known injection tool
            let is_injection_tool = injection_tools.iter().any(|t| proc_lower.starts_with(t));

            // Check if handles point to parent/child (normal)
            let handles_are_parent_child = target_pids_all.iter().all(|tpid| {
                child_of.get(injector_pid) == Some(tpid) || child_of.get(tpid) == Some(injector_pid)
            });

            // FILTERING: Only report if we have corroborating evidence
            // Use MZ-header malfind hits (not JIT) for corroboration
            if self_mz_malfind == 0 && targets_with_malfind.is_empty() && !is_injection_tool {
                // No corroboration — skip or downgrade
                if handles_are_parent_child && !target_pids_all.is_empty() {
                    continue; // Parent-child handles are normal
                }
                if dangerous_handles.len() < 3 {
                    continue; // Too few handles with no corroboration, skip
                }
                // 3+ non-parent-child handles without malfind — unusual but low confidence
                // Skip these too to reduce noise
                continue;
            }

            // Build description of targets
            let target_description: Vec<String> = dangerous_handles
                .iter()
                .take(5)
                .map(|(access, target)| format!("target='{}' access={}", target, access))
                .collect();

            // Calculate confidence (use MZ malfind counts)
            let confidence = if self_mz_malfind > 0 && !targets_with_malfind.is_empty() {
                0.98 // Self MZ malfind AND target MZ malfind
            } else if self_mz_malfind > 0 || is_injection_tool {
                0.95 // Self MZ malfind or known tool
            } else if !targets_with_malfind.is_empty() {
                0.90 // Target has MZ malfind hits
            } else {
                0.70 // Handles only
            };

            let mut evidence = vec![Evidence {
                source_plugin: "handles+malfind".to_string(),
                source_file: String::new(),
                line_number: None,
                data: format!(
                    "PID:{} DangerousProcessHandles:{} SelfMZMalfind:{} TargetsWithMZMalfind:{} Targets:[{}]",
                    injector_pid,
                    dangerous_handles.len(),
                    self_mz_malfind,
                    targets_with_malfind.len(),
                    target_description.join("; ")
                ),
            }];

            if !targets_with_malfind.is_empty() {
                evidence.push(Evidence {
                    source_plugin: "malfind".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "Handle targets with injection indicators: {}",
                        targets_with_malfind.iter()
                            .map(|(pid, name)| format!("PID {} ({})", pid, name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }

            let proc_display = proc_names
                .get(injector_pid)
                .copied()
                .unwrap_or(proc_name.as_str());

            let description = if self_mz_malfind > 0 {
                format!(
                    "Process '{}' (PID {}) holds {} Process handle(s) with write/create-thread rights \
                    AND has {} MZ-header malfind hit(s) (DLL injection) in its own address space. \
                    This matches the DLL injection attacker profile: OpenProcess → WriteProcessMemory → CreateRemoteThread.",
                    proc_display, injector_pid, dangerous_handles.len(), self_mz_malfind
                )
            } else if !targets_with_malfind.is_empty() {
                format!(
                    "Process '{}' (PID {}) holds {} Process handle(s) with write/execute access to \
                    processes that show injection indicators (malfind hits). Targets with hits: {}.",
                    proc_display, injector_pid, dangerous_handles.len(),
                    targets_with_malfind.iter()
                        .map(|(pid, name)| format!("{} (PID {})", name, pid))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "Known injection tool '{}' (PID {}) holds {} Process handle(s) with \
                    write/create-thread access rights (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                    PROCESS_CREATE_THREAD).",
                    proc_display, injector_pid, dangerous_handles.len()
                )
            };

            let mut finding = create_finding(
                self,
                format!(
                    "DLL injection source: {} (PID {}) with {} dangerous process handle(s)",
                    proc_display, injector_pid, dangerous_handles.len()
                ),
                description,
                evidence,
            );
            finding.related_pids = vec![*injector_pid];
            finding.confidence = confidence;
            findings.push(finding);
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex address string (e.g., "0x7ff6e8a10000" or "7ff6e8a10000") to u64
pub fn parse_hex_addr(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let hex_str = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(hex_str, 16).ok()
}
