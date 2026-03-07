//! Forensic metadata extraction from parsed Volatility 3 data
//!
//! This module extracts Chain of Custody, System Profile, and User Activity
//! evidence from the parsed plugin outputs.

use crate::models::forensic_metadata::{
    AnalystQuickView, EnvironmentSummary, HandleSummary, QuickCommand, QuickDll, QuickFile,
    QuickNetConn, QuickRegKey, QuickService, QuickUserAssist, SessionInfo, SystemProfile,
    UserActivityEvidence,
};
use crate::parsers::ParsedData;
use std::collections::{HashMap, HashSet};

/// Extract user activity evidence from parsed data
pub fn extract_user_activity(data: &ParsedData) -> UserActivityEvidence {
    let mut activity = UserActivityEvidence::default();

    // Extract environment variable summaries for suspicious processes
    activity.environment_summary = extract_environment_summary(data);

    // Extract interesting handles
    activity.interesting_handles = extract_interesting_handles(data);

    // Extract session information from processes
    activity.sessions = extract_sessions(data);

    activity
}

/// Extract environment variable summaries grouped by process
fn extract_environment_summary(data: &ParsedData) -> Vec<EnvironmentSummary> {
    let mut by_pid: HashMap<u32, EnvironmentSummary> = HashMap::new();

    for envar in &data.envars {
        let entry = by_pid.entry(envar.pid).or_insert_with(|| EnvironmentSummary {
            pid: envar.pid,
            process_name: envar.process.clone(),
            username: None,
            computer_name: None,
            temp_path: None,
            user_profile: None,
            notable_vars: Vec::new(),
        });

        let var_upper = envar.variable.to_uppercase();
        match var_upper.as_str() {
            "USERNAME" | "USER" => entry.username = Some(envar.value.clone()),
            "COMPUTERNAME" => entry.computer_name = Some(envar.value.clone()),
            "TEMP" | "TMP" => entry.temp_path = Some(envar.value.clone()),
            "USERPROFILE" => entry.user_profile = Some(envar.value.clone()),
            // Collect notable/suspicious environment variables
            "PSModulePath" | "PROCESSOR_ARCHITECTURE" | "SYSTEMROOT" => {
                entry
                    .notable_vars
                    .push((envar.variable.clone(), envar.value.clone()));
            }
            _ => {
                // Check for potentially suspicious environment variables
                if is_suspicious_envar(&envar.variable, &envar.value) {
                    entry
                        .notable_vars
                        .push((envar.variable.clone(), envar.value.clone()));
                }
            }
        }
    }

    // Only include processes with interesting data
    by_pid
        .into_values()
        .filter(|env| {
            env.username.is_some()
                || env.computer_name.is_some()
                || !env.notable_vars.is_empty()
        })
        .take(20) // Limit to 20 most relevant
        .collect()
}

/// Check if an environment variable is potentially suspicious
fn is_suspicious_envar(name: &str, value: &str) -> bool {
    let name_lower = name.to_lowercase();
    let value_lower = value.to_lowercase();

    // Check for common attack indicators
    name_lower.contains("password")
        || name_lower.contains("secret")
        || name_lower.contains("token")
        || name_lower.contains("api_key")
        || name_lower.contains("credential")
        || value_lower.contains("powershell")
        || value_lower.contains("cmd.exe")
        || value_lower.contains("http://")
        || value_lower.contains("https://")
        || value_lower.contains("base64")
}

/// Extract interesting handles from parsed data
fn extract_interesting_handles(data: &ParsedData) -> Vec<HandleSummary> {
    let mut handles = Vec::new();

    for handle in &data.handles {
        let name = handle.name.as_deref().unwrap_or("");
        if name.is_empty() {
            continue;
        }

        let (is_suspicious, reason) = analyze_handle(handle);

        // Include interesting handles (limited to 50)
        if is_interesting_handle(handle) || is_suspicious {
            if handles.len() < 50 {
                handles.push(HandleSummary {
                    pid: handle.pid,
                    process_name: handle.process.clone(),
                    handle_type: handle.handle_type.clone(),
                    name: name.to_string(),
                    is_suspicious,
                    reason,
                });
            }
        }
    }

    handles
}

/// Check if a handle is interesting for forensic purposes
fn is_interesting_handle(handle: &crate::models::files::HandleInfo) -> bool {
    let handle_type_lower = handle.handle_type.to_lowercase();
    let name_lower = handle.name.as_deref().unwrap_or("").to_lowercase();

    // Interesting handle types
    if handle_type_lower == "mutant" || handle_type_lower == "mutex" {
        return true;
    }

    // Registry keys related to persistence
    if handle_type_lower == "key" {
        if name_lower.contains("\\run")
            || name_lower.contains("\\services")
            || name_lower.contains("\\currentversion")
        {
            return true;
        }
    }

    // Files in suspicious locations
    if handle_type_lower == "file" {
        if name_lower.contains("\\temp\\")
            || name_lower.contains("\\downloads\\")
            || name_lower.contains("\\appdata\\local\\temp")
        {
            return true;
        }
    }

    false
}

/// Analyze a handle for suspicious characteristics
fn analyze_handle(
    handle: &crate::models::files::HandleInfo,
) -> (bool, Option<String>) {
    let handle_type_lower = handle.handle_type.to_lowercase();
    let name_lower = handle.name.as_deref().unwrap_or("").to_lowercase();

    // Check for sensitive process handles (credential dumping indicator)
    if handle_type_lower == "process" && name_lower.contains("lsass") {
        return (
            true,
            Some("Handle to LSASS process - potential credential access".to_string()),
        );
    }

    // Check for suspicious mutex names (malware indicators)
    if handle_type_lower == "mutant" || handle_type_lower == "mutex" {
        let suspicious_mutexes = [
            "global\\", "dce", "rat", "bot", "shell", "inject", "hook",
        ];
        for pattern in suspicious_mutexes {
            if name_lower.contains(pattern) {
                return (
                    true,
                    Some(format!("Suspicious mutex name containing '{}'", pattern)),
                );
            }
        }
    }

    // Check for suspicious file handles
    if handle_type_lower == "file" {
        if name_lower.ends_with(".ps1")
            || name_lower.ends_with(".vbs")
            || name_lower.ends_with(".bat")
        {
            if name_lower.contains("\\temp\\") || name_lower.contains("\\downloads\\") {
                return (
                    true,
                    Some("Script file in suspicious location".to_string()),
                );
            }
        }
    }

    (false, None)
}

/// Extract session information from process data
fn extract_sessions(data: &ParsedData) -> Vec<SessionInfo> {
    let mut sessions: HashMap<u32, SessionInfo> = HashMap::new();

    // Extract unique sessions from processes
    for process in &data.processes {
        if let Some(ref session_str) = process.session {
            if let Ok(session_id) = session_str.parse::<u32>() {
                sessions.entry(session_id).or_insert_with(|| SessionInfo {
                    session_id,
                    username: None,
                    logon_type: if session_id == 0 {
                        Some("System".to_string())
                    } else if session_id == 1 {
                        Some("Interactive (Console)".to_string())
                    } else {
                        Some("Interactive (Remote)".to_string())
                    },
                    logon_time: process.create_time,
                    authentication_package: None,
                });
            }
        }
    }

    sessions.into_values().collect()
}

/// Extract system profile from parsed data
pub fn extract_system_profile(data: &ParsedData) -> SystemProfile {
    let mut profile = SystemProfile::new();

    // Try to extract system information from environment variables
    let mut seen_computers: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_users: std::collections::HashSet<String> = std::collections::HashSet::new();

    for envar in &data.envars {
        let var_upper = envar.variable.to_uppercase();
        match var_upper.as_str() {
            "COMPUTERNAME" => {
                if !seen_computers.contains(&envar.value) {
                    profile.computer_name = Some(envar.value.clone());
                    seen_computers.insert(envar.value.clone());
                }
            }
            "USERDOMAIN" | "USERDNSDOMAIN" => {
                profile.domain = Some(envar.value.clone());
            }
            "USERNAME" | "USER" => {
                if !seen_users.contains(&envar.value) {
                    seen_users.insert(envar.value.clone());
                }
            }
            "PROCESSOR_ARCHITECTURE" => {
                profile.architecture = Some(envar.value.clone());
            }
            "NUMBER_OF_PROCESSORS" => {
                if let Ok(count) = envar.value.parse::<u32>() {
                    profile.processor_count = Some(count);
                }
            }
            "SYSTEMROOT" => {
                profile.system_root = Some(envar.value.clone());
            }
            _ => {}
        }
    }

    // Set active users
    profile.active_users = seen_users.into_iter().collect();

    // Detect security software from running processes
    for process in &data.processes {
        let name_lower = process.name.to_lowercase();
        if is_security_software(&name_lower) {
            let software_name = get_security_software_name(&name_lower);
            if !profile.security_software.contains(&software_name) {
                profile.security_software.push(software_name);
            }
        }
    }

    // Default OS info if not detected
    if profile.os_name.is_none() {
        profile.os_name = Some("Windows".to_string());
    }

    profile
}

/// Check if a process is security software
fn is_security_software(process_name: &str) -> bool {
    let security_processes = ["tmedr", "tmsm", "tmcss"]; // Trend Micro EDR
    security_processes.iter().any(|p| process_name.contains(p))
}

/// Get the display name for security software
fn get_security_software_name(_process_name: &str) -> String {
    "Trend Micro EDR".to_string()
}

// ── Analyst Quick-View extraction ───────────────────────────────────────

/// Build the analyst quick-view from all available parsed data.
pub fn extract_analyst_quickview(data: &ParsedData) -> AnalystQuickView {
    AnalystQuickView {
        executed_commands: extract_quick_commands(data),
        network_connections: extract_quick_net(data),
        registry_keys: extract_quick_reg(data),
        interesting_files: extract_quick_files(data),
        services: extract_quick_services(data),
        programs_run: extract_quick_userassist(data),
        suspicious_dlls: extract_quick_dlls(data),
    }
}

// ─── commands ─────────────────────────────────────────────

fn extract_quick_commands(data: &ParsedData) -> Vec<QuickCommand> {
    let mut cmds = Vec::new();

    // Build PID → (process_name, ppid) lookup from all processes
    let proc_map: HashMap<u32, (&str, u32)> = data
        .processes
        .iter()
        .map(|p| (p.pid, (p.name.as_str(), p.ppid)))
        .collect();

    // Helper closure: resolve parent info for a given pid
    let parent_info = |pid: u32| -> (u32, String) {
        if let Some(&(_name, ppid)) = proc_map.get(&pid) {
            let parent_name = proc_map
                .get(&ppid)
                .map(|(n, _)| n.to_string())
                .unwrap_or_else(|| "<unknown>".into());
            (ppid, parent_name)
        } else {
            (0, "<unknown>".into())
        }
    };

    // 1) cmdline plugin
    for cl in &data.cmdlines {
        let args = cl.args.trim();
        if args.is_empty() || args == "N/A" || args == "-" {
            continue;
        }
        let (ppid, parent) = parent_info(cl.pid);
        cmds.push(QuickCommand {
            pid: cl.pid,
            process: cl.process.clone(),
            ppid,
            parent_process: parent,
            command: args.to_string(),
            source: "cmdline".into(),
        });
    }

    // 2) cmdscan / consoles (recursive children extraction)
    for (label, records) in [
        ("cmdscan", &data.cmdscan_records),
        ("consoles", &data.console_records),
    ] {
        for rec in records {
            collect_commands_from_json(rec, label, &proc_map, &mut cmds);
        }
    }

    cmds
}

/// Walk the `__children` tree of cmdscan / consoles records and pull out
/// things that look like commands.
fn collect_commands_from_json(
    val: &serde_json::Value,
    source: &str,
    proc_map: &HashMap<u32, (&str, u32)>,
    out: &mut Vec<QuickCommand>,
) {
    if let Some(obj) = val.as_object() {
        // Try to get a command-like field
        let cmd = obj
            .get("CommandHistory")
            .or_else(|| obj.get("Command"))
            .or_else(|| obj.get("Output"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if !cmd.is_empty() && cmd != "N/A" {
            let pid = obj
                .get("PID")
                .or_else(|| obj.get("Pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let proc_name = obj
                .get("Application")
                .or_else(|| obj.get("Process"))
                .or_else(|| obj.get("Name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let (ppid, parent) = if let Some(&(_name, ppid)) = proc_map.get(&pid) {
                let pn = proc_map
                    .get(&ppid)
                    .map(|(n, _)| n.to_string())
                    .unwrap_or_else(|| "<unknown>".into());
                (ppid, pn)
            } else {
                (0, "<unknown>".into())
            };
            out.push(QuickCommand {
                pid,
                process: proc_name,
                ppid,
                parent_process: parent,
                command: cmd.to_string(),
                source: source.into(),
            });
        }
        // Recurse into __children
        if let Some(children) = obj.get("__children").and_then(|v| v.as_array()) {
            for child in children {
                collect_commands_from_json(child, source, proc_map, out);
            }
        }
    }
}

// ─── network ──────────────────────────────────────────────

fn extract_quick_net(data: &ParsedData) -> Vec<QuickNetConn> {
    let mut conns: Vec<QuickNetConn> = Vec::new();
    let mut seen = HashSet::new();

    for c in &data.connections {
        // De-duplicate by (remote, remote_port, pid)
        let key = format!("{}:{}:{}", c.foreign_addr, c.foreign_port, c.pid);
        if !seen.insert(key) {
            continue;
        }

        // Prefer external and ESTABLISHED, but include LISTENING too
        let state = c
            .state
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let owner = c.owner.as_deref().unwrap_or("").to_string();

        conns.push(QuickNetConn {
            pid: c.pid,
            process: owner,
            protocol: c.protocol.clone(),
            local: format!("{}:{}", c.local_addr, c.local_port),
            remote: format!("{}:{}", c.foreign_addr, c.foreign_port),
            state,
        });
    }

    // Sort: external first, then ESTABLISHED first
    conns.sort_by(|a, b| {
        let a_ext = !a.remote.starts_with("0.0.0.0")
            && !a.remote.starts_with("127.")
            && !a.remote.starts_with("*")
            && !a.remote.starts_with("::");
        let b_ext = !b.remote.starts_with("0.0.0.0")
            && !b.remote.starts_with("127.")
            && !b.remote.starts_with("*")
            && !b.remote.starts_with("::");
        b_ext.cmp(&a_ext).then_with(|| {
            let a_est = a.state.contains("ESTAB");
            let b_est = b.state.contains("ESTAB");
            b_est.cmp(&a_est)
        })
    });
    conns
}

// ─── registry ─────────────────────────────────────────────

fn extract_quick_reg(data: &ParsedData) -> Vec<QuickRegKey> {
    let mut keys = Vec::new();
    for rk in &data.registry_keys {
        keys.push(QuickRegKey {
            key: rk.key.clone(),
            name: rk.name.clone().unwrap_or_default(),
            data: rk.data.clone().unwrap_or_default(),
            value_type: rk.value_type.clone().unwrap_or_default(),
        });
    }
    keys
}

// ─── files ────────────────────────────────────────────────

fn extract_quick_files(data: &ParsedData) -> Vec<QuickFile> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();

    for f in &data.files {
        let lower = f.name.to_lowercase();
        // Skip kernel / driver noise
        if lower.starts_with("\\device\\") && !lower.contains("\\users\\") && !lower.contains("\\temp") {
            continue;
        }

        let reason = if f.is_staging_pattern() {
            "staging path"
        } else if f.is_executable() {
            if lower.contains("\\temp\\") || lower.contains("\\tmp\\") {
                "executable in Temp"
            } else if lower.contains("\\downloads\\") {
                "executable in Downloads"
            } else if lower.contains("\\appdata\\") {
                "executable in AppData"
            } else if lower.contains("\\programdata\\") {
                "executable in ProgramData"
            } else if lower.contains("\\public\\") {
                "executable in Public"
            } else {
                continue; // normal executable, skip
            }
        } else if lower.contains("\\downloads\\") {
            "in Downloads"
        } else {
            continue;
        };

        if seen.insert(f.name.clone()) {
            files.push(QuickFile {
                path: f.name.clone(),
                reason: reason.to_string(),
            });
        }
    }

    // Also pull from MFT if we have entries
    for m in &data.mft_entries {
        if let Some(ref fname) = m.filename {
            let lower = fname.to_lowercase();
            if (lower.contains("\\temp\\") || lower.contains("\\downloads\\") || lower.contains("\\appdata\\"))
                && crate::models::mft::MftEntry::SUSPICIOUS_EXTENSIONS
                    .iter()
                    .any(|ext| lower.ends_with(ext))
            {
                if seen.insert(fname.clone()) {
                    files.push(QuickFile {
                        path: fname.clone(),
                        reason: "MFT: suspicious location".to_string(),
                    });
                }
            }
        }
    }
    files
}

// ─── services ─────────────────────────────────────────────

fn extract_quick_services(data: &ParsedData) -> Vec<QuickService> {
    let mut svcs = Vec::new();
    for s in &data.services {
        svcs.push(QuickService {
            name: s.name.clone(),
            display_name: s.display_name.clone().unwrap_or_default(),
            state: s.state.clone().unwrap_or_default(),
            binary: s.binary_path.clone().unwrap_or_default(),
            start_type: s.start_type.clone().unwrap_or_default(),
        });
    }
    // Sort running services first
    svcs.sort_by(|a, b| {
        let a_run = a.state.to_uppercase().contains("RUNNING");
        let b_run = b.state.to_uppercase().contains("RUNNING");
        b_run.cmp(&a_run)
    });
    svcs
}

// ─── userassist ───────────────────────────────────────────

fn extract_quick_userassist(data: &ParsedData) -> Vec<QuickUserAssist> {
    let mut items: Vec<QuickUserAssist> = data
        .userassist
        .iter()
        .filter(|ua| ua.is_executable() || ua.count.unwrap_or(0) > 0)
        .map(|ua| QuickUserAssist {
            path: ua.path.clone(),
            count: ua.count.unwrap_or(0),
            last_run: ua
                .last_updated
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default(),
        })
        .collect();
    // Sort by count desc
    items.sort_by(|a, b| b.count.cmp(&a.count));
    items
}

// ─── suspicious DLLs ─────────────────────────────────────

fn extract_quick_dlls(data: &ParsedData) -> Vec<QuickDll> {
    let mut dlls = Vec::new();
    let mut seen = HashSet::new();

    for d in &data.dlls {
        let path_lower = d.path.to_lowercase();
        let name_lower = d.name.to_lowercase();

        let reason = if path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\") {
            "loaded from Temp"
        } else if path_lower.contains("\\appdata\\") && !path_lower.contains("\\local\\microsoft\\") {
            "loaded from AppData"
        } else if path_lower.contains("\\downloads\\") {
            "loaded from Downloads"
        } else if path_lower.contains("\\public\\") {
            "loaded from Public"
        } else if name_lower.ends_with(".dll") && !path_lower.contains("\\windows\\")
            && !path_lower.contains("\\program files")
            && !path_lower.contains("\\winsxs\\")
            && !path_lower.is_empty()
        {
            "non-standard path"
        } else {
            continue;
        };

        let key = format!("{}:{}", d.pid, d.path);
        if seen.insert(key) {
            dlls.push(QuickDll {
                pid: d.pid,
                process: d.name.clone(),
                dll_path: d.path.clone(),
                reason: reason.to_string(),
            });
        }
    }
    dlls
}
