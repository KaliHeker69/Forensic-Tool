//! Module 3: Cmdline Analysis
//!
//! Three sub-stages:
//! - 3A: Structural anomalies (missing/stomped cmdline)
//! - 3B: Parent-child anomalies
//! - 3C: Signature patterns (encoded PS, LOLBins, recon)

use std::collections::HashMap;

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;
use crate::{Finding, Severity};

// Weight constants
const WEIGHT_MISSING_CMDLINE: i32 = 20;
const WEIGHT_NAME_MISMATCH: i32 = 25;
const WEIGHT_ANOMALOUS_PARENT: i32 = 20;
const WEIGHT_ENCODED_PS: i32 = 20;
const WEIGHT_LOLBIN: i32 = 15;
const WEIGHT_RECON: i32 = 10;
const WEIGHT_CHILD_OF_INJECTED: i32 = 15;

/// Anomalous parent-child pairs: (child, allowed_parents, mitre)
const ANOMALOUS_PAIRS: &[(&str, &[&str], &str)] = &[
    // Command shells
    ("cmd.exe",
        &["explorer.exe", "services.exe", "svchost.exe", "conhost.exe"],
        "T1059.003"),
    ("powershell.exe",
        &["explorer.exe", "services.exe", "svchost.exe", "conhost.exe", "wsmprovhost.exe"],
        "T1059.001"),
    ("pwsh.exe",
        &["explorer.exe", "services.exe"],
        "T1059.001"),

    // Script engines
    ("mshta.exe",
        &[],
        "T1218.005"),
    ("wscript.exe",
        &["explorer.exe"],
        "T1059.005"),
    ("cscript.exe",
        &["explorer.exe", "svchost.exe"],
        "T1059.005"),

    // LOLBins
    ("rundll32.exe",
        &["explorer.exe", "svchost.exe"],
        "T1218.011"),
    ("regsvr32.exe",
        &["explorer.exe", "svchost.exe"],
        "T1218.010"),
    ("installutil.exe",
        &[],
        "T1218.004"),
    ("msbuild.exe",
        &[],
        "T1218.004"),
    ("certutil.exe",
        &["explorer.exe"],
        "T1140"),
    ("bitsadmin.exe",
        &["explorer.exe", "svchost.exe"],
        "T1197"),
    ("schtasks.exe",
        &["explorer.exe", "services.exe"],
        "T1053.005"),
    ("wmic.exe",
        &["explorer.exe"],
        "T1047"),

    // Scripting runtimes
    ("python.exe",
        &["explorer.exe"],
        "T1059.006"),
    ("perl.exe",
        &["explorer.exe"],
        "T1059.006"),
    ("ruby.exe",
        &["explorer.exe"],
        "T1059.006"),

    // WSL / cross-environment abuse
    ("bash.exe",
        &["explorer.exe"],
        "T1059.004"),
];


/// LOLBin patterns: (executable, flag_condition_regex)
const LOLBIN_PATTERNS: &[(&str, &str)] = &[
    // Certutil: encoding/decoding and URL cache ops (often used to decode malicious content)
    ("certutil.exe", "(?:-encode|-decode|-urlcache)"),

    // Bitsadmin: transfer or job creation/download (common for staged download)
    ("bitsadmin.exe", "(?:/transfer|/addfile|/download)"),

    // Forfiles: running commands via /c {cmd|powershell} is used in script pivoting
    ("forfiles.exe", "/c\\s*(?:cmd\\.exe|powershell.exe)"),

    // Mshta: any URL or script argument often signals exploitation of HTML/HTA abuse
    ("mshta.exe", "(?:https?://|\\.vbs|\\.js|\\.hta)"),

    // Regsvr32: scriptlet execution via /i:http or proxy loading
    ("regsvr32.exe", "(?:/s|/i:http)"),

    // WMIC: process calls or remote node targets
    ("wmic.exe", "(?:process\\scall|/node:)"),

    // PowerShell: encoded commands or download operations
    ("powershell.exe", "(?:-enc|-EncodedCommand|DownloadFile|System\\.Net\\.WebClient)"),

    // InstallUtil: /u or invoking installers from remote sources
    ("installutil.exe", "(?:/u|/LogToConsole=false)"),

    // Msbuild: generating/executing code via project builds
    ("msbuild.exe", "(?:/p:|/target:)"),
];


/// Recon command patterns (simple substrings)
const RECON_PATTERNS: &[&str] = &[
    // User and group enumeration
    "net user",
    "net group",
    "net localgroup",
    "net view",      // list network resources
    "net use",       // list network connections

    // Active Directory and domain queries
    "dsquery",       // AD object query
    "nltest",        // domain trust, DC info

    // System state & identity
    "whoami",
    "hostname",
    "systeminfo",
    "ipconfig",
    "tasklist",
    "wmic",          // WMI queries for processes/services :contentReference[oaicite:1]{index=1}

    // Network discovery
    "netstat",
    "route print",
    "arp -a",
    "nslookup",

    // Session / Terminal info
    "qwinsta",       // session enumeration
    "query user",    // local session query

    // Credential listing
    "cmdkey /list",  // enumerates stored credentials
    "dir /s",        // recursive directory listing (often used in file system recon) :contentReference[oaicite:2]{index=2}
];


pub struct CmdlineAnalysisModule;

impl PipelineModule for CmdlineAnalysisModule {
    fn id(&self) -> &str {
        "3_cmdline_analysis"
    }
    
    fn name(&self) -> &str {
        "Cmdline Analysis"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Build lookups
        let cmdline_by_pid: HashMap<u32, &str> = ctx.data.cmdlines
            .iter()
            .map(|c| (c.pid, c.args.as_str()))
            .collect();
        
        let proc_by_pid: HashMap<u32, (&str, u32)> = ctx.data.processes
            .iter()
            .map(|p| (p.pid, (p.name.as_str(), p.ppid)))
            .collect();
        
        // ── Sub-stage A: Structural Anomalies ──
        for proc in &ctx.data.processes {
            if ctx.is_allowlisted(proc.pid) {
                continue;
            }
            
            // Skip exited processes
            if proc.exit_time.is_some() {
                continue;
            }
            
            let cmdline = cmdline_by_pid.get(&proc.pid).copied();
            
            // A1: Missing command line
            if cmdline.is_none() || cmdline.map(|c| c.trim().is_empty()).unwrap_or(true) {
                let finding = Finding {
                    id: format!("CMDLINE_MISSING_{}", proc.pid),
                    rule_id: "MOD3A_MISSING".to_string(),
                    rule_name: "Missing Command Line".to_string(),
                    title: format!("Missing cmdline: {} (PID {})", proc.name, proc.pid),
                    description: format!(
                        "Process '{}' (PID {}) is running but has no command-line entry. \
                        PEB may have been wiped (anti-forensics) or process was created via injection.",
                        proc.name, proc.pid
                    ),
                    severity: Severity::Medium,
                    confidence: 0.75,
                    mitre_attack: Some("T1055".to_string()),
                    related_pids: vec![proc.pid],
                    ..Default::default()
                };
                ctx.add_finding(proc.pid, finding, WEIGHT_MISSING_CMDLINE, self.id());
                ctx.flag_cmdline_anomaly(proc.pid);
            }
            
            // A2: Name stomping
            if let Some(cmd) = cmdline {
                let cmd_exe = extract_executable_name(cmd);
                if !cmd_exe.is_empty() && cmd_exe.to_lowercase() != proc.name.to_lowercase() {
                    // Check if it's truly a mismatch (not just path difference)
                    if !cmd.to_lowercase().contains(&proc.name.to_lowercase().replace(".exe", "")) {
                        let finding = Finding {
                            id: format!("CMDLINE_MISMATCH_{}", proc.pid),
                            rule_id: "MOD3A_MISMATCH".to_string(),
                            rule_name: "Name Mismatch".to_string(),
                            title: format!("Name mismatch: image={}, cmdline={}", proc.name, cmd_exe),
                            description: format!(
                                "Process image name '{}' and command line executable '{}' do not match. \
                                This indicates process hollowing or name stomping.",
                                proc.name, cmd_exe
                            ),
                            severity: Severity::High,
                            confidence: 0.80,
                            mitre_attack: Some("T1055.012".to_string()),
                            related_pids: vec![proc.pid],
                            ..Default::default()
                        };
                        ctx.add_finding(proc.pid, finding, WEIGHT_NAME_MISMATCH, self.id());
                        ctx.flag_cmdline_anomaly(proc.pid);
                    }
                }
            }
        }
        
        // ── Sub-stage B: Parent-Child Anomalies ──
        for proc in &ctx.data.processes {
            if ctx.is_allowlisted(proc.pid) {
                continue;
            }
            
            let proc_name = proc.name.to_lowercase();
            let parent = proc_by_pid.get(&proc.ppid);
            
            for (child_pattern, allowed_parents, mitre) in ANOMALOUS_PAIRS {
                if proc_name == *child_pattern {
                    let parent_name = parent.map(|(n, _)| n.to_lowercase()).unwrap_or_default();
                    
                    if !allowed_parents.iter().any(|&p| parent_name == p) {
                        let finding = Finding {
                            id: format!("PARENT_CHILD_{}", proc.pid),
                            rule_id: "MOD3B_PARENT".to_string(),
                            rule_name: "Anomalous Parent-Child".to_string(),
                            title: format!("Anomalous spawn: {} → {}", parent_name, proc.name),
                            description: format!(
                                "Process '{}' (PID {}) was spawned by '{}' which is not in the \
                                expected parent list for this process type.",
                                proc.name, proc.pid, parent_name
                            ),
                            severity: Severity::Medium,
                            confidence: 0.75,
                            mitre_attack: Some(mitre.to_string()),
                            related_pids: vec![proc.pid, proc.ppid],
                            ..Default::default()
                        };
                        ctx.add_finding(proc.pid, finding, WEIGHT_ANOMALOUS_PARENT, self.id());
                    }
                    break;
                }
            }
            
            // Flag children of injected processes
            if ctx.injection_flagged_pids.contains(&proc.ppid) {
                let finding = Finding {
                    id: format!("CHILD_OF_INJECTED_{}", proc.pid),
                    rule_id: "MOD3B_INJECTED_CHILD".to_string(),
                    rule_name: "Child of Injected Process".to_string(),
                    title: format!("Child of injected process: {} (PID {})", proc.name, proc.pid),
                    description: format!(
                        "Process '{}' (PID {}) was spawned by a process flagged for injection \
                        indicators (PPID {}). This may indicate lateral movement from compromised parent.",
                        proc.name, proc.pid, proc.ppid
                    ),
                    severity: Severity::High,
                    confidence: 0.70,
                    mitre_attack: Some("T1055".to_string()),
                    related_pids: vec![proc.pid, proc.ppid],
                    ..Default::default()
                };
                ctx.add_finding(proc.pid, finding, WEIGHT_CHILD_OF_INJECTED, self.id());
            }
        }
        
        // ── Sub-stage C: Signature Patterns ──
        for cmdline in &ctx.data.cmdlines {
            if ctx.is_allowlisted(cmdline.pid) {
                continue;
            }
            
            let cmd = cmdline.args.to_lowercase();
            let proc_name = proc_by_pid.get(&cmdline.pid)
                .map(|(n, _)| n.to_lowercase())
                .unwrap_or_default();
            
            // C1: Encoded PowerShell
            if (proc_name.contains("powershell") || cmd.contains("powershell"))
                && (cmd.contains("-enc ") || cmd.contains("-encodedcommand ") || cmd.contains("-e "))
            {
                // Check for base64-like content
                if contains_base64_like(&cmdline.args) {
                    let finding = Finding {
                        id: format!("ENCODED_PS_{}", cmdline.pid),
                        rule_id: "MOD3C_ENCODED".to_string(),
                        rule_name: "Encoded PowerShell".to_string(),
                        title: format!("Encoded PowerShell: PID {}", cmdline.pid),
                        description: format!(
                            "PowerShell with encoded command detected. Command: {}...",
                            &cmdline.args[..cmdline.args.len().min(100)]
                        ),
                        severity: Severity::High,
                        confidence: 0.85,
                        mitre_attack: Some("T1059.001".to_string()),
                        related_pids: vec![cmdline.pid],
                        ..Default::default()
                    };
                    ctx.add_finding(cmdline.pid, finding, WEIGHT_ENCODED_PS, self.id());
                }
            }
            
            // C2: LOLBin abuse (using regex patterns)
            for (lolbin, pattern) in LOLBIN_PATTERNS {
                if proc_name == *lolbin {
                    let matches = if pattern.is_empty() {
                        !cmd.trim().is_empty() // Any argument
                    } else {
                        // Use regex for pattern matching
                        regex::Regex::new(pattern)
                            .map(|re| re.is_match(&cmd))
                            .unwrap_or_else(|_| {
                                // Fallback to simple contains if regex is invalid
                                pattern.split('|').any(|p| cmd.contains(p))
                            })
                    };
                    
                    if matches {
                        let finding = Finding {
                            id: format!("LOLBIN_{}", cmdline.pid),
                            rule_id: "MOD3C_LOLBIN".to_string(),
                            rule_name: "LOLBin Abuse".to_string(),
                            title: format!("LOLBin abuse: {} (PID {})", lolbin, cmdline.pid),
                            description: format!(
                                "Living-off-the-Land binary '{}' executed with suspicious arguments: {}",
                                lolbin, &cmdline.args[..cmdline.args.len().min(100)]
                            ),
                            severity: Severity::Medium,
                            confidence: 0.75,
                            mitre_attack: Some("T1218".to_string()),
                            related_pids: vec![cmdline.pid],
                            ..Default::default()
                        };
                        ctx.add_finding(cmdline.pid, finding, WEIGHT_LOLBIN, self.id());
                        break;
                    }
                }
            }
            
            // C3: Recon commands
            let is_recon = RECON_PATTERNS.iter().any(|&p| cmd.contains(p));
            if is_recon {
                // Only flag if parent is anomalous
                let parent_name = proc_by_pid.get(&cmdline.pid)
                    .and_then(|(_, ppid)| proc_by_pid.get(ppid))
                    .map(|(n, _)| n.to_lowercase())
                    .unwrap_or_default();
                
                let suspicious_parent = !["explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe"]
                    .iter()
                    .any(|&p| parent_name == p);
                
                if suspicious_parent && ctx.network_pids.contains(&cmdline.pid) {
                    let finding = Finding {
                        id: format!("RECON_{}", cmdline.pid),
                        rule_id: "MOD3C_RECON".to_string(),
                        rule_name: "Reconnaissance Command".to_string(),
                        title: format!("Recon command with network: PID {}", cmdline.pid),
                        description: format!(
                            "Reconnaissance command detected from process with network activity: {}",
                            &cmdline.args[..cmdline.args.len().min(80)]
                        ),
                        severity: Severity::Low,
                        confidence: 0.65,
                        mitre_attack: Some("T1082".to_string()),
                        related_pids: vec![cmdline.pid],
                        ..Default::default()
                    };
                    ctx.add_finding(cmdline.pid, finding, WEIGHT_RECON, self.id());
                }
            }
        }
        
        ctx
    }
}

/// Extract executable name from command line
fn extract_executable_name(cmdline: &str) -> String {
    let cmd = cmdline.trim();
    
    // Handle quoted paths
    let exe_part = if cmd.starts_with('"') {
        cmd[1..].split('"').next().unwrap_or("")
    } else {
        cmd.split_whitespace().next().unwrap_or("")
    };
    
    // Extract just the filename
    exe_part
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Check if string contains base64-like content
fn contains_base64_like(s: &str) -> bool {
    // Look for long base64-ish strings
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.iter().any(|p| {
        p.len() >= 20 
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && p.chars().filter(|c| c.is_ascii_uppercase()).count() > 5
    })
}
