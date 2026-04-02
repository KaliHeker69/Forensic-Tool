//! Process-related data models for pslist, pstree, cmdline, dlllist

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use super::{ProcessAssociated, Timestamped};

/// Flexible deserializer that accepts strings, integers, booleans, and null → Option<String>
/// Volatility3 outputs fields like Threads, Handles, SessionId as integers,
/// Wow64 as booleans, but some plugins output them as strings.
pub fn deserialize_flexible_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let val: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match val {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => {
            if s.is_empty() || s == "N/A" || s == "-" {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        Some(serde_json::Value::Number(n)) => Ok(Some(n.to_string())),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(serde_json::Value::Null) => Ok(None),
        Some(other) => Ok(Some(other.to_string())),
    }
}

/// Non-optional variant: accepts strings, integers, booleans → String (never None)
/// Returns empty string for null values.
pub fn deserialize_flexible_string_required<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let val: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        other => Ok(other.to_string()),
    }
}

/// Flexible deserializer that accepts booleans, numbers, and common string forms.
/// Converts to Option<bool> so unknown values can be represented safely.
pub fn deserialize_flexible_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let val: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match val {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(i != 0))
            } else if let Some(u) = n.as_u64() {
                Ok(Some(u != 0))
            } else if let Some(f) = n.as_f64() {
                Ok(Some(f != 0.0))
            } else {
                Ok(None)
            }
        }
        Some(serde_json::Value::String(s)) => {
            let normalized = s.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "true" | "t" | "yes" | "y" | "1" => Ok(Some(true)),
                "false" | "f" | "no" | "n" | "0" => Ok(Some(false)),
                "" | "n/a" | "-" => Ok(None),
                _ => Ok(None),
            }
        }
        Some(_) => Ok(None),
    }
}

/// Flexible deserializer for addresses/integers represented as number or string.
pub fn deserialize_flexible_u64_required<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let val: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("invalid numeric value for u64")),
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "N/A" || trimmed == "-" {
                return Ok(0);
            }
            let hex_trimmed = trimmed.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(hex_trimmed, 16)
                .or_else(|_| trimmed.parse::<u64>())
                .map_err(serde::de::Error::custom)
        }
        serde_json::Value::Bool(b) => Ok(u64::from(b)),
        serde_json::Value::Null => Ok(0),
        other => Err(serde::de::Error::custom(format!(
            "unsupported value for u64: {}",
            other
        ))),
    }
}

/// Custom deserializer that treats "N/A", "-", and empty strings as None
pub fn deserialize_optional_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "N/A" || trimmed == "-" {
                return Ok(None);
            }
            
            // Try ISO 8601 format first (JSONL output): "2023-01-23T17:51:42+00:00"
            if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
                return Ok(Some(dt.with_timezone(&Utc)));
            }
            
            // Try ISO 8601 without timezone (assume UTC): "2023-01-23T17:51:42"
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
                return Ok(Some(dt.and_utc()));
            }
            
            // Volatility3 CSV format: "2023-01-23 17:51:42.000000 UTC"
            // Strip the " UTC" suffix and parse as NaiveDateTime
            let cleaned = trimmed.trim_end_matches(" UTC").trim_end_matches(" utc");
            
            // Try parsing with microseconds
            chrono::NaiveDateTime::parse_from_str(cleaned, "%Y-%m-%d %H:%M:%S%.f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(cleaned, "%Y-%m-%d %H:%M:%S"))
                .map(|dt| Some(dt.and_utc()))
                .map_err(serde::de::Error::custom)
        }
    }
}


/// Source plugin for process data (for pipeline integrity checks)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProcessSource {
    /// From pslist plugin (linked list traversal)
    PsList,
    /// From psscan plugin (pool scanning)
    PsScan,
    /// From pstree plugin
    PsTree,
    /// Unknown/merged source
    #[default]
    Unknown,
}

/// Process information from pslist/pstree plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Tree depth (for pstree output)
    #[serde(alias = "TreeDepth", alias = "tree_depth", default, deserialize_with = "deserialize_flexible_string")]
    pub tree_depth: Option<String>,

    /// Virtual offset of EPROCESS
    #[serde(alias = "Offset(V)", alias = "OFFSET(V)", alias = "offset", default, deserialize_with = "deserialize_flexible_string")]
    pub offset: Option<String>,

    /// Process name
    #[serde(alias = "Name", alias = "ImageFileName", alias = "name")]
    pub name: String,

    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Parent Process ID
    #[serde(alias = "PPID", alias = "PPid")]
    pub ppid: u32,

    /// Number of threads
    #[serde(alias = "Thds", alias = "Threads", alias = "threads", default, deserialize_with = "deserialize_flexible_string")]
    pub threads: Option<String>,

    /// Number of handles
    #[serde(alias = "Hnds", alias = "Handles", alias = "handles", default, deserialize_with = "deserialize_flexible_string")]
    pub handles: Option<String>,

    /// Session ID
    #[serde(alias = "Sess", alias = "SessionId", alias = "session", default, deserialize_with = "deserialize_flexible_string")]
    pub session: Option<String>,

    /// Is WoW64 (32-bit on 64-bit)
    /// Stored as String to handle case-insensitive True/False from CSV
    #[serde(alias = "Wow64", alias = "wow64", default, deserialize_with = "deserialize_flexible_string")]
    pub wow64: Option<String>,

    /// Process creation time
    #[serde(alias = "Start", alias = "CreateTime", alias = "create_time", default, deserialize_with = "deserialize_optional_datetime")]
    pub create_time: Option<DateTime<Utc>>,

    /// Process exit time
    #[serde(alias = "Exit", alias = "ExitTime", alias = "exit_time", default, deserialize_with = "deserialize_optional_datetime")]
    pub exit_time: Option<DateTime<Utc>>,

    /// File output field (Volatility3 output control)
    #[serde(alias = "File output", alias = "file_output", default)]
    pub file_output: Option<String>,

    /// Source plugin (for pipeline integrity checks)
    #[serde(skip)]
    pub source: ProcessSource,

    /// Whether this process is allowlisted (skip certain detections)
    #[serde(skip)]
    pub allowlisted: bool,
}

impl Timestamped for ProcessInfo {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.create_time
    }
}

impl ProcessAssociated for ProcessInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.name)
    }
}

/// psxview entry for cross-view process integrity checks.
/// Each boolean indicates whether a process is visible from a given enumeration method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsXViewEntry {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Name", alias = "Process", alias = "ImageFileName", default)]
    pub process: String,

    #[serde(alias = "pslist", alias = "PsList", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_pslist: Option<bool>,

    #[serde(alias = "psscan", alias = "PsScan", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_psscan: Option<bool>,

    #[serde(alias = "thrdproc", alias = "ThrdProc", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_thrdproc: Option<bool>,

    #[serde(alias = "pspcid", alias = "PspCid", alias = "PspCidTable", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_pspcid: Option<bool>,

    #[serde(alias = "csrss", alias = "Csrss", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_csrss: Option<bool>,

    #[serde(alias = "session", alias = "Session", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_session: Option<bool>,

    #[serde(alias = "deskthrd", alias = "DeskThrd", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_deskthrd: Option<bool>,
}

impl PsXViewEntry {
    /// Number of views that reported this process as missing.
    pub fn hidden_votes(&self) -> usize {
        [
            self.in_pslist,
            self.in_psscan,
            self.in_thrdproc,
            self.in_pspcid,
            self.in_csrss,
            self.in_session,
            self.in_deskthrd,
        ]
        .into_iter()
        .filter(|v| matches!(v, Some(false)))
        .count()
    }

    /// Strong DKOM signal:
    /// - not visible in pslist but visible in psscan, or
    /// - multiple independent views mark it missing.
    pub fn is_likely_hidden(&self) -> bool {
        if self.in_psscan == Some(true) && self.in_pslist == Some(false) {
            return true;
        }

        (self.in_pslist == Some(false) && self.hidden_votes() >= 2) || self.hidden_votes() >= 3
    }
}

/// Structured entry from windows.hollowprocesses output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowProcessEntry {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process", alias = "Name", alias = "ImageFileName", default)]
    pub process: String,

    /// Optional parent process ID
    #[serde(alias = "PPID", alias = "PPid", default)]
    pub ppid: Option<u32>,

    /// Suspicious region start/base
    #[serde(
        alias = "Start",
        alias = "Address",
        alias = "BaseAddress",
        alias = "Base",
        default,
        deserialize_with = "deserialize_flexible_string"
    )]
    pub start: Option<String>,

    /// Suspicious region end
    #[serde(alias = "End", alias = "EndAddress", default, deserialize_with = "deserialize_flexible_string")]
    pub end: Option<String>,

    /// Memory protection details
    #[serde(alias = "Protection", alias = "protect", default)]
    pub protection: Option<String>,

    /// Plugin-specific reason/details for the hollowing flag
    #[serde(alias = "Details", alias = "Reason", alias = "Description", default)]
    pub details: Option<String>,
}

/// Command line arguments from cmdline plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLine {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process", alias = "Name", alias = "ImageFileName")]
    pub process: String,

    /// Command line arguments
    #[serde(alias = "Args", alias = "Arguments", alias = "CmdLine")]
    pub args: String,
}

impl CommandLine {
    /// Check if command line contains encoded content (Base64, etc.)
    pub fn is_encoded(&self) -> bool {
        // Skip detection for known legitimate processes
        if self.is_whitelisted_process() {
            return false;
        }

        let lower = self.args.to_lowercase();
        lower.contains("-enc ")
            || lower.contains("-encodedcommand ")
            || lower.contains(" -e ")
            || lower.contains("frombase64string")
            || lower.contains("convert]::frombase64")
            || lower.contains("[text.encoding]::unicode.getstring")
            || lower.contains("::utf8.getstring")
            // Check for common Base64 patterns in command line (with context)
            || self.has_suspicious_base64_pattern()
    }

    /// Check if this is a whitelisted legitimate process
    pub fn is_whitelisted_process(&self) -> bool {
        let lower = self.args.to_lowercase();

        // Common Chromium-based browser executables (Windows & cross-platform names)
        if lower.contains("msedgewebview2.exe")
            || lower.contains("chrome.exe")
            || lower.contains("chromium.exe")
            || lower.contains("msedge.exe")
            || lower.contains("brave.exe")
            || lower.contains("vivaldi.exe")
            || lower.contains("opera.exe")
        {
            return true;
        }

        // Chromium/Electron child process types (multi-process architecture).
        //
        // These are typical switches used by Chromium to launch GPU, renderer,
        // utility, broker, zygote, and crashpad processes. :contentReference[oaicite:1]{index=1}
        if lower.contains("--type=gpu-process")
            || lower.contains("--type=renderer")
            || lower.contains("--type=utility")
            || lower.contains("--type=crashpad")
            || lower.contains("--type=zygote")
            || lower.contains("--type=broker")
            || lower.contains("--type=ppapi-broker")
        {
            return true;
        }

        false
    }

    /// Check for Base64-like patterns that are actually suspicious
    fn has_suspicious_base64_pattern(&self) -> bool {
        let lower = self.args.to_lowercase();
        

    // Exclude legitimate Chromium flags that contain Base64-like or dynamic data
    let excluded_patterns = [
        "--gpu-preferences=",
        "--field-trial-handle=",
        "--metrics-shmem-handle=",
        "--variations-seed-version",
        "--trace-process-track-uuid=",
        "--mojo-platform-channel-handle=",
        "/prefetch:",

        // Common dynamic/internal flags that include handles, IDs, or seeds:
        "--force-field-trials=",
        "--force-field-trial-params=",
        "--force-variation-ids=",
        "--reset-variation-state",
        "--accept-empty-variations-seed-signature",

        // Handles for workers/processes, often numeric and irrelevant for content matching:
        "--type=",
        "--utility-sub-type=",
        "--renderer-client-id=",
        "--service-sandbox-type=",
        "--mojo-embedder=",

        // IPC / metrics / tracing / shared resources:
        "--metrics-recording-only",
        "--enable-tracing",
        "--trace-config-file=",
        "--trace-startup-epoch=",
    ];

        
        // If command contains known Chromium flags, skip Base64 detection
        if excluded_patterns.iter().any(|p| lower.contains(p)) {
            return false;
        }

        // Look for Base64 patterns only in suspicious contexts
        // Must be preceded by PowerShell encoding flags
        let has_ps_context = lower.contains("powershell")
            || lower.contains("pwsh")
            || lower.contains("-enc")
            || lower.contains("-e ");

        if !has_ps_context {
            return false;
        }

        // Look for long Base64 strings
        if let Ok(re) = regex::Regex::new(r"[A-Za-z0-9+/]{50,}={0,2}") {
            return re.is_match(&self.args);
        }
        false
    }

    /// Check if command line has suspicious flags
    pub fn has_suspicious_flags(&self) -> bool {
        let lower = self.args.to_lowercase();
        lower.contains("-w hidden")
            || lower.contains("-windowstyle hidden")
            || lower.contains("-window hidden")
            || lower.contains("-wi h")
            || lower.contains("-nop")
            || lower.contains("-noprofile")
            || lower.contains("-nologo")
            || lower.contains("-noninteractive")
            || lower.contains("-noni")
            || lower.contains("-exec bypass")
            || lower.contains("-executionpolicy bypass")
            || lower.contains("-ep bypass")
            || lower.contains("-executionpolicy unrestricted")
            || lower.contains("-executionpolicy remotesigned")
            || lower.contains("downloadstring")
            || lower.contains("downloadfile")
            || lower.contains("downloaddata")
            || lower.contains("iex")
            || lower.contains("invoke-expression")
            || lower.contains("invoke-webrequest")
            || lower.contains("invoke-restmethod")
            || lower.contains("iwr")
            || lower.contains("irm")
            || lower.contains("curl")
            || lower.contains("wget")
            || lower.contains("bitstransfer")
            || lower.contains("start-bitstransfer")
    }

    /// Check for suspicious process combinations
    pub fn has_suspicious_process_chain(&self) -> bool {
        let lower = self.args.to_lowercase();

        // Command execution patterns
        let has_cmd_exec = lower.contains("cmd.exe /c")
            || lower.contains("cmd /c")
            || lower.contains("cmd.exe /k")
            || lower.contains("cmd /k");

        // Script execution patterns
        let has_script_exec = lower.contains("powershell")
            || lower.contains("pwsh")
            || lower.contains("wscript")
            || lower.contains("cscript")
            || lower.contains("mshta");

        has_cmd_exec && has_script_exec
    }

    /// Check for obfuscation techniques
    pub fn is_obfuscated(&self) -> bool {
        let lower = self.args.to_lowercase();

        // String concatenation obfuscation
        let has_concat = lower.matches('+').count() > 5
            || lower.matches("join").count() > 2
            || lower.contains("-join")
            || lower.contains("-f ") // Format operator
            || lower.contains("[char]");

        // Variable substitution obfuscation
        let has_var_substitution =
            lower.matches('$').count() > 5 || lower.matches('{').count() > 5;

        // Tick marks (PowerShell obfuscation)
        let has_tick_marks = self.args.matches('`').count() > 3;

        // Caret obfuscation (cmd.exe)
        let has_caret = self.args.matches('^').count() > 5;

        has_concat || has_var_substitution || has_tick_marks || has_caret
    }

    /// Check for network-related suspicious activity
    pub fn has_network_activity(&self) -> bool {
        let lower = self.args.to_lowercase();
        lower.contains("http://")
            || lower.contains("https://")
            || lower.contains("ftp://")
            || lower.contains("net.webclient")
            || lower.contains("webrequest")
            || lower.contains("restmethod")
            || lower.contains("sockets.tcpclient")
            || lower.contains("system.net")
    }

    /// Check for credential access patterns
    pub fn attempts_credential_access(&self) -> bool {
        let lower = self.args.to_lowercase();
        let proc_lower = self.process.to_lowercase();
        
        // Exclude legitimate lsass.exe itself - it naturally contains "lsass" in its path
        // Also exclude legitimate system processes that may reference lsass
        if proc_lower == "lsass.exe" 
            || proc_lower == "services.exe" 
            || proc_lower == "wininit.exe"
            || proc_lower == "csrss.exe"
            || proc_lower == "smss.exe" {
            return false;
        }
        
        // Check if it's just a simple path to a legitimate executable (not credential dumping)
        // Pattern: just a path like "C:\Windows\System32\lsass.exe" without additional args
        if self.is_simple_executable_path() {
            return false;
        }
        
        lower.contains("mimikatz")
            || lower.contains("sekurlsa")
            || lower.contains("lsadump")
            || lower.contains("get-credential")
            || lower.contains("convertto-securestring")
            || (lower.contains("credential") && !lower.contains("credentialguard"))
            || lower.contains("hashdump")
            // Only flag "lsass" if it appears with dump/inject/memory access keywords
            || (lower.contains("lsass") && self.has_memory_access_keywords())
            // Only flag procdump if targeting lsass
            || (lower.contains("procdump") && lower.contains("lsass"))
            // SAM hive access
            || (lower.contains("\\sam") && (lower.contains("reg") || lower.contains("copy") || lower.contains("save")))
    }
    
    /// Check if command line is just a simple executable path without suspicious arguments
    fn is_simple_executable_path(&self) -> bool {
        let trimmed = self.args.trim();
        
        // If it's just a quoted or unquoted path ending in .exe with no additional args
        let normalized = trimmed.trim_matches('"').trim();
        
        // Simple check: ends with .exe and contains only path characters
        if normalized.to_lowercase().ends_with(".exe") {
            // Check if there are no additional arguments (just the path)
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            return parts.len() <= 1 || (parts.len() == 1 && normalized.contains("\\"));
        }
        false
    }
    
    /// Check if command line contains keywords suggesting memory access/dumping
    fn has_memory_access_keywords(&self) -> bool {
        let lower = self.args.to_lowercase();
        lower.contains("dump")
            || lower.contains("-ma ")  // full memory dump
            || lower.contains("minidump")
            || lower.contains("memory")
            || lower.contains("inject")
            || lower.contains("handle")
            || lower.contains("comsvcs")
            || lower.contains("sqldumper")
            || lower.contains("createdump")
    }

    /// Check for persistence mechanisms
    pub fn attempts_persistence(&self) -> bool {
        let lower = self.args.to_lowercase();
        lower.contains("schtasks")
            || lower.contains("new-scheduledtask")
            || lower.contains("register-scheduledtask")
            || lower.contains("startup")
            || lower.contains("\\currentversion\\run\\")
            || lower.contains("\\currentversion\\runonce")
            || lower.contains("wmic")
            || lower.contains("new-service")
            || lower.contains("sc create")
            || lower.contains("reg add")
    }

    /// Check for defense evasion techniques
    pub fn attempts_defense_evasion(&self) -> bool {
        let lower = self.args.to_lowercase();
        lower.contains("stop-service")
            || lower.contains("remove-item")
            || lower.contains("clear-eventlog")
            || lower.contains("wevtutil")
            || lower.contains("set-mppreference")
            || lower.contains("add-mppreference")
            || lower.contains("exclusion")
            || lower.contains("disableantispyware")
            || lower.contains("amsi")
            || lower.contains("reflection.assembly")
    }

    /// Try to decode Base64 content from command line
    pub fn decode_base64(&self) -> Option<String> {
        // Look for -enc or -e followed by Base64
        let patterns = ["-enc ", "-encodedcommand ", "-e "];
        for pattern in patterns {
            if let Some(idx) = self.args.to_lowercase().find(pattern) {
                let start = idx + pattern.len();
                let b64_part: String = self.args[start..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();

                if let Ok(decoded) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &b64_part,
                ) {
                    // Try UTF-16LE first (PowerShell default), then UTF-8
                    if decoded.len() >= 2 {
                        let utf16: Vec<u16> = decoded
                            .chunks(2)
                            .filter_map(|c| {
                                if c.len() == 2 {
                                    Some(u16::from_le_bytes([c[0], c[1]]))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if let Ok(s) = String::from_utf16(&utf16) {
                            return Some(s);
                        }
                    }
                    if let Ok(s) = String::from_utf8(decoded) {
                        return Some(s);
                    }
                }
            }
        }
        None
    }
}

impl ProcessAssociated for CommandLine {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// DLL information from dlllist plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllInfo {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process", alias = "ImageFileName")]
    pub process: String,

    /// DLL base address
    #[serde(alias = "Base", alias = "base")]
    pub base: String,

    /// DLL size
    #[serde(alias = "Size", alias = "size")]
    pub size: Option<u64>,

    /// DLL name
    #[serde(alias = "Name", alias = "BaseDllName")]
    pub name: String,

    /// Full path to DLL
    #[serde(alias = "Path", alias = "FullDllName")]
    pub path: String,

    /// Load time
    #[serde(alias = "LoadTime")]
    pub load_time: Option<DateTime<Utc>>,
}

impl DllInfo {
    /// Check if DLL is loaded from a suspicious location
    /// DEPRECATED: Use BlacklistConfig in detection rules instead
    pub fn is_suspicious_path(&self) -> bool {
        false
    }
}

impl ProcessAssociated for DllInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// Module visibility details from windows.ldrmodules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdrModuleInfo {
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    #[serde(alias = "Process", alias = "Name", alias = "ImageFileName")]
    pub process: String,

    #[serde(alias = "Base", alias = "base", deserialize_with = "deserialize_flexible_u64_required")]
    pub base: u64,

    #[serde(alias = "InLoad", alias = "inload", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_load: Option<bool>,

    #[serde(alias = "InInit", alias = "ininit", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_init: Option<bool>,

    #[serde(alias = "InMem", alias = "inmem", default, deserialize_with = "deserialize_flexible_bool")]
    pub in_mem: Option<bool>,

    #[serde(alias = "MappedPath", alias = "Path", alias = "mapped_path", default)]
    pub mapped_path: Option<String>,
}

impl LdrModuleInfo {
    pub fn is_hidden_from_peb(&self) -> bool {
        self.in_load == Some(false) && self.in_init == Some(false) && self.in_mem == Some(false)
    }

    pub fn is_unlinked(&self) -> bool {
        (self.in_load == Some(true) || self.in_init == Some(true)) && self.in_mem == Some(false)
    }

    pub fn mapped_path_or_empty(&self) -> &str {
        self.mapped_path.as_deref().unwrap_or("")
    }

    pub fn has_suspicious_path(&self) -> bool {
        let path = self.mapped_path_or_empty().to_ascii_lowercase();
        if path.is_empty() {
            return true;
        }
        ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\", "\\users\\"]
            .iter()
            .any(|p| path.contains(p))
    }
}

impl ProcessAssociated for LdrModuleInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// Environment variables from envars plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVar {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process", alias = "Name")]
    pub process: String,

    /// Variable name
    #[serde(alias = "Variable")]
    pub variable: String,

    /// Variable value
    #[serde(alias = "Value", alias = "value")]
    pub value: String,
}

/// Process tree node for hierarchical representation with genealogy
#[derive(Debug, Clone, Serialize)]
pub struct ProcessTreeNode {
    pub process: ProcessInfo,
    pub cmdline: Option<String>,
    pub children: Vec<ProcessTreeNode>,
    pub depth: usize,
}

impl ProcessTreeNode {
    pub fn new(process: ProcessInfo, depth: usize) -> Self {
        Self {
            process,
            cmdline: None,
            children: Vec::new(),
            depth,
        }
    }
}

/// Extended process node with full genealogy information
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub parent_name: Option<String>,
    pub children_pids: Vec<u32>,
    pub session_id: Option<String>,
    pub create_time: Option<DateTime<Utc>>,
    pub cmdline: Option<String>,
    pub depth: usize,
    pub signature: Option<SignatureInfo>,
}

impl ProcessNode {
    pub fn from_process_info(proc: &ProcessInfo, parent_name: Option<String>) -> Self {
        Self {
            pid: proc.pid,
            name: proc.name.clone(),
            parent_pid: proc.ppid,
            parent_name,
            children_pids: Vec::new(),
            session_id: proc.session.clone(),
            create_time: proc.create_time,
            cmdline: None,
            depth: 0,
            signature: None,
        }
    }

    /// Check if this process has a legitimate parent according to Windows process rules
    pub fn has_legitimate_parent(&self) -> bool {
        let name_lower = self.name.to_lowercase();
        let parent_lower = self.parent_name.as_ref().map(|s| s.to_lowercase());

        match name_lower.as_str() {
            "lsass.exe" => parent_lower.as_deref() == Some("wininit.exe"),
            "services.exe" => parent_lower.as_deref() == Some("wininit.exe"),
            "svchost.exe" => parent_lower.as_deref() == Some("services.exe"),
            "smss.exe" => self.parent_pid == 4,
            // csrss.exe, winlogon.exe, wininit.exe are spawned by smss.exe during session creation
            // smss.exe typically exits after spawning these, so the parent may not be in process list
            // Accept if parent is smss.exe OR if parent is unknown (exited smss)
            "csrss.exe" | "winlogon.exe" | "wininit.exe" => {
                parent_lower.as_deref() == Some("smss.exe") 
                    || self.parent_is_likely_exited_smss()
            }
            "userinit.exe" => parent_lower.as_deref() == Some("winlogon.exe"),
            "explorer.exe" => {
                parent_lower.as_deref() == Some("userinit.exe")
                    || parent_lower.as_deref() == Some("explorer.exe")
            }
            "taskhostw.exe" => parent_lower.as_deref() == Some("svchost.exe"),
            // dwm.exe can be spawned by svchost.exe (older Windows) or winlogon.exe (Windows 10/11)
            "dwm.exe" => {
                parent_lower.as_deref() == Some("svchost.exe")
                    || parent_lower.as_deref() == Some("winlogon.exe")
            }
            "runtimebroker.exe" => parent_lower.as_deref() == Some("svchost.exe"),
            _ => true,
        }
    }
    
    /// Check if the parent PID is likely an exited smss.exe process
    /// smss.exe creates session managers then exits, leaving orphaned children
    /// These children have parent PIDs that no longer exist in the process list
    fn parent_is_likely_exited_smss(&self) -> bool {
        // If parent name is None, the parent process has exited
        // For session 0 processes (csrss, wininit) and session 1+ processes (csrss, winlogon),
        // this is expected behavior when smss.exe exits after session initialization
        self.parent_name.is_none() && self.parent_pid != 0 && self.parent_pid != 4
    }

    /// Get expected parent name for this process (for error reporting)
    pub fn expected_parent(&self) -> Option<&'static str> {
        match self.name.to_lowercase().as_str() {
            "lsass.exe" => Some("wininit.exe"),
            "services.exe" => Some("wininit.exe"),
            "svchost.exe" => Some("services.exe"),
            "smss.exe" => Some("System (PID 4)"),
            "csrss.exe" => Some("smss.exe"),
            "winlogon.exe" => Some("smss.exe"),
            "wininit.exe" => Some("smss.exe"),
            "userinit.exe" => Some("winlogon.exe"),
            "explorer.exe" => Some("userinit.exe"),
            "taskhostw.exe" => Some("svchost.exe"),
            // dwm.exe: svchost.exe (legacy) or winlogon.exe (Win10/11)
            "dwm.exe" => Some("svchost.exe or winlogon.exe"),
            "runtimebroker.exe" => Some("svchost.exe"),
            _ => None,
        }
    }

    /// Get expected file path for this process (for error reporting)
    pub fn expected_path(&self) -> &'static str {
        match self.name.to_lowercase().as_str() {
            "lsass.exe" | "services.exe" | "smss.exe" | "csrss.exe" 
            | "winlogon.exe" | "wininit.exe" => "C:\\Windows\\System32\\",
            "svchost.exe" => "C:\\Windows\\System32\\ or C:\\Windows\\SysWOW64\\",
            "explorer.exe" => "C:\\Windows\\",
            _ => "Unknown",
        }
    }

    /// Check if this is a critical Windows system process
    pub fn is_critical_system_process(&self) -> bool {
        let lower = self.name.to_lowercase();
        matches!(
            lower.as_str(),
            "lsass.exe"
                | "services.exe"
                | "svchost.exe"
                | "smss.exe"
                | "csrss.exe"
                | "winlogon.exe"
                | "wininit.exe"
                | "system"
        )
    }

    /// Check if the process is running from an expected system directory
    pub fn has_legitimate_path(&self) -> bool {
        if let Some(ref cmdline) = self.cmdline {
            let path_lower = cmdline.to_lowercase();
            let name_lower = self.name.to_lowercase();

            match name_lower.as_str() {
                "lsass.exe" | "services.exe" | "smss.exe" | "csrss.exe" 
                | "winlogon.exe" | "wininit.exe" => {
                    path_lower.contains("\\system32\\") || path_lower.contains("\\windows\\system32\\")
                }
                "svchost.exe" => {
                    path_lower.contains("\\system32\\") || path_lower.contains("\\syswow64\\")
                }
                "explorer.exe" => {
                    path_lower.contains("\\windows\\") && !path_lower.contains("\\temp\\")
                }
                _ => true,
            }
        } else {
            true
        }
    }

    /// Detect suspicious characteristics that might indicate process injection or hollowing
    pub fn has_suspicious_characteristics(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();

        if !self.has_legitimate_parent() {
            flags.push("illegitimate_parent");
        }

        if !self.has_legitimate_path() {
            flags.push("suspicious_path");
        }

        if self.is_critical_system_process() && self.session_id.as_deref() != Some("0") {
            flags.push("critical_process_non_session_zero");
        }

        if self.has_duplicate_critical_process() {
            flags.push("duplicate_critical_process");
        }

        if self.has_suspicious_name_pattern() {
            flags.push("suspicious_naming");
        }

        flags
    }

    /// Check for duplicate critical system processes (there should only be one instance)
    fn has_duplicate_critical_process(&self) -> bool {
        let lower = self.name.to_lowercase();
        matches!(
            lower.as_str(),
            "lsass.exe" | "services.exe" | "wininit.exe" | "smss.exe"
        )
    }

    /// Detect suspicious naming patterns (typosquatting, extra characters)
    fn has_suspicious_name_pattern(&self) -> bool {
        let lower = self.name.to_lowercase();
        
        let known_typos = [
            "lssass.exe", "lsas.exe", "isass.exe",
            "svchост.exe", "scvhost.exe",
            "csrsss.exe", "cssrs.exe",
            "expIorer.exe", "explorar.exe",
        ];

        known_typos.contains(&lower.as_str())
    }

    /// Check if process should only run in Session 0 (system session)
    pub fn should_be_session_zero(&self) -> bool {
        let lower = self.name.to_lowercase();
        matches!(
            lower.as_str(),
            "lsass.exe" | "services.exe" | "svchost.exe" | "smss.exe" 
            | "wininit.exe" | "csrss.exe"
        )
    }

    /// Calculate a risk score based on various indicators
    pub fn calculate_risk_score(&self) -> u8 {
        let mut score = 0u8;

        let suspicious_flags = self.has_suspicious_characteristics();
        score += (suspicious_flags.len() * 20) as u8;

        if self.is_critical_system_process() && !self.signature.as_ref().map_or(false, |s| s.signature_valid) {
            score += 30;
        }

        if self.parent_pid == 0 && !matches!(self.name.to_lowercase().as_str(), "system" | "idle") {
            score += 25;
        }

        if self.should_be_session_zero() && self.session_id.as_deref() != Some("0") {
            score += 35;
        }

        score.min(100)
    }

    /// Get a human-readable risk level
    pub fn risk_level(&self) -> &'static str {
        match self.calculate_risk_score() {
            0..=20 => "Low",
            21..=50 => "Medium",
            51..=75 => "High",
            _ => "Critical",
        }
    }

    /// Generate a detailed security assessment
    pub fn security_assessment(&self) -> SecurityAssessment {
        let flags = self.has_suspicious_characteristics();
        let risk_score = self.calculate_risk_score();
        
        SecurityAssessment {
            process_name: self.name.clone(),
            pid: self.pid,
            risk_score,
            risk_level: self.risk_level().to_string(),
            flags,
            recommendations: self.get_recommendations(),
        }
    }

    /// Get security recommendations based on findings
    fn get_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        let flags = self.has_suspicious_characteristics();

        if flags.contains(&"illegitimate_parent") {
            recommendations.push(format!(
                "Investigate parent process relationship. Expected parent: {}",
                self.expected_parent().unwrap_or("unknown")
            ));
        }

        if flags.contains(&"suspicious_path") {
            recommendations.push(
                "Verify process binary location and integrity".to_string()
            );
        }

        if flags.contains(&"critical_process_non_session_zero") {
            recommendations.push(
                "Critical system process running outside Session 0 - possible impersonation".to_string()
            );
        }

        if self.calculate_risk_score() > 50 {
            recommendations.push(
                "High risk detected - consider isolating system and performing forensic analysis".to_string()
            );
        }

        recommendations
    }
}

#[derive(Debug, Clone)]
pub struct SecurityAssessment {
    pub process_name: String,
    pub pid: u32,
    pub risk_score: u8,
    pub risk_level: String,
    pub flags: Vec<&'static str>,
    pub recommendations: Vec<String>,
}
/// Digital signature information for a process/file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Whether the file is digitally signed
    pub is_signed: bool,

    /// Signer name (e.g., "Microsoft Corporation")
    pub signer: Option<String>,

    /// Whether the signature is valid
    pub signature_valid: bool,

    /// Whether the certificate has expired
    pub certificate_expired: bool,

    /// Whether the certificate chain is valid
    pub certificate_chain_valid: bool,
}

impl SignatureInfo {
    /// Create an unsigned entry
    pub fn unsigned() -> Self {
        Self {
            is_signed: false,
            signer: None,
            signature_valid: false,
            certificate_expired: false,
            certificate_chain_valid: false,
        }
    }

    /// Create a valid Microsoft signature
    pub fn microsoft_signed() -> Self {
        Self {
            is_signed: true,
            signer: Some("Microsoft Corporation".to_string()),
            signature_valid: true,
            certificate_expired: false,
            certificate_chain_valid: true,
        }
    }

    /// Check if the signature is from Microsoft
    pub fn is_microsoft_signed(&self) -> bool {
        self.is_signed
            && self.signature_valid
            && self
                .signer
                .as_ref()
                .map(|s| s.to_lowercase().contains("microsoft"))
                .unwrap_or(false)
    }

    /// Check if signature is suspicious for a system process
    pub fn is_suspicious_for_system_process(&self) -> bool {
        !self.is_signed || !self.signature_valid || !self.is_microsoft_signed()
    }
}
