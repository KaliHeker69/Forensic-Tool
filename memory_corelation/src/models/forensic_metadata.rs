//! Forensic metadata models for Chain of Custody, System Profile, and Analysis Info

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Chain of Custody information for forensic integrity
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainOfCustody {
    /// Date/time of memory capture
    pub acquisition_time: Option<DateTime<Utc>>,
    /// Acquisition method (live capture, hibernation file, crash dump)
    pub acquisition_method: Option<String>,
    /// Operator/examiner name
    pub acquired_by: Option<String>,
    /// Tool used for acquisition
    pub acquisition_tool: Option<String>,
    /// MD5 hash of source memory image
    pub md5_hash: Option<String>,
    /// SHA-1 hash of source memory image
    pub sha1_hash: Option<String>,
    /// SHA-256 hash of source memory image
    pub sha256_hash: Option<String>,
    /// Hash verification timestamp
    pub hash_verified_at: Option<DateTime<Utc>>,
    /// Memory image file path
    pub image_path: Option<String>,
    /// Memory image file size in bytes
    pub image_size: Option<u64>,
}

impl ChainOfCustody {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any acquisition details are available
    pub fn has_acquisition_info(&self) -> bool {
        self.acquisition_time.is_some()
            || self.acquisition_method.is_some()
            || self.acquired_by.is_some()
            || self.acquisition_tool.is_some()
    }

    /// Check if any hash information is available
    pub fn has_hash_info(&self) -> bool {
        self.md5_hash.is_some() || self.sha1_hash.is_some() || self.sha256_hash.is_some()
    }
}

/// System profile information from windows.info plugin
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemProfile {
    /// Operating system name
    pub os_name: Option<String>,
    /// OS version (e.g., "10.0.19041")
    pub os_version: Option<String>,
    /// OS build number
    pub os_build: Option<String>,
    /// System architecture (x86/x64)
    pub architecture: Option<String>,
    /// Total physical RAM in bytes
    pub total_ram: Option<u64>,
    /// Number of processors
    pub processor_count: Option<u32>,
    /// System root path
    pub system_root: Option<String>,
    /// Computer name
    pub computer_name: Option<String>,
    /// Domain/workgroup
    pub domain: Option<String>,
    /// Active users at capture time
    pub active_users: Vec<String>,
    /// System uptime (if available)
    pub uptime: Option<String>,
    /// Security software detected
    pub security_software: Vec<String>,
}

impl SystemProfile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Format RAM as human-readable string
    pub fn formatted_ram(&self) -> String {
        match self.total_ram {
            Some(bytes) => {
                let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                format!("{:.1} GB", gb)
            }
            None => "Unknown".to_string(),
        }
    }
}

/// Volatility 3 analysis information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VolatilityInfo {
    /// Volatility version used
    pub version: String,
    /// ISF (Intermediate Symbol Format) symbol file path
    pub isf_file: Option<String>,
    /// Kernel base address
    pub kernel_base: Option<String>,
    /// DTB (Directory Table Base / CR3)
    pub dtb: Option<String>,
    /// NT Build number
    pub nt_build: Option<String>,
    /// Number of layers
    pub layers: Option<u32>,
    /// Primary layer name
    pub primary_layer: Option<String>,
}

impl VolatilityInfo {
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        }
    }
}

/// User activity evidence from memory
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserActivityEvidence {
    /// Clipboard contents (if available)
    pub clipboard_contents: Vec<ClipboardEntry>,
    /// Console/command history
    pub console_history: Vec<ConsoleHistoryEntry>,
    /// Notable environment variables by process
    pub environment_summary: Vec<EnvironmentSummary>,
    /// Interesting handles (files, mutexes, registry keys)
    pub interesting_handles: Vec<HandleSummary>,
    /// Session information
    pub sessions: Vec<SessionInfo>,
}

/// Clipboard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub session_id: Option<u32>,
    pub format: String,
    pub content: String,
    pub handle: Option<String>,
}

/// Console history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleHistoryEntry {
    pub pid: u32,
    pub process_name: String,
    pub command: String,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Environment variable summary for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSummary {
    pub pid: u32,
    pub process_name: String,
    pub username: Option<String>,
    pub computer_name: Option<String>,
    pub temp_path: Option<String>,
    pub user_profile: Option<String>,
    pub notable_vars: Vec<(String, String)>,
}

/// Handle summary for interesting handles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleSummary {
    pub pid: u32,
    pub process_name: String,
    pub handle_type: String,
    pub name: String,
    pub is_suspicious: bool,
    pub reason: Option<String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: u32,
    pub username: Option<String>,
    pub logon_type: Option<String>,
    pub logon_time: Option<DateTime<Utc>>,
    pub authentication_package: Option<String>,
}

/// Analysis methodology documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMethodology {
    /// Tools used
    pub tools: Vec<ToolInfo>,
    /// Volatility 3 plugins executed
    pub plugins_executed: Vec<String>,
    /// Analysis limitations
    pub limitations: Vec<String>,
    /// Analysis start time
    pub analysis_start: DateTime<Utc>,
    /// Analysis end time
    pub analysis_end: Option<DateTime<Utc>>,
}

impl Default for AnalysisMethodology {
    fn default() -> Self {
        Self {
            tools: vec![ToolInfo {
                name: "Volatility 3".to_string(),
                version: "3.x".to_string(),
                purpose: "Memory forensics framework".to_string(),
            }],
            plugins_executed: Vec::new(),
            limitations: Vec::new(),
            analysis_start: Utc::now(),
            analysis_end: None,
        }
    }
}

/// Tool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub purpose: String,
}

// ── Analyst Quick-View ──────────────────────────────────────────────────

/// Pre-extracted forensic highlights for the analyst quick-view panel.
/// Each field contains ready-to-render rows so the HTML generator
/// doesn't need access to `ParsedData`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalystQuickView {
    /// Commands executed from cmdline, cmdscan, and consoles plugins
    pub executed_commands: Vec<QuickCommand>,
    /// External / notable network connections
    pub network_connections: Vec<QuickNetConn>,
    /// Registry keys of interest (persistence, Run/RunOnce, etc.)
    pub registry_keys: Vec<QuickRegKey>,
    /// Interesting files (executables in temp, downloads, staging paths)
    pub interesting_files: Vec<QuickFile>,
    /// Running services with binary paths
    pub services: Vec<QuickService>,
    /// UserAssist execution history
    pub programs_run: Vec<QuickUserAssist>,
    /// Loaded DLLs that look suspicious
    pub suspicious_dlls: Vec<QuickDll>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickCommand {
    pub pid: u32,
    pub process: String,
    pub ppid: u32,
    pub parent_process: String,
    pub command: String,
    /// "cmdline" | "cmdscan" | "consoles"
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickNetConn {
    pub pid: u32,
    pub process: String,
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickRegKey {
    pub key: String,
    pub name: String,
    pub data: String,
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickFile {
    pub path: String,
    /// Why it's interesting (e.g. "executable in Temp", "staging path")
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickService {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub binary: String,
    pub start_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickUserAssist {
    pub path: String,
    pub count: u32,
    pub last_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickDll {
    pub pid: u32,
    pub process: String,
    pub dll_path: String,
    pub reason: String,
}
