//! Parsers for Volatility3 plugin outputs (JSONL and JSON formats)

pub mod json_parser;
pub mod jsonl_parser;
pub mod plugin_detection;

use std::path::Path;

pub use json_parser::JsonParser;
pub use jsonl_parser::JsonlParser;
pub use plugin_detection::{detect_plugin_type, PluginType};

use crate::error::Result;
use crate::models::{
    browser::{BrowserHistory, DownloadHistory},
    certificates::CertificateInfo,
    files::{DumpedFile, FileObject, HandleInfo},
    malware::{MalfindResult, VadInfo, VadYaraScanResult, YaraScanResult},
    mft::MftEntry,
    network::NetworkConnection,
    process::{CommandLine, DllInfo, EnvironmentVar, HollowProcessEntry, ProcessInfo, PsXViewEntry},
    registry::{RegistryHive, RegistryKey, UserAssist},
    security::{PrivilegeInfo, SidInfo},
    services::{CallbackInfo, DriverInfo, ServiceInfo, SsdtEntry},
    threads::ThreadInfo,
};

/// Unified container for all parsed plugin data
#[derive(Debug, Default)]
pub struct ParsedData {
    // Process plugins
    pub processes: Vec<ProcessInfo>,           // Merged (backward compat)
    pub pslist_processes: Vec<ProcessInfo>,    // From pslist only
    pub psscan_processes: Vec<ProcessInfo>,    // From psscan only
    pub psxview_entries: Vec<PsXViewEntry>,    // From psxview
    pub hollow_processes: Vec<HollowProcessEntry>, // From hollowprocesses
    pub cmdlines: Vec<CommandLine>,
    pub dlls: Vec<DllInfo>,
    pub envars: Vec<EnvironmentVar>,

    // Thread plugins
    pub threads: Vec<ThreadInfo>,

    // Network plugins
    pub connections: Vec<NetworkConnection>,

    // File plugins
    pub files: Vec<FileObject>,
    pub handles: Vec<HandleInfo>,
    pub dumped_files: Vec<DumpedFile>,
    pub mft_entries: Vec<MftEntry>,

    // Browser plugins (custom)
    pub browser_history: Vec<BrowserHistory>,
    pub downloads: Vec<DownloadHistory>,

    // Malware plugins
    pub malfind: Vec<MalfindResult>,
    pub vads: Vec<VadInfo>,
    pub yara_matches: Vec<YaraScanResult>,
    pub vad_yara_matches: Vec<VadYaraScanResult>,

    // Registry plugins
    pub hives: Vec<RegistryHive>,
    pub hivescan_hives: Vec<RegistryHive>,     // From hivescan only
    pub registry_keys: Vec<RegistryKey>,
    pub userassist: Vec<UserAssist>,

    // Services & Drivers
    pub services: Vec<ServiceInfo>,
    pub drivers: Vec<DriverInfo>,
    pub callbacks: Vec<CallbackInfo>,
    pub ssdt: Vec<SsdtEntry>,

    // Security plugins
    pub privileges: Vec<PrivilegeInfo>,
    pub sids: Vec<SidInfo>,
    pub certificates: Vec<CertificateInfo>,

    // Additional plugin outputs (raw JSON records)
    pub cmdscan_records: Vec<serde_json::Value>,
    pub console_records: Vec<serde_json::Value>,
    pub cachedump_records: Vec<serde_json::Value>,
    pub scheduled_task_records: Vec<serde_json::Value>,
    pub system_info_records: Vec<serde_json::Value>,

    // Plugins used in this analysis
    pub plugins_used: std::collections::HashSet<String>,

    // Parse errors (non-fatal)
    pub parse_errors: Vec<String>,
}

impl ParsedData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a plugin was used
    pub fn add_plugin(&mut self, plugin: &PluginType) {
        self.plugins_used.insert(plugin.to_string());
    }

    /// Get list of plugins used
    pub fn get_plugins_used(&self) -> Vec<&str> {
        let mut plugins: Vec<_> = self.plugins_used.iter().map(|s| s.as_str()).collect();
        plugins.sort();
        plugins
    }

    /// Get total number of parsed items across all categories
    pub fn total_items(&self) -> usize {
        self.processes.len()
            + self.cmdlines.len()
            + self.dlls.len()
            + self.envars.len()
            + self.psxview_entries.len()
            + self.hollow_processes.len()
            + self.threads.len()
            + self.connections.len()
            + self.files.len()
            + self.handles.len()
            + self.dumped_files.len()
            + self.mft_entries.len()
            + self.browser_history.len()
            + self.downloads.len()
            + self.malfind.len()
            + self.vads.len()
            + self.yara_matches.len()
            + self.vad_yara_matches.len()
            + self.hives.len()
            + self.registry_keys.len()
            + self.userassist.len()
            + self.services.len()
            + self.drivers.len()
            + self.callbacks.len()
            + self.ssdt.len()
            + self.privileges.len()
            + self.sids.len()
            + self.certificates.len()
            + self.cmdscan_records.len()
            + self.console_records.len()
            + self.cachedump_records.len()
            + self.scheduled_task_records.len()
            + self.system_info_records.len()
    }

    /// Get a summary of what was parsed
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.processes.is_empty() {
            parts.push(format!("{} processes", self.processes.len()));
        }
        if !self.cmdlines.is_empty() {
            parts.push(format!("{} cmdlines", self.cmdlines.len()));
        }
        if !self.connections.is_empty() {
            parts.push(format!("{} connections", self.connections.len()));
        }
        if !self.files.is_empty() {
            parts.push(format!("{} files", self.files.len()));
        }
        if !self.browser_history.is_empty() {
            parts.push(format!("{} browser entries", self.browser_history.len()));
        }
        if !self.downloads.is_empty() {
            parts.push(format!("{} downloads", self.downloads.len()));
        }
        if !self.malfind.is_empty() {
            parts.push(format!("{} malfind results", self.malfind.len()));
        }
        if !self.vad_yara_matches.is_empty() {
            parts.push(format!("{} vadyarascan matches", self.vad_yara_matches.len()));
        }
        if !self.hollow_processes.is_empty() {
            parts.push(format!("{} hollowprocesses hits", self.hollow_processes.len()));
        }
        if !self.psxview_entries.is_empty() {
            parts.push(format!("{} psxview entries", self.psxview_entries.len()));
        }
        if !self.registry_keys.is_empty() {
            parts.push(format!("{} registry keys", self.registry_keys.len()));
        }
        if !self.services.is_empty() {
            parts.push(format!("{} services", self.services.len()));
        }
        if !self.scheduled_task_records.is_empty() {
            parts.push(format!("{} scheduled tasks", self.scheduled_task_records.len()));
        }
        if !self.cmdscan_records.is_empty() {
            parts.push(format!("{} cmdscan records", self.cmdscan_records.len()));
        }
        parts.join(", ")
    }
}

/// Parse all files in a directory
pub fn parse_directory(dir: &Path) -> Result<ParsedData> {
    use walkdir::WalkDir;

    let mut data = ParsedData::new();

    for entry in WalkDir::new(dir)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext != "jsonl" && ext != "json" {
            continue;
        }

        match parse_file(path, &mut data) {
            Ok(_) => {}
            Err(e) => {
                data.parse_errors
                    .push(format!("{}: {}", path.display(), e));
            }
        }
    }

    if data.total_items() == 0 && data.parse_errors.is_empty() {
        return Err(crate::Vol3Error::NoInputFiles {
            path: dir.display().to_string(),
        });
    }

    Ok(data)
}

/// Parse a single file and add results to the data container
fn parse_file(path: &Path, data: &mut ParsedData) -> Result<()> {
    let plugin_type = detect_plugin_type(path)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Track this plugin (only if not Unknown)
    if plugin_type != PluginType::Unknown {
        data.add_plugin(&plugin_type);
    }

    match (plugin_type, ext) {
        // Process plugins - route to separate vectors by source (JSONL)
        (PluginType::PsList, "jsonl") => {
            use crate::models::process::ProcessSource;
            let mut procs: Vec<ProcessInfo> = JsonlParser::parse(path)?;
            for p in &mut procs {
                p.source = ProcessSource::PsList;
            }
            data.pslist_processes.extend(procs.clone());
            data.processes.extend(procs);
        }
        (PluginType::PsScan, "jsonl") => {
            use crate::models::process::ProcessSource;
            let mut procs: Vec<ProcessInfo> = JsonlParser::parse(path)?;
            for p in &mut procs {
                p.source = ProcessSource::PsScan;
            }
            data.psscan_processes.extend(procs.clone());
            data.processes.extend(procs);
        }
        (PluginType::PsTree, "jsonl") => {
            use crate::models::process::ProcessSource;
            let mut procs: Vec<ProcessInfo> = JsonlParser::parse(path)?;
            for p in &mut procs {
                p.source = ProcessSource::PsTree;
            }
            data.processes.extend(procs);
        }
        (PluginType::PsXView, "jsonl") => {
            data.psxview_entries.extend(JsonlParser::parse::<PsXViewEntry>(path)?);
        }
        (PluginType::HollowProcesses, "jsonl") => {
            data.hollow_processes
                .extend(JsonlParser::parse::<HollowProcessEntry>(path)?);
        }
        (PluginType::CmdLine, "jsonl") => {
            data.cmdlines.extend(JsonlParser::parse::<CommandLine>(path)?);
        }
        (PluginType::DllList, "jsonl") => {
            data.dlls.extend(JsonlParser::parse::<DllInfo>(path)?);
        }
        (PluginType::Envars, "jsonl") => {
            data.envars.extend(JsonlParser::parse::<EnvironmentVar>(path)?);
        }

        // Network plugins (JSONL)
        (PluginType::NetScan | PluginType::NetStat, "jsonl") => {
            data.connections.extend(JsonlParser::parse::<NetworkConnection>(path)?);
        }

        // File plugins (JSONL)
        (PluginType::FileScan, "jsonl") => {
            data.files.extend(JsonlParser::parse::<FileObject>(path)?);
        }
        (PluginType::Handles, "jsonl") => {
            data.handles.extend(JsonlParser::parse::<HandleInfo>(path)?);
        }
        (PluginType::DumpFiles, "jsonl") => {
            data.dumped_files.extend(JsonlParser::parse::<DumpedFile>(path)?);
        }

        // Browser plugins (JSONL)
        (PluginType::BrowserHistory, "jsonl") => {
            data.browser_history.extend(JsonlParser::parse::<BrowserHistory>(path)?);
        }
        (PluginType::DownloadHistory, "jsonl") => {
            data.downloads.extend(JsonlParser::parse::<DownloadHistory>(path)?);
        }

        // Malware plugins (JSONL)
        (PluginType::Malfind, "jsonl") => {
            data.malfind.extend(JsonlParser::parse::<MalfindResult>(path)?);
        }
        (PluginType::VadInfo, "jsonl") => {
            data.vads.extend(JsonlParser::parse::<VadInfo>(path)?);
        }
        (PluginType::YaraScan, "jsonl") => {
            data.yara_matches.extend(JsonlParser::parse::<YaraScanResult>(path)?);
        }
        (PluginType::VadYaraScan, "jsonl") => {
            let parsed = JsonlParser::parse::<VadYaraScanResult>(path)?;
            data.yara_matches
                .extend(parsed.iter().map(VadYaraScanResult::as_generic_yara));
            data.vad_yara_matches.extend(parsed);
        }

        // Registry plugins (JSONL)
        (PluginType::RegistryHiveList, "jsonl") => {
            data.hives.extend(JsonlParser::parse::<RegistryHive>(path)?);
        }
        (PluginType::RegistryPrintKey, "jsonl") => {
            data.registry_keys.extend(JsonlParser::parse::<RegistryKey>(path)?);
        }
        (PluginType::UserAssist, "jsonl") => {
            data.userassist.extend(JsonlParser::parse::<UserAssist>(path)?);
        }

        // Services & Drivers (JSONL)
        (PluginType::SvcScan, "jsonl") => {
            data.services.extend(JsonlParser::parse::<ServiceInfo>(path)?);
        }
        (PluginType::DriverScan | PluginType::Modules, "jsonl") => {
            data.drivers.extend(JsonlParser::parse::<DriverInfo>(path)?);
        }
        (PluginType::Callbacks, "jsonl") => {
            data.callbacks.extend(JsonlParser::parse::<CallbackInfo>(path)?);
        }
        (PluginType::Ssdt, "jsonl") => {
            data.ssdt.extend(JsonlParser::parse::<SsdtEntry>(path)?);
        }
        (PluginType::LdrModules, "jsonl") => {
            // LdrModules outputs DLL-like data
            data.dlls.extend(JsonlParser::parse::<DllInfo>(path)?);
        }

        // Thread plugins (JSONL)
        (PluginType::ThrDScan, "jsonl") => {
            data.threads.extend(JsonlParser::parse::<ThreadInfo>(path)?);
        }

        // MFT plugins (JSONL)
        (PluginType::MftScan, "jsonl") => {
            data.mft_entries.extend(JsonlParser::parse::<MftEntry>(path)?);
        }

        // Security plugins (JSONL)
        (PluginType::Privileges, "jsonl") => {
            data.privileges.extend(JsonlParser::parse::<PrivilegeInfo>(path)?);
        }
        (PluginType::GetSids, "jsonl") => {
            data.sids.extend(JsonlParser::parse::<SidInfo>(path)?);
        }
        (PluginType::Certificates, "jsonl") => {
            data.certificates.extend(JsonlParser::parse::<CertificateInfo>(path)?);
        }

        // HiveScan (JSONL)
        (PluginType::RegistryHiveScan, "jsonl") => {
            data.hivescan_hives.extend(JsonlParser::parse::<RegistryHive>(path)?);
        }

        // ModScan (JSONL)
        (PluginType::ModScan, "jsonl") => {
            data.drivers.extend(JsonlParser::parse::<DriverInfo>(path)?);
        }

        // Credential and console plugins (raw JSONL records)
        (PluginType::CmdScan, "jsonl") => {
            data.cmdscan_records.extend(JsonlParser::parse_raw(path)?);
        }
        (PluginType::Consoles, "jsonl") => {
            data.console_records.extend(JsonlParser::parse_raw(path)?);
        }
        (PluginType::CachedDump, "jsonl") => {
            data.cachedump_records.extend(JsonlParser::parse_raw(path)?);
        }

        // Scheduled tasks and system info (raw JSONL records)
        (PluginType::ScheduledTasks, "jsonl") => {
            data.scheduled_task_records.extend(JsonlParser::parse_raw(path)?);
        }
        (PluginType::Info, "jsonl") => {
            data.system_info_records.extend(JsonlParser::parse_raw(path)?);
        }

        // JSON parsing (TreeGrid format)
        (plugin_type, "json") => {
            parse_json_file(path, plugin_type, data)?;
        }

        _ => {}
    }

    Ok(())
}

fn parse_json_file(path: &Path, plugin_type: PluginType, data: &mut ParsedData) -> Result<()> {
    match plugin_type {
        PluginType::PsList | PluginType::PsTree | PluginType::PsScan => {
            data.processes.extend(JsonParser::parse::<ProcessInfo>(path)?);
        }
        PluginType::PsXView => {
            data.psxview_entries
                .extend(JsonParser::parse::<PsXViewEntry>(path)?);
        }
        PluginType::HollowProcesses => {
            data.hollow_processes
                .extend(JsonParser::parse::<HollowProcessEntry>(path)?);
        }
        PluginType::CmdLine => {
            data.cmdlines.extend(JsonParser::parse::<CommandLine>(path)?);
        }
        PluginType::DllList => {
            data.dlls.extend(JsonParser::parse::<DllInfo>(path)?);
        }
        PluginType::NetScan | PluginType::NetStat => {
            data.connections.extend(JsonParser::parse::<NetworkConnection>(path)?);
        }
        PluginType::FileScan => {
            data.files.extend(JsonParser::parse::<FileObject>(path)?);
        }
        PluginType::Handles => {
            data.handles.extend(JsonParser::parse::<HandleInfo>(path)?);
        }
        PluginType::BrowserHistory => {
            data.browser_history.extend(JsonParser::parse::<BrowserHistory>(path)?);
        }
        PluginType::DownloadHistory => {
            data.downloads.extend(JsonParser::parse::<DownloadHistory>(path)?);
        }
        PluginType::Malfind => {
            data.malfind.extend(JsonParser::parse::<MalfindResult>(path)?);
        }
        PluginType::VadInfo => {
            data.vads.extend(JsonParser::parse::<VadInfo>(path)?);
        }
        PluginType::YaraScan => {
            data.yara_matches.extend(JsonParser::parse::<YaraScanResult>(path)?);
        }
        PluginType::VadYaraScan => {
            let parsed = JsonParser::parse::<VadYaraScanResult>(path)?;
            data.yara_matches
                .extend(parsed.iter().map(VadYaraScanResult::as_generic_yara));
            data.vad_yara_matches.extend(parsed);
        }
        PluginType::SvcScan => {
            data.services.extend(JsonParser::parse::<ServiceInfo>(path)?);
        }
        _ => {}
    }
    Ok(())
}
