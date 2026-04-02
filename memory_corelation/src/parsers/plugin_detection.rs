//! Plugin type detection from filename and content

use std::path::Path;

use crate::error::{Result, Vol3Error};

/// Supported Volatility3 plugin types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginType {
    // Process plugins
    PsList,
    PsTree,
    PsScan,
    PsXView,
    HollowProcesses,
    CmdLine,
    DllList,
    LdrModules,
    Envars,
    Handles,

    // Thread plugins
    ThrDScan,

    // Network plugins
    NetScan,
    NetStat,

    // File plugins
    FileScan,
    DumpFiles,
    MftScan,

    // Registry plugins
    RegistryHiveList,
    RegistryHiveScan,
    RegistryPrintKey,
    UserAssist,

    // Malware detection plugins
    Malfind,
    VadInfo,
    VadWalk,
    YaraScan,
    VadYaraScan,

    // Services & Drivers
    SvcScan,
    DriverScan,
    Modules,
    ModScan,
    Callbacks,
    Ssdt,
    DriverIrp,
    Idt,
    Atoms,

    // Security plugins
    Privileges,
    GetSids,
    Certificates,

    // Credential plugins
    CmdScan,
    Consoles,
    CachedDump,

    // Scheduled tasks
    ScheduledTasks,

    // System info
    Info,

    // Browser plugins (custom)
    BrowserHistory,
    DownloadHistory,

    // Timeline
    Timeliner,

    // Unknown
    Unknown,
}

impl PluginType {
    /// Get the canonical name for this plugin type
    pub fn name(&self) -> &'static str {
        match self {
            PluginType::PsList => "pslist",
            PluginType::PsTree => "pstree",
            PluginType::PsScan => "psscan",
            PluginType::PsXView => "psxview",
            PluginType::HollowProcesses => "hollowprocesses",
            PluginType::CmdLine => "cmdline",
            PluginType::DllList => "dlllist",
            PluginType::LdrModules => "ldrmodules",
            PluginType::Envars => "envars",
            PluginType::Handles => "handles",
            PluginType::ThrDScan => "thrdscan",
            PluginType::NetScan => "netscan",
            PluginType::NetStat => "netstat",
            PluginType::FileScan => "filescan",
            PluginType::DumpFiles => "dumpfiles",
            PluginType::MftScan => "mftscan",
            PluginType::RegistryHiveList => "hivelist",
            PluginType::RegistryHiveScan => "hivescan",
            PluginType::RegistryPrintKey => "printkey",
            PluginType::UserAssist => "userassist",
            PluginType::Malfind => "malfind",
            PluginType::VadInfo => "vadinfo",
            PluginType::VadWalk => "vadwalk",
            PluginType::YaraScan => "yarascan",
            PluginType::VadYaraScan => "vadyarascan",
            PluginType::SvcScan => "svcscan",
            PluginType::DriverScan => "driverscan",
            PluginType::Modules => "modules",
            PluginType::ModScan => "modscan",
            PluginType::Callbacks => "callbacks",
            PluginType::Ssdt => "ssdt",
            PluginType::DriverIrp => "driverirp",
            PluginType::Idt => "idt",
            PluginType::Atoms => "atoms",
            PluginType::Privileges => "privileges",
            PluginType::GetSids => "getsids",
            PluginType::Certificates => "certificates",
            PluginType::CmdScan => "cmdscan",
            PluginType::Consoles => "consoles",
            PluginType::CachedDump => "cachedump",
            PluginType::ScheduledTasks => "scheduled_tasks",
            PluginType::Info => "info",
            PluginType::BrowserHistory => "browser_history",
            PluginType::DownloadHistory => "download_history",
            PluginType::Timeliner => "timeliner",
            PluginType::Unknown => "unknown",
        }
    }

    /// Get the category for this plugin type
    pub fn category(&self) -> &'static str {
        match self {
            PluginType::PsList
            | PluginType::PsTree
            | PluginType::PsScan
            | PluginType::PsXView
            | PluginType::HollowProcesses
            | PluginType::CmdLine
            | PluginType::DllList
            | PluginType::LdrModules
            | PluginType::Envars
            | PluginType::Handles => "process",

            PluginType::ThrDScan => "thread",

            PluginType::NetScan | PluginType::NetStat => "network",

            PluginType::FileScan | PluginType::DumpFiles | PluginType::MftScan => "file",

            PluginType::RegistryHiveList
            | PluginType::RegistryHiveScan
            | PluginType::RegistryPrintKey
            | PluginType::UserAssist => "registry",

            PluginType::Malfind
            | PluginType::VadInfo
            | PluginType::VadWalk
            | PluginType::YaraScan
            | PluginType::VadYaraScan => "malware",

            PluginType::SvcScan
            | PluginType::DriverScan
            | PluginType::Modules
            | PluginType::ModScan
            | PluginType::Callbacks
            | PluginType::Ssdt
            | PluginType::DriverIrp
            | PluginType::Idt => "services",

            PluginType::Atoms => "security",

            PluginType::Privileges | PluginType::GetSids | PluginType::Certificates => "security",

            PluginType::CmdScan | PluginType::Consoles | PluginType::CachedDump => "credentials",

            PluginType::ScheduledTasks => "persistence",

            PluginType::Info => "system",

            PluginType::BrowserHistory | PluginType::DownloadHistory => "browser",

            PluginType::Timeliner => "timeline",

            PluginType::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for PluginType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Detect plugin type from file path
pub fn detect_plugin_type(path: &Path) -> Result<PluginType> {
    let filename = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Vol3Error::UnknownPlugin {
            path: path.display().to_string(),
        })?
        .to_lowercase();

    // Match against known plugin name patterns
    let plugin_type = match filename.as_str() {
        // Process plugins
        s if s.contains("pslist") => PluginType::PsList,
        s if s.contains("pstree") => PluginType::PsTree,
        s if s.contains("psscan") => PluginType::PsScan,
        s if s.contains("psxview") => PluginType::PsXView,
        s if s.contains("hollowprocess") || s.contains("hollow_process") => {
            PluginType::HollowProcesses
        }
        s if s.contains("cmdline") && !s.contains("cmdscan") => PluginType::CmdLine,
        s if s.contains("dlllist") => PluginType::DllList,
        s if s.contains("ldrmodule") => PluginType::LdrModules,
        s if s.contains("envar") => PluginType::Envars,
        s if s.contains("handle") => PluginType::Handles,

        // Thread plugins
        s if s.contains("thrdscan") || s.contains("threads") => PluginType::ThrDScan,

        // Network plugins
        s if s.contains("netscan") => PluginType::NetScan,
        s if s.contains("netstat") => PluginType::NetStat,

        // File plugins
        s if s.contains("filescan") => PluginType::FileScan,
        s if s.contains("dumpfile") => PluginType::DumpFiles,
        // mftscan sub-plugins: MFTScan, ADS (Alternate Data Streams), ResidentData
        s if s.contains("mftscan") || s.contains("mft") || s == "ads" || s.contains("residentdata") => PluginType::MftScan,

        // Registry plugins
        s if s.contains("hivelist") || s.contains("hive_list") => PluginType::RegistryHiveList,
        s if s.contains("hivescan") || s.contains("hive_scan") => PluginType::RegistryHiveScan,
        s if s.contains("printkey") || s.contains("print_key") => PluginType::RegistryPrintKey,
        s if s.contains("userassist") || s.contains("user_assist") => PluginType::UserAssist,

        // Malware plugins
        s if s.contains("malfind") => PluginType::Malfind,
        s if s.contains("vadinfo") || s.contains("vad_info") => PluginType::VadInfo,
        s if s.contains("vadwalk") => PluginType::VadWalk,
        s if s.contains("vadyarascan") || (s.contains("vad") && s.contains("yara")) => {
            PluginType::VadYaraScan
        }
        s if s.contains("yarascan") || s.contains("yara") => PluginType::YaraScan,

        // Services & Drivers
        s if s.contains("svcscan") || s.contains("services") => PluginType::SvcScan,
        s if s.contains("driverirp") || s.contains("driver_irp") => PluginType::DriverIrp,
        s if s == "idt" || s.contains(".idt") || s.contains("_idt") => PluginType::Idt,
        s if s == "atoms" || s.contains("atom") => PluginType::Atoms,
        s if s.contains("driverscan") || s.contains("driver") => PluginType::DriverScan,
        s if s.contains("modscan") => PluginType::ModScan,
        s if s.contains("modules") && !s.contains("ldr") => PluginType::Modules,
        s if s.contains("callback") => PluginType::Callbacks,
        s if s.contains("ssdt") => PluginType::Ssdt,

        // Security plugins
        s if s.contains("privileges") || s.contains("privs") => PluginType::Privileges,
        s if s.contains("getsids") || s.contains("sids") => PluginType::GetSids,
        s if s.contains("certificates") || s.contains("certs") => PluginType::Certificates,

        // Credential plugins
        s if s.contains("cmdscan") => PluginType::CmdScan,
        s if s.contains("consoles") => PluginType::Consoles,
        s if s.contains("cachedump") || s.contains("lsadump") || s.contains("hashdump") => {
            PluginType::CachedDump
        }

        // Scheduled tasks
        s if s.contains("scheduled") || s.contains("tasks") => PluginType::ScheduledTasks,

        // System info
        s if s == "info" => PluginType::Info,

        // Browser plugins (custom)
        s if s.contains("browser") && s.contains("hist") => PluginType::BrowserHistory,
        s if s.contains("chrome") && s.contains("hist") => PluginType::BrowserHistory,
        s if s.contains("firefox") && s.contains("hist") => PluginType::BrowserHistory,
        s if s.contains("download") => PluginType::DownloadHistory,

        // Timeline
        s if s.contains("timeline") => PluginType::Timeliner,

        _ => PluginType::Unknown,
    };

    Ok(plugin_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pslist() {
        let path = Path::new("/data/volatility/pslist.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::PsList);
    }

    #[test]
    fn test_detect_with_prefix() {
        let path = Path::new("/data/case001_netscan_output.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::NetScan);
    }

    #[test]
    fn test_detect_browser_history() {
        let path = Path::new("/data/chrome_browser_history.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::BrowserHistory);
    }
    
    #[test]
    fn test_detect_json_format() {
        let path = Path::new("/data/volatility/pslist.json");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::PsList);
    }

    #[test]
    fn test_detect_psxview() {
        let path = Path::new("/data/volatility/windows.psxview.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::PsXView);
    }

    #[test]
    fn test_detect_driverirp() {
        let path = Path::new("/data/volatility/driverirp.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::DriverIrp);
    }

    #[test]
    fn test_detect_idt() {
        let path = Path::new("/data/volatility/idt.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::Idt);
    }

    #[test]
    fn test_detect_atoms() {
        let path = Path::new("/data/volatility/atoms.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::Atoms);
    }

    #[test]
    fn test_detect_hollowprocesses() {
        let path = Path::new("/data/volatility/hollowprocesses_output.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::HollowProcesses);
    }

    #[test]
    fn test_detect_vadyarascan() {
        let path = Path::new("/data/volatility/windows.vadyarascan.jsonl");
        assert_eq!(detect_plugin_type(path).unwrap(), PluginType::VadYaraScan);
    }
}
