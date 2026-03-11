//! Configuration and Detection Rules for Artifact Analysis

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

// =============================================================================
// SUSPICIOUS LOCATIONS
// =============================================================================

lazy_static! {
    // MFTECmd uses relative paths like .\\Windows\\Temp instead of C:\\Windows\\Temp
    pub static ref SUSPICIOUS_PATHS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        // Standard Windows paths
        set.insert(r"C:\Windows\Temp");
        set.insert(r"C:\Temp");
        set.insert(r"C:\ProgramData");
        set.insert(r"C:\Users\Public");
        set.insert(r"C:\Users\Default");
        set.insert(r"C:\$Recycle.Bin");
        // MFTECmd relative format
        set.insert(r".\Windows\Temp");
        set.insert(r".\Temp");
        set.insert(r".\ProgramData");
        set.insert(r".\Users\Public");
        set.insert(r".\Users\Default");
        set.insert(r".\$Recycle.Bin");
        set
    };
    
    pub static ref SUSPICIOUS_PATH_PATTERNS: Vec<Regex> = vec![
        // Standard paths
        Regex::new(r"(?i)C:\\Users\\[^\\]+\\AppData\\Local\\Temp").unwrap(),
        Regex::new(r"(?i)C:\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\[^\\]+\.exe$").unwrap(),
        Regex::new(r"(?i)C:\\Windows\\System32\\spool\\drivers").unwrap(),
        Regex::new(r"(?i)C:\\Windows\\Debug").unwrap(),
        Regex::new(r"(?i)C:\\Windows\\Tracing").unwrap(),
        Regex::new(r"(?i)C:\\PerfLogs").unwrap(),
        Regex::new(r"(?i)^[A-Z]:\\[^\\]+\.exe$").unwrap(),
        // MFTECmd relative format (starts with .)
        Regex::new(r"(?i)\.\\Users\\[^\\]+\\AppData\\Local\\Temp").unwrap(),
        Regex::new(r"(?i)\.\\Users\\[^\\]+\\AppData\\Roaming\\[^\\]+\\[^\\]+\.exe$").unwrap(),
        Regex::new(r"(?i)\.\\Windows\\System32\\spool\\drivers").unwrap(),
        Regex::new(r"(?i)\.\\Windows\\Debug").unwrap(),
        Regex::new(r"(?i)\.\\Windows\\Tracing").unwrap(),
        Regex::new(r"(?i)\.\\PerfLogs").unwrap(),
    ];
}

// =============================================================================
// CREDENTIAL DUMPING INDICATORS
// =============================================================================

lazy_static! {
    pub static ref CREDENTIAL_FILES: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("lsass.exe");
        set.insert("lsass.dmp");
        set.insert("sam");
        set.insert("security");
        set.insert("system");
        set.insert("ntds.dit");
        set.insert("ntds.jfm");
        set.insert("sekurlsa.log");
        set.insert("mimikatz.log");
        set.insert("procdump.exe");
        set.insert("procdump64.exe");
        set.insert("sqldumper.exe");
        set.insert("minidump");
        set.insert("comsvcs.dll");
        set
    };
    
    pub static ref CREDENTIAL_PATHS: Vec<Regex> = vec![
        Regex::new(r"(?i).*\\Windows\\System32\\config\\SAM").unwrap(),
        Regex::new(r"(?i).*\\Windows\\System32\\config\\SECURITY").unwrap(),
        Regex::new(r"(?i).*\\Windows\\System32\\config\\SYSTEM").unwrap(),
        Regex::new(r"(?i).*\\Windows\\NTDS\\ntds\.dit").unwrap(),
        Regex::new(r"(?i).*lsass.*\.dmp").unwrap(),
    ];
}

// =============================================================================
// LATERAL MOVEMENT INDICATORS
// =============================================================================

lazy_static! {
    pub static ref LATERAL_MOVEMENT_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)\\\\[^\\]+\\C\$").unwrap(),      // C$ share
        Regex::new(r"(?i)\\\\[^\\]+\\ADMIN\$").unwrap(),  // ADMIN$ share
        Regex::new(r"(?i)\\\\[^\\]+\\IPC\$").unwrap(),    // IPC$ share
        Regex::new(r"(?i)\\\\[^\\]+\\[A-Z]\$").unwrap(),  // Any drive share
    ];
}

// =============================================================================
// LIVING OFF THE LAND BINARIES (LOLBins)
// =============================================================================

lazy_static! {
    pub static ref LOLBINS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("cmd.exe");
        set.insert("powershell.exe");
        set.insert("pwsh.exe");
        set.insert("wmic.exe");
        set.insert("mshta.exe");
        set.insert("cscript.exe");
        set.insert("wscript.exe");
        set.insert("certutil.exe");
        set.insert("bitsadmin.exe");
        set.insert("msiexec.exe");
        set.insert("regsvr32.exe");
        set.insert("rundll32.exe");
        set.insert("installutil.exe");
        set.insert("msbuild.exe");
        set.insert("cmstp.exe");
        set.insert("regasm.exe");
        set.insert("regsvcs.exe");
        set.insert("msconfig.exe");
        set.insert("schtasks.exe");
        set.insert("at.exe");
        set.insert("sc.exe");
        set.insert("net.exe");
        set.insert("net1.exe");
        set.insert("netsh.exe");
        set.insert("psexec.exe");
        set.insert("psexesvc.exe");
        set.insert("wmiprvse.exe");
        set.insert("forfiles.exe");
        set.insert("pcalua.exe");
        set.insert("bash.exe");
        set.insert("wsl.exe");
        set
    };
}

// =============================================================================
// ANTI-FORENSICS INDICATORS
// =============================================================================

lazy_static! {
    pub static ref ANTI_FORENSICS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i).*\.evtx$").unwrap(),
        Regex::new(r"(?i).*\.pf$").unwrap(),
        Regex::new(r"(?i).*\\Prefetch\\.*").unwrap(),
        Regex::new(r"(?i).*sdelete.*").unwrap(),
        Regex::new(r"(?i).*cipher\.exe.*").unwrap(),
        Regex::new(r"(?i).*wevtutil.*").unwrap(),
        Regex::new(r"(?i).*fsutil.*usn.*").unwrap(),
    ];
    
    pub static ref SECURITY_TOOLS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("mbam.exe");
        set.insert("mbamservice.exe");
        set.insert("avgui.exe");
        set.insert("avgsvc.exe");
        set.insert("avastsvc.exe");
        set.insert("avastui.exe");
        set.insert("msmpeng.exe");
        set.insert("msseces.exe");
        set.insert("kavtray.exe");
        set.insert("ekrn.exe");
        set.insert("egui.exe");
        set.insert("savservice.exe");
        set.insert("ccsvchst.exe");
        set.insert("rtvscan.exe");
        set.insert("mcshield.exe");
        set.insert("bdagent.exe");
        set.insert("vsserv.exe");
        set.insert("sfc.exe");
        set.insert("mrt.exe");
        set
    };
}

// =============================================================================
// DATA STAGING INDICATORS
// =============================================================================

lazy_static! {
    pub static ref DATA_STAGING_EXTENSIONS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert(".zip");
        set.insert(".rar");
        set.insert(".7z");
        set.insert(".tar");
        set.insert(".gz");
        set.insert(".cab");
        set.insert(".iso");
        set
    };
}

pub const DATA_STAGING_SIZE_THRESHOLD: u64 = 50 * 1024 * 1024; // 50MB

// =============================================================================
// WINDOWS SYSTEM FILES (for masquerading detection)
// =============================================================================

lazy_static! {
    pub static ref WINDOWS_SYSTEM_NAMES: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("svchost.exe");
        set.insert("csrss.exe");
        set.insert("lsass.exe");
        set.insert("services.exe");
        set.insert("wininit.exe");
        set.insert("winlogon.exe");
        set.insert("explorer.exe");
        set.insert("taskmgr.exe");
        set.insert("cmd.exe");
        set.insert("powershell.exe");
        set.insert("notepad.exe");
        set
    };
}

// =============================================================================
// SEVERITY LEVELS
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

// =============================================================================
// MITRE ATT&CK MAPPINGS
// =============================================================================

pub fn get_mitre_technique(technique_name: &str) -> &'static str {
    match technique_name {
        "timestomping" => "T1070.006",
        "indicator_removal" => "T1070",
        "log_clearing" => "T1070.001",
        "file_deletion" => "T1070.004",
        "credential_dumping" => "T1003",
        "lsass_dump" => "T1003.001",
        "sam_dump" => "T1003.002",
        "ntds_dump" => "T1003.003",
        "lateral_movement_smb" => "T1021.002",
        "persistence_run_key" => "T1547.001",
        "persistence_service" => "T1543.003",
        "data_staged" => "T1074",
        "masquerading" => "T1036",
        "defense_evasion" => "T1562",
        _ => "Unknown",
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Check if a path is in a suspicious location
pub fn is_suspicious_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    
    // Check exact matches
    for suspicious in SUSPICIOUS_PATHS.iter() {
        if path_lower.starts_with(&suspicious.to_lowercase()) {
            return true;
        }
    }
    
    // Check patterns
    for pattern in SUSPICIOUS_PATH_PATTERNS.iter() {
        if pattern.is_match(path) {
            return true;
        }
    }
    
    false
}

/// Check if a file is credential-related
pub fn is_credential_file(file_name: &str, full_path: &str) -> bool {
    let file_lower = file_name.to_lowercase();
    
    // Check filename
    if CREDENTIAL_FILES.contains(file_lower.as_str()) {
        return true;
    }
    
    // Check path patterns
    for pattern in CREDENTIAL_PATHS.iter() {
        if pattern.is_match(full_path) {
            return true;
        }
    }
    
    false
}

/// Check if file is a LOLBin
pub fn is_lolbin(file_name: &str) -> bool {
    LOLBINS.contains(file_name.to_lowercase().as_str())
}

/// Check if file is a Windows system file (for masquerading detection)
pub fn is_windows_system_file(file_name: &str) -> bool {
    WINDOWS_SYSTEM_NAMES.contains(file_name.to_lowercase().as_str())
}
