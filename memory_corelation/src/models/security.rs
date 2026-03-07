//! Security-related data models for privileges and getsids plugins

use serde::{Deserialize, Serialize};

use super::process::deserialize_flexible_string_required;
use super::ProcessAssociated;

/// Process privilege information from privileges plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeInfo {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process", alias = "Name")]
    pub process: String,

    /// Privilege name (e.g., SeDebugPrivilege)
    #[serde(alias = "Privilege", alias = "privilege")]
    pub privilege: String,

    /// Privilege attributes (Present, Enabled, Default)
    #[serde(alias = "Attributes", alias = "attributes")]
    pub attributes: String,

    /// Human-readable description
    #[serde(alias = "Description", alias = "description")]
    pub description: Option<String>,

    /// Privilege value
    #[serde(alias = "Value", alias = "value")]
    pub value: Option<u32>,
}

impl PrivilegeInfo {
    /// Check if privilege is enabled
    pub fn is_enabled(&self) -> bool {
        self.attributes.to_lowercase().contains("enabled")
    }

    /// Check if privilege is present
    pub fn is_present(&self) -> bool {
        self.attributes.to_lowercase().contains("present")
    }

    /// Check if this is a dangerous privilege
    pub fn is_dangerous(&self) -> bool {
        let dangerous_privs = [
            "sedebugprivilege",
            "setcbprivilege",
            "seloaddriverprivilege",
            "sebackupprivilege",
            "serestoreprivilege",
            "setakeownershipprivilege",
            "seassignprimarytokenprivilege",
            "secreatetokenprivilege",
            "seimpersonateprivilege",
            "sesecurityprivilege",
        ];
        
        let lower = self.privilege.to_lowercase();
        dangerous_privs.iter().any(|p| lower.contains(p))
    }

    /// Check if this is SeDebugPrivilege specifically
    pub fn is_debug_privilege(&self) -> bool {
        self.privilege.to_lowercase().contains("sedebugprivilege")
    }

    /// Check if this is SeTcbPrivilege (act as OS)
    pub fn is_tcb_privilege(&self) -> bool {
        self.privilege.to_lowercase().contains("setcbprivilege")
    }

    /// Check if this is SeLoadDriverPrivilege
    pub fn is_load_driver_privilege(&self) -> bool {
        self.privilege.to_lowercase().contains("seloaddriverprivilege")
    }

    /// Check if this is SeImpersonatePrivilege
    pub fn is_impersonate_privilege(&self) -> bool {
        self.privilege.to_lowercase().contains("seimpersonateprivilege")
    }
}

impl ProcessAssociated for PrivilegeInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// Security Identifier information from getsids plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidInfo {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process")]
    pub process: String,

    /// Security Identifier string
    #[serde(alias = "SID", alias = "Sid")]
    pub sid: String,

    /// Human-readable name for the SID
    #[serde(alias = "Name", alias = "name", default, deserialize_with = "deserialize_flexible_string_required")]
    pub name: String,
}

impl SidInfo {
    /// Well-known SID constants
    pub const SYSTEM_SID: &'static str = "S-1-5-18";
    pub const LOCAL_SERVICE_SID: &'static str = "S-1-5-19";
    pub const NETWORK_SERVICE_SID: &'static str = "S-1-5-20";
    pub const ADMINISTRATORS_SID: &'static str = "S-1-5-32-544";
    pub const USERS_SID: &'static str = "S-1-5-32-545";
    
    // Integrity levels
    pub const SYSTEM_INTEGRITY: &'static str = "S-1-16-16384";
    pub const HIGH_INTEGRITY: &'static str = "S-1-16-12288";
    pub const MEDIUM_INTEGRITY: &'static str = "S-1-16-8192";
    pub const LOW_INTEGRITY: &'static str = "S-1-16-4096";

    /// Check if this is the SYSTEM SID
    pub fn is_system(&self) -> bool {
        self.sid == Self::SYSTEM_SID
    }

    /// Check if this is an Administrator SID
    pub fn is_administrator(&self) -> bool {
        self.sid == Self::ADMINISTRATORS_SID
    }

    /// Check if this is a service account SID
    pub fn is_service_account(&self) -> bool {
        self.sid == Self::LOCAL_SERVICE_SID || self.sid == Self::NETWORK_SERVICE_SID
    }

    /// Check if this is an integrity level SID
    pub fn is_integrity_level(&self) -> bool {
        self.sid.starts_with("S-1-16-")
    }

    /// Get integrity level if this is an integrity SID
    pub fn integrity_level(&self) -> Option<&'static str> {
        match self.sid.as_str() {
            Self::SYSTEM_INTEGRITY => Some("System"),
            Self::HIGH_INTEGRITY => Some("High"),
            Self::MEDIUM_INTEGRITY => Some("Medium"),
            Self::LOW_INTEGRITY => Some("Low"),
            _ if self.sid.starts_with("S-1-16-") => Some("Unknown"),
            _ => None,
        }
    }

    /// Check if this is a domain user SID (S-1-5-21-...)
    pub fn is_domain_user(&self) -> bool {
        self.sid.starts_with("S-1-5-21-")
    }

    /// Check if the SID name indicates an unusual condition
    pub fn has_suspicious_name(&self) -> bool {
        let lower = self.name.to_lowercase();
        lower.contains("unknown") || lower.is_empty()
    }
}

impl ProcessAssociated for SidInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// Summary of privilege analysis for a process
#[derive(Debug, Clone, Serialize)]
pub struct PrivilegeSummary {
    pub pid: u32,
    pub process_name: String,
    pub total_privileges: usize,
    pub dangerous_enabled: Vec<String>,
    pub has_debug: bool,
    pub has_tcb: bool,
    pub has_load_driver: bool,
    pub has_impersonate: bool,
    pub running_as_system: bool,
    pub integrity_level: Option<String>,
    pub risk_score: u8,
}

impl PrivilegeSummary {
    pub fn calculate_risk_score(&mut self, is_expected_system_process: bool) {
        let mut score: u16 = 0;

        // Only score if not an expected system process
        if !is_expected_system_process {
            if self.has_debug {
                score += 35;
            }
            if self.has_tcb {
                score += 40;
            }
            if self.has_load_driver {
                score += 30;
            }
            if self.has_impersonate {
                score += 20;
            }
            
            // Multiple dangerous privileges compound the risk
            score += ((self.dangerous_enabled.len() as u16).saturating_sub(1)) * 10;
            
            // Running as SYSTEM when not expected
            if self.running_as_system {
                score += 25;
            }
        }

        self.risk_score = score.min(100) as u8;
    }
}

/// Expected system processes that should run as SYSTEM with elevated privileges
pub fn is_expected_system_process(name: &str) -> bool {
    let system_processes = [
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "lsaiso.exe",
        "memory compression",
        "memcompression",
        "registry",
        "secure system",
        // Security / monitoring tools
        "msmpeng.exe",       // Windows Defender
        "mssense.exe",       // Microsoft Defender ATP
        "sysmon64.exe",      // Sysmon
        "sysmon.exe",
        "nissrv.exe",        // NIS service (Defender)
        "securityhealthservice.exe",
        "securityhealth",
        // Common system services
        "searchindexer.exe",
        "spoolsv.exe",
        "wuauserv",
        "trustedinstaller.exe",
        "tiworker.exe",
        "msiexec.exe",
        "wmiprvse.exe",
        // VirtualBox guest additions
        "vboxservice.exe",
        "vboxtray.exe",
        // Office / common apps running as SYSTEM
        "officeclicktorun.exe",
        "officec2rclient.exe",
        "appvshnotify.exe",
        // COM/WMI host processes
        "dllhost.exe",
        "unsecapp.exe",
        "wmiapsrv.exe",
        // Windows services that run as SYSTEM
        "mousocoreworker.exe",
        "audiodg.exe",
        "sgrmbroker.exe",
        "dashost.exe",
        "conhost.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
        "compattelrunner.exe",
        "securityhealthsystray.exe",
        "sgrmbroker.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        "sihost.exe",
        "ctfmon.exe",
        "smartscreen.exe",
        // Forensic capture tools
        "magnetramcapture",
        "magnetramcaptu",
        "ramcapture",
        "dumpit.exe",
        "ftk imager",
        "go-winpmem_amd64_1.0-rc2_signed.exe",
        // Sysinternals tools
        "procmon64.exe",
        "procmon.exe",
        "procexp64.exe",
        "procexp.exe",
        // Misc system processes
        "sppsvc.exe",
        "wermgr.exe",
        "werfault.exe",
        "csrss.exe",
    ];

    let lower = name.to_lowercase();
    // Handle Volatility3 truncated process names (typically 14-15 chars)
    // Match if either contains the other, or if one starts with the other
    system_processes.iter().any(|p| {
        lower.contains(p) || p.starts_with(&*lower) || lower.starts_with(p)
    })
}
