//! Services and drivers data models for svcscan, driverscan plugins

use serde::{Deserialize, Serialize};

use super::process::{deserialize_flexible_string, deserialize_flexible_string_required};
use super::ProcessAssociated;

/// Service information from svcscan plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Memory offset
    #[serde(alias = "Offset", alias = "offset", default, deserialize_with = "deserialize_flexible_string")]
    pub offset: Option<String>,

    /// Service order (start order)
    #[serde(alias = "Order", alias = "order")]
    pub order: Option<u32>,

    /// Process ID hosting the service
    #[serde(alias = "PID", alias = "Pid", alias = "ProcessId", default, deserialize_with = "deserialize_flexible_string")]
    pub pid: Option<String>,

    /// Service start type
    #[serde(alias = "Start", alias = "StartType")]
    pub start_type: Option<String>,

    /// Service name
    #[serde(alias = "Name", alias = "ServiceName", alias = "name")]
    pub name: String,

    /// Display name
    #[serde(alias = "Display", alias = "DisplayName", alias = "display")]
    pub display_name: Option<String>,

    /// Service type
    #[serde(alias = "Type", alias = "ServiceType", alias = "type")]
    pub service_type: Option<String>,

    /// Service state
    #[serde(alias = "State", alias = "CurrentState", alias = "state")]
    pub state: Option<String>,

    /// Service binary path
    #[serde(alias = "Binary", alias = "BinaryPath", alias = "binary")]
    pub binary_path: Option<String>,
}

impl ServiceInfo {
    /// Check if service is running
    pub fn is_running(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| s.to_uppercase().contains("RUNNING"))
            .unwrap_or(false)
    }

    /// Check if service binary is in a suspicious location
    /// Check if service binary is in a suspicious location
    /// DEPRECATED: Use BlacklistConfig in detection rules instead
    pub fn is_suspicious_path(&self) -> bool {
        false
    }

    /// Check if this service name is suspicious (random-looking or mimicking)
    /// Returns false for known legitimate Windows services
    pub fn is_suspicious_name(&self) -> bool {
        let name = self.name.to_lowercase();
        
        // Comprehensive whitelist of known legitimate Windows services
        // These should NEVER be flagged as suspicious
        const LEGITIMATE_SERVICES: &[&str] = &[
            // Core Windows services (short names)
            "afd", "bfe", "lsm", "tpm", "efs", "vss", "wof", "csc", "dps", "dxgkrnl",
            "tcpip", "ndis", "http", "rdp", "smb", "dns", "dhcp", "rpc", "sam", "bits",
            "wmi", "wer", "pfn", "pnp", "usb", "scm", "acpi", "pci", "ntfs", "refs",
            "fdc", "i8042prt", "kbdclass", "mouclass", "cdrom", "disk", "partmgr",
            "volmgr", "volsnap", "fvevol", "iorate", "wfplwf", "ndisuio", "netbt",
            "smb2", "srv", "srv2", "mrxsmb", "rdbss", "mup", "dfsc", "lxcore", "npfs",
            "msfs", "cng", "ksecdd", "ksecpkg", "clipsp", "clfs",
            
            // Windows Defender / Security (including MpKsl* pattern)
            "mpssvc", "wscsvc", "windefend", "securityhealthservice", "sense",
            "mssense", "mpsdrv", "wdfilter", "wdboot", "wdnisdrv", "wdnissvc",
            
            // Cryptographic and security services
            "cryptsvc", "keyiso", "samss", "vaultsvc", "dpapi", "protecteduserssvc",
            
            // Network services
            "netlogon", "lanmanserver", "lanmanworkstation", "browser", "lmhosts",
            "dnscache", "iphlpsvc", "nla", "ncsi", "netprofm", "wpnservice",
            "wcncsvc", "wcmsvc", "rmcsvc", "icssvc", "wlansvc", "dot3svc",
            "eaphost", "rasman", "rasauto", "remoteaccess", "sstpsvc", "ikeext",
            "ipnat", "sharedaccess",
            
            // Print services
            "spooler", "printnotify",
            
            // Audio/Media services
            "audiosrv", "audioendpointbuilder", "mmcss", "qwave",
            
            // Power/Hardware services
            "power", "umbus", "usbhub", "usbhub3", "usbxhci", "hidusb",
            "hidbth", "bthhfenum", "bthserv", "bthenum", "rfcomm",
            
            // User/Session services
            "profsvcs", "profsvc", "usersvc", "staterepository", "appxsvc",
            "tiledatamodelsvc", "cbdhsvc", "cbtransmgrsvc",
            
            // Windows Update/Installer
            "wuauserv", "bits", "msiserver", "trustedinstaller", "usosvc",
            
            // Task Scheduler
            "schedule", "taskhost", "taskhostw",
            
            // Event Log / Tracing
            "eventlog", "eventsystem", "pcasvc", "diagtrack", "utcsvc",
            
            // Themes/UI
            "themes", "uxsms", "dwm", "fontcache", "fontcache3_0_0_0",
            
            // Storage/Backup
            "vds", "swprv", "wbengine", "wbiosrvc", "sdrsvc", "fdrpuller",
            
            // COM/DCOM
            "dcomlaunch", "rpcss", "rpclocator", "rpcepmap",
            
            // Search/Indexing
            "wsearch", "sensorsvc", "sensordatasvc", "sensorservice",
            
            // App services
            "appinfo", "appidsvc", "appreadiness", "appxsvc",
            
            // Browser/Web
            "winhttp", "winrm", "wecsvc", "w3svc", "was", "wmsvc",
            
            // VirtualBox/VMware guest additions
            "vboxservice", "vboxtray", "vmtoolsd", "vmwaretoolsservice",
            "synth3dvsc",
            
            // Remote services
            "termservice", "umrdpservice", "sessionenv",
            
            // System services (can have numbers/hex suffixes)
            "ngcctnrsvc", "ngcsvc", "deviceinstall", "devicesflow",
            
            // Additional common services
            "gpsvc", "grouppolicy", "hvsics", "hvhost", "vmcompute", "vmicheartbeat",
            "vmickvpexchange", "vmicshutdown", "vmictimesync", "vmicvss",
        ];
        
        // Check for MpKsl* pattern (Windows Defender kernel driver - random hex suffix is normal)
        if name.starts_with("mpksl") {
            return false;
        }
        
        // Check against whitelist
        if LEGITIMATE_SERVICES.contains(&name.as_str()) {
            return false;
        }
        
        // Check for known legit service mimicry ONLY
        let mimics = ["svch0st", "svchosts", "svcnost", "spoolsvr", "lssas", "lssass", "svhost", 
                      "scvhost", "csvhost", "svvchost", "ssvchost", "svchosst", "svchostt"];
        if mimics.iter().any(|m| name == *m) {
            return true;
        }
        
        // Check for truly random-looking names (8+ consonants with 0 vowels in 10+ char names)
        // This is more conservative to avoid false positives
        if name.len() >= 10 {
            let vowels: usize = name.chars().filter(|c| "aeiou".contains(*c)).count();
            let consonants: usize = name.chars().filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c)).count();
            
            if consonants >= 8 && vowels == 0 {
                return true;
            }
        }
        
        // Names that are purely hex (common for malware) - but exclude known patterns
        if name.len() >= 8 && name.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        false
    }

    /// Check if binary path uses suspicious execution patterns
    pub fn has_suspicious_execution(&self) -> bool {
        self.binary_path
            .as_ref()
            .map(|p| {
                let lower = p.to_lowercase();
                lower.contains("cmd.exe /c")
                    || lower.contains("powershell")
                    || lower.contains("-enc")
                    || lower.contains("-e ")
                    || lower.contains("mshta")
                    || lower.contains("wscript")
                    || lower.contains("cscript")
            })
            .unwrap_or(false)
    }
}

impl ProcessAssociated for ServiceInfo {
    fn pid(&self) -> Option<u32> {
        self.pid.as_ref().and_then(|s| s.parse().ok())
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.name)
    }
}

/// Driver information from driverscan/modules plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    /// Memory offset
    #[serde(alias = "Offset", alias = "offset", deserialize_with = "deserialize_flexible_string_required")]
    pub offset: String,

    /// Base address
    #[serde(alias = "Base", alias = "Start", alias = "base", default, deserialize_with = "deserialize_flexible_string")]
    pub base: Option<String>,

    /// Size
    #[serde(alias = "Size", alias = "size")]
    pub size: Option<u64>,

    /// Driver name
    #[serde(alias = "Name", alias = "name")]
    pub name: String,

    /// Full path
    #[serde(alias = "Path", alias = "FullName", alias = "path")]
    pub path: Option<String>,
}

impl DriverInfo {
    /// Check if driver is from System32\drivers
    pub fn is_standard_location(&self) -> bool {
        self.path
            .as_ref()
            .map(|p| {
                let lower = p.to_lowercase();
                lower.contains("\\system32\\drivers\\") || lower.contains("\\syswow64\\")
            })
            .unwrap_or(false)
    }

    /// Check if driver is in suspicious location
    pub fn is_suspicious_path(&self) -> bool {
        self.path
            .as_ref()
            .map(|p| {
                let lower = p.to_lowercase();
                !self.is_standard_location()
                    && (lower.contains("\\temp\\")
                        || lower.contains("\\tmp\\")
                        || lower.contains("\\appdata\\")
                        || lower.contains("\\users\\"))
            })
            .unwrap_or(false)
    }
}

/// Callback information from callbacks plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackInfo {
    /// Callback type
    #[serde(alias = "Type", alias = "type")]
    pub callback_type: String,

    /// Callback address
    #[serde(alias = "Callback", alias = "Address", alias = "callback")]
    pub callback: String,

    /// Module name
    #[serde(alias = "Module", alias = "Owner", alias = "module")]
    pub module: Option<String>,

    /// Details
    #[serde(alias = "Detail", alias = "Details", alias = "detail")]
    pub detail: Option<String>,
}

impl CallbackInfo {
    /// Check if callback is from an unknown/suspicious module
    pub fn is_suspicious_module(&self) -> bool {
        self.module
            .as_ref()
            .map(|m| {
                let lower = m.to_lowercase();
                // Unknown or unusual module
                lower.contains("unknown")
                    || lower.is_empty()
                    || (!lower.contains("nt")
                        && !lower.contains("win32k")
                        && !lower.contains("hal.")
                        && !lower.contains("ci.dll")
                        && !lower.contains("clfs")
                        && !lower.contains("tcpip"))
            })
            .unwrap_or(true)
    }
}

/// SSDT entry from ssdt plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsdtEntry {
    /// Index in SSDT
    #[serde(alias = "Index", alias = "index")]
    pub index: u32,

    /// Address
    #[serde(alias = "Address", alias = "address")]
    pub address: String,

    /// Module name
    #[serde(alias = "Module", alias = "Owner", alias = "module")]
    pub module: Option<String>,

    /// Symbol name (if resolved)
    #[serde(alias = "Symbol", alias = "Name", alias = "symbol")]
    pub symbol: Option<String>,
}

impl SsdtEntry {
    /// Check if SSDT entry points outside ntoskrnl
    pub fn is_hooked(&self) -> bool {
        self.module
            .as_ref()
            .map(|m| {
                let lower = m.to_lowercase();
                !lower.contains("ntoskrnl") && !lower.contains("ntos")
            })
            .unwrap_or(false)
    }
}

/// Driver IRP dispatch entry from driverirp plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverIrpEntry {
    /// Driver object offset
    #[serde(alias = "Offset", alias = "offset", default, deserialize_with = "deserialize_flexible_string")]
    pub offset: Option<String>,

    /// Driver name
    #[serde(alias = "Driver Name", alias = "DriverName", alias = "Driver", alias = "Name")]
    pub driver_name: String,

    /// Major IRP function name
    #[serde(alias = "IRP", alias = "MajorFunction", alias = "Type")]
    pub irp: String,

    /// Handler address
    #[serde(
        alias = "Address",
        alias = "address",
        alias = "Function",
        deserialize_with = "deserialize_flexible_string_required"
    )]
    pub address: String,

    /// Resolved owning module for the handler
    #[serde(alias = "Module", alias = "Owner", alias = "module", default)]
    pub module: Option<String>,

    /// Resolved symbol name (if available)
    #[serde(alias = "Symbol", alias = "symbol", default)]
    pub symbol: Option<String>,
}

impl DriverIrpEntry {
    /// Heuristic for suspicious IRP handler ownership.
    pub fn is_suspicious_handler_owner(&self) -> bool {
        let module = self.module.as_deref().unwrap_or("").to_ascii_lowercase();
        if module.is_empty() || module.contains("unknown") {
            return true;
        }

        // Userland owners or writable-path indicators should never own kernel IRP dispatch.
        module.contains(".exe")
            || module.contains("\\users\\")
            || module.contains("\\temp\\")
            || module.contains("\\appdata\\")
    }
}

/// Interrupt Descriptor Table entry from idt plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdtEntry {
    /// Vector/index
    #[serde(alias = "Index", alias = "Vector", alias = "Entry", default, deserialize_with = "deserialize_flexible_string")]
    pub index: Option<String>,

    /// Handler address
    #[serde(
        alias = "Address",
        alias = "Handler",
        alias = "Offset",
        deserialize_with = "deserialize_flexible_string_required"
    )]
    pub address: String,

    /// Resolved module owning the handler
    #[serde(alias = "Module", alias = "Owner", alias = "module", default)]
    pub module: Option<String>,

    /// Resolved symbol (if available)
    #[serde(alias = "Symbol", alias = "Name", alias = "symbol", default)]
    pub symbol: Option<String>,
}

impl IdtEntry {
    /// IDT entries should resolve into core kernel modules.
    pub fn is_suspicious_owner(&self) -> bool {
        let module = self.module.as_deref().unwrap_or("").to_ascii_lowercase();
        if module.is_empty() || module.contains("unknown") {
            return true;
        }

        !(module.contains("ntoskrnl")
            || module.contains("hal")
            || module.contains("win32k")
            || module.contains("ci.dll"))
    }
}

/// Atom entry from atoms plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomEntry {
    /// Atom or name field
    #[serde(alias = "Atom", alias = "Name", alias = "AtomName", alias = "atom")]
    pub atom: String,

    /// Optional process context if provided by plugin variant
    #[serde(alias = "PID", alias = "Pid", default)]
    pub pid: Option<u32>,

    /// Optional process/image name if provided
    #[serde(alias = "Process", alias = "ImageFileName", alias = "Owner", default)]
    pub process: Option<String>,

    /// Additional metadata fields exposed by plugin variants
    #[serde(alias = "ReferenceCount", alias = "RefCount", default, deserialize_with = "deserialize_flexible_string")]
    pub ref_count: Option<String>,
}

impl AtomEntry {
    pub fn is_suspicious_name(&self) -> bool {
        let v = self.atom.trim().to_ascii_lowercase();
        if v.is_empty() {
            return false;
        }

        // Common IOC-style atom naming patterns used by message-hook injectors.
        let ioc_keywords = ["cobalt", "meterpreter", "shellcode", "hook", "inject", "payload"];
        if ioc_keywords.iter().any(|k| v.contains(k)) {
            return true;
        }

        // High-entropy blob-like atoms are unusual in normal desktop usage.
        let long_hex_like = v.len() >= 20 && v.chars().all(|c| c.is_ascii_hexdigit());
        let long_b64_like = v.len() >= 24
            && v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

        long_hex_like || long_b64_like
    }
}
