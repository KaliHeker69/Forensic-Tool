//! File-related data models for filescan, handles, dumpfiles plugins

use serde::{Deserialize, Serialize};

use super::process::deserialize_flexible_string_required;
use super::ProcessAssociated;

/// File object from filescan plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileObject {
    /// Memory offset
    #[serde(alias = "Offset", alias = "offset", deserialize_with = "deserialize_flexible_string_required")]
    pub offset: String,

    /// Pointer count
    #[serde(alias = "Ptr", alias = "#Ptr", alias = "ptr")]
    pub ptr: Option<u32>,

    /// Handle count
    #[serde(alias = "Hnd", alias = "#Hnd", alias = "hnd")]
    pub hnd: Option<u32>,

    /// Access rights
    #[serde(alias = "Access", alias = "access")]
    pub access: Option<String>,

    /// File name/path
    #[serde(alias = "Name", alias = "FileName", alias = "name")]
    pub name: String,
}

impl FileObject {
    /// Check if file is in a suspicious location
    /// DEPRECATED: Use BlacklistConfig in detection rules instead
    pub fn is_suspicious_path(&self) -> bool {
        false
    }

    /// Check if file has executable extension
    pub fn is_executable(&self) -> bool {
        let lower = self.name.to_lowercase();
        let exe_extensions = [
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
            ".msi", ".jar", ".com", ".pif",
        ];
        exe_extensions.iter().any(|ext| lower.ends_with(ext))
    }

    /// Check if file is a known staging pattern
    pub fn is_staging_pattern(&self) -> bool {
        let lower = self.name.to_lowercase();
        // Common malware staging patterns
        lower.contains("\\downloads\\")
            || lower.contains("\\temp\\")
            || (lower.contains("\\appdata\\") && self.is_executable())
    }

    /// Extract just the filename from the full path
    pub fn filename(&self) -> &str {
        self.name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.name)
    }
}

/// Handle information from handles plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    /// Process ID
    #[serde(alias = "PID", alias = "Pid")]
    pub pid: u32,

    /// Process name
    #[serde(alias = "Process")]
    pub process: String,

    /// Handle offset
    #[serde(alias = "Offset", alias = "offset", deserialize_with = "deserialize_flexible_string_required")]
    pub offset: String,

    /// Handle type (File, Key, Process, Thread, etc.)
    #[serde(alias = "Type", alias = "HandleType", alias = "type")]
    pub handle_type: String,

    /// Handle value
    #[serde(alias = "HandleValue", alias = "handle_value", default)]
    pub handle_value: Option<u64>,

    /// Granted access mask
    #[serde(alias = "GrantedAccess", alias = "Access", deserialize_with = "deserialize_flexible_string_required")]
    pub granted_access: String,

    /// Object name (if available)
    #[serde(alias = "Name", alias = "Details", alias = "name")]
    pub name: Option<String>,
}

impl HandleInfo {
    /// Check if this is a handle to a sensitive process (e.g., lsass)
    pub fn is_sensitive_process_handle(&self) -> bool {
        if self.handle_type.to_lowercase() != "process" {
            return false;
        }
        let name_lower = self.name.as_deref().unwrap_or("").to_lowercase();
        let sensitive = ["lsass", "csrss", "winlogon", "services", "smss"];
        sensitive.iter().any(|p| name_lower.contains(p))
    }

    /// Check if this is a file handle
    pub fn is_file_handle(&self) -> bool {
        self.handle_type.to_lowercase() == "file"
    }

    /// Check if this is a registry key handle
    pub fn is_registry_handle(&self) -> bool {
        self.handle_type.to_lowercase() == "key"
    }

    /// Check if this is a mutex/mutant handle
    pub fn is_mutex_handle(&self) -> bool {
        let t = self.handle_type.to_lowercase();
        t == "mutant" || t == "mutex"
    }
}

impl ProcessAssociated for HandleInfo {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        Some(&self.process)
    }
}

/// Dumped file information from dumpfiles plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedFile {
    /// Cache type (DataSectionObject, ImageSectionObject, SharedCacheMap)
    #[serde(alias = "Cache", alias = "CacheType", alias = "cache")]
    pub cache_type: String,

    /// File offset
    #[serde(alias = "FileObject", alias = "offset")]
    pub file_object: String,

    /// Original file name
    #[serde(alias = "FileName", alias = "Name", alias = "name")]
    pub file_name: String,

    /// Result of dump operation
    #[serde(alias = "Result", alias = "result")]
    pub result: Option<String>,
}
