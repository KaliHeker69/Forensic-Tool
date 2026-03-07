//! Registry-related data models for registry plugins

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::process::{deserialize_flexible_string, deserialize_flexible_string_required};
use super::Timestamped;

/// Registry hive information from hivelist plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryHive {
    /// Memory offset
    #[serde(alias = "Offset", alias = "offset", deserialize_with = "deserialize_flexible_string_required")]
    pub offset: String,

    /// Hive file path
    #[serde(alias = "FileFullPath", alias = "Path", alias = "path", default)]
    pub path: String,

    /// Hive name
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
}

impl RegistryHive {
    /// Check if this is a user hive (NTUSER.DAT)
    pub fn is_user_hive(&self) -> bool {
        let lower = self.path.to_lowercase();
        lower.contains("ntuser.dat") || lower.contains("usrclass.dat")
    }

    /// Check if this is a system hive
    pub fn is_system_hive(&self) -> bool {
        let lower = self.path.to_lowercase();
        lower.contains("\\system32\\config\\")
    }
}

/// Registry key/value from printkey plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    /// Hive offset
    #[serde(alias = "Hive Offset", alias = "HiveOffset", alias = "hive_offset", default, deserialize_with = "deserialize_flexible_string")]
    pub hive_offset: Option<String>,

    /// Key path
    #[serde(alias = "Key", alias = "KeyPath", alias = "key")]
    pub key: String,

    /// Key name
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,

    /// Value type
    #[serde(alias = "Type", alias = "type")]
    pub value_type: Option<String>,

    /// Value data
    #[serde(alias = "Data", alias = "Value", alias = "data")]
    pub data: Option<String>,

    /// Volatile flag
    #[serde(alias = "Volatile", alias = "volatile")]
    pub volatile: Option<bool>,

    /// Last write time
    #[serde(alias = "Last Write Time", alias = "LastWriteTime", alias = "last_write")]
    pub last_write: Option<DateTime<Utc>>,
}

impl RegistryKey {
    /// Check if this is a known persistence location
    pub fn is_persistence_key(&self) -> bool {
        let lower = self.key.to_lowercase();
        let persistence_keys = [
            "\\run",
            "\\runonce",
            "\\runservices",
            "\\runonceex",
            "\\explorer\\shellexecutehooks",
            "\\explorer\\browser helper objects",
            "\\winlogon\\notify",
            "\\winlogon\\userinit",
            "\\winlogon\\shell",
            "\\image file execution options",
            "\\appinit_dlls",
            "\\sessions\\sessionmanager",
            "\\environment\\userinitialization",
            "\\currentversion\\policies\\explorer\\run",
        ];
        persistence_keys.iter().any(|k| lower.contains(k))
    }

    /// Check if the data contains an executable path
    pub fn has_executable_data(&self) -> bool {
        self.data
            .as_ref()
            .map(|d| {
                let lower = d.to_lowercase();
                lower.ends_with(".exe")
                    || lower.ends_with(".dll")
                    || lower.ends_with(".bat")
                    || lower.ends_with(".cmd")
                    || lower.ends_with(".ps1")
                    || lower.ends_with(".vbs")
                    || lower.contains("powershell")
                    || lower.contains("cmd.exe")
                    || lower.contains("wscript")
                    || lower.contains("cscript")
                    || lower.contains("mshta")
                    || lower.contains("rundll32")
            })
            .unwrap_or(false)
    }

    /// Check if data looks obfuscated
    pub fn has_obfuscated_data(&self) -> bool {
        self.data
            .as_ref()
            .map(|d| {
                let lower = d.to_lowercase();
                lower.contains("base64")
                    || lower.contains("-enc")
                    || lower.contains("-e ")
                    || lower.contains("frombase64string")
                    || d.matches('^').count() > 5  // XOR obfuscation pattern
                    || (d.len() > 100 && d.chars().filter(|c| *c == '+').count() > 10)
            })
            .unwrap_or(false)
    }

    /// Extract the base key name (last component of path)
    pub fn base_name(&self) -> &str {
        self.key.rsplit('\\').next().unwrap_or(&self.key)
    }
}

impl Timestamped for RegistryKey {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.last_write
    }
}

/// UserAssist entry for execution history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAssist {
    /// Hive offset
    #[serde(alias = "Hive Offset", alias = "hive_offset", default, deserialize_with = "deserialize_flexible_string")]
    pub hive_offset: Option<String>,

    /// Path (ROT13 encoded originally)
    #[serde(alias = "Path", alias = "Name", alias = "path")]
    pub path: String,

    /// Execution count
    #[serde(alias = "Count", alias = "count")]
    pub count: Option<u32>,

    /// Focus count
    #[serde(alias = "Focus", alias = "FocusCount", alias = "focus")]
    pub focus_count: Option<u32>,

    /// Focus time (in 100ns intervals)
    #[serde(alias = "Time Focused", alias = "TimeFocused", alias = "time_focused")]
    pub time_focused: Option<u64>,

    /// Last execution time
    #[serde(alias = "Last Updated", alias = "LastUpdated", alias = "last_updated")]
    pub last_updated: Option<DateTime<Utc>>,
}

impl UserAssist {
    /// Check if this is an executable being tracked
    pub fn is_executable(&self) -> bool {
        let lower = self.path.to_lowercase();
        lower.ends_with(".exe")
            || lower.ends_with(".lnk")
            || lower.ends_with(".bat")
            || lower.ends_with(".cmd")
    }

    /// Check if this looks like a suspicious execution
    /// Check if this looks like a suspicious execution
    /// DEPRECATED: Use BlacklistConfig in detection rules instead
    pub fn is_suspicious_path(&self) -> bool {
        false
    }
}

impl Timestamped for UserAssist {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.last_updated
    }
}
