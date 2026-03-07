/// Registry artifact models for EZ Tools RECmd JSON output
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// RECmd batch output entry (generic registry key/value)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegCmdEntry {
    #[serde(alias = "HivePath")]
    pub hive_path: Option<String>,
    #[serde(alias = "HiveType")]
    pub hive_type: Option<String>,
    #[serde(alias = "Description")]
    pub description: Option<String>,
    #[serde(alias = "Category")]
    pub category: Option<String>,
    #[serde(alias = "KeyPath")]
    pub key_path: Option<String>,
    #[serde(alias = "ValueName")]
    pub value_name: Option<String>,
    #[serde(alias = "ValueType")]
    pub value_type: Option<String>,
    #[serde(alias = "ValueData")]
    pub value_data: Option<String>,
    #[serde(alias = "ValueData2")]
    pub value_data2: Option<String>,
    #[serde(alias = "ValueData3")]
    pub value_data3: Option<String>,
    #[serde(alias = "Comment")]
    pub comment: Option<String>,
    #[serde(alias = "Recursive")]
    pub recursive: Option<bool>,
    #[serde(alias = "Deleted")]
    pub deleted: Option<bool>,
    #[serde(alias = "LastWriteTimestamp")]
    pub last_write_timestamp: Option<String>,
    #[serde(alias = "PluginDetailValues")]
    pub plugin_detail_values: Option<serde_json::Value>,
}

/// USBSTOR device entry parsed from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct UsbStorEntry {
    pub vendor: String,
    pub product: String,
    pub revision: Option<String>,
    pub serial_number: String,
    pub friendly_name: Option<String>,
    pub first_install_date: Option<DateTime<Utc>>,
    pub last_connected: Option<DateTime<Utc>>,
    pub last_removal: Option<DateTime<Utc>>,
    pub container_id: Option<String>,
    pub device_desc: Option<String>,
    pub parent_id_prefix: Option<String>,
}

/// MountPoints2 entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MountPoints2Entry {
    pub volume_guid: String,
    pub user_sid: Option<String>,
    pub last_write_time: Option<DateTime<Utc>>,
}

/// MountedDevices entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MountedDeviceEntry {
    pub drive_letter: Option<String>,
    pub volume_guid: Option<String>,
    pub device_data: String,
}

/// AppCompatCache entry from AppCompatCacheParser
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AppCompatCacheEntry {
    #[serde(alias = "ControlSet")]
    pub control_set: Option<i32>,
    #[serde(alias = "CacheEntryPosition")]
    pub cache_entry_position: Option<i32>,
    #[serde(alias = "Path")]
    pub path: Option<String>,
    #[serde(alias = "LastModifiedTimeUTC")]
    pub last_modified_time_utc: Option<String>,
    #[serde(alias = "Executed")]
    pub executed: Option<String>,
    #[serde(alias = "Duplicate")]
    pub duplicate: Option<bool>,
    #[serde(alias = "SourceFile")]
    pub source_file: Option<String>,
}
