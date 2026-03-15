use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchFile {
    pub source_filename: String,
    pub header: PrefetchHeader,
    pub file_metrics: Vec<FileMetricEntry>,
    pub volumes: Vec<VolumeInfo>,
    pub filename_strings: Vec<String>,
    pub version: u32,
    pub was_compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchHeader {
    pub version: u32,
    pub exe_name: String,
    pub prefetch_hash: String,
    pub file_size: u32,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    // Internal counts (not serialised to JSON — informational only)
    #[serde(skip)]
    pub file_metrics_count: u32,
    #[serde(skip)]
    pub volume_info_count: u32,
    // Legacy offset fields kept for compat with detection/rules.rs API surface
    #[serde(skip)]
    pub file_metrics_offset: u32,
    #[serde(skip)]
    pub trace_chains_offset: u32,
    #[serde(skip)]
    pub trace_chains_count: u32,
    #[serde(skip)]
    pub filename_strings_offset: u32,
    #[serde(skip)]
    pub filename_strings_size: u32,
    #[serde(skip)]
    pub volume_info_offset: u32,
    #[serde(skip)]
    pub volume_info_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetricEntry {
    pub index: u32,
    pub filename: String,
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub flags: u32,
    #[serde(skip)]
    pub filename_offset: u32,
    #[serde(skip)]
    pub filename_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub device_path: String,
    pub creation_time: DateTime<Utc>,
    pub serial_number: String,
    pub directories: Vec<String>,
}

/// Format version enum — used only by the hash-mismatch detection rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrefetchVersion {
    V17,
    V23,
    V26,
    V30,
    V31,
}

impl PrefetchVersion {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            17 => Some(Self::V17),
            23 => Some(Self::V23),
            26 => Some(Self::V26),
            30 => Some(Self::V30),
            31 => Some(Self::V31),
            _ => None,
        }
    }
}
