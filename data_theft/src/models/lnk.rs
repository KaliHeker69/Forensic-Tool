/// LNK file artifact models for EZ Tools LECmd JSON output
use serde::{Deserialize, Serialize};

/// LECmd JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LnkEntry {
    #[serde(alias = "SourceFile")]
    pub source_file: Option<String>,
    #[serde(alias = "SourceCreated")]
    pub source_created: Option<String>,
    #[serde(alias = "SourceModified")]
    pub source_modified: Option<String>,
    #[serde(alias = "SourceAccessed")]
    pub source_accessed: Option<String>,
    #[serde(alias = "TargetCreated")]
    pub target_created: Option<String>,
    #[serde(alias = "TargetModified")]
    pub target_modified: Option<String>,
    #[serde(alias = "TargetAccessed")]
    pub target_accessed: Option<String>,
    #[serde(alias = "FileSize")]
    pub file_size: Option<i64>,
    #[serde(alias = "RelativePath")]
    pub relative_path: Option<String>,
    #[serde(alias = "WorkingDirectory")]
    pub working_directory: Option<String>,
    #[serde(alias = "FileAttributes")]
    pub file_attributes: Option<String>,
    #[serde(alias = "HeaderFlags")]
    pub header_flags: Option<String>,
    #[serde(alias = "DriveType")]
    pub drive_type: Option<String>,
    #[serde(alias = "DriveSerialNumber")]
    pub drive_serial_number: Option<String>,
    #[serde(alias = "VolumeLabel")]
    pub volume_label: Option<String>,
    #[serde(alias = "LocalPath")]
    pub local_path: Option<String>,
    #[serde(alias = "NetworkPath")]
    pub network_path: Option<String>,
    #[serde(alias = "CommonPath")]
    pub common_path: Option<String>,
    #[serde(alias = "Arguments")]
    pub arguments: Option<String>,
    #[serde(alias = "TargetIDAbsolutePath")]
    pub target_id_absolute_path: Option<String>,
    #[serde(alias = "TargetMFTEntryNumber")]
    pub target_mft_entry_number: Option<i64>,
    #[serde(alias = "TargetMFTSequenceNumber")]
    pub target_mft_sequence_number: Option<i64>,
    #[serde(alias = "MachineID")]
    pub machine_id: Option<String>,
    #[serde(alias = "MachineMACAddress")]
    pub machine_mac_address: Option<String>,
    #[serde(alias = "TrackerCreatedOn")]
    pub tracker_created_on: Option<String>,
    #[serde(alias = "ExtraBlocks")]
    pub extra_blocks: Option<serde_json::Value>,
}
