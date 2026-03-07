/// USN Journal artifact models for EZ Tools MFTECmd JSON output (--usn flag)
use serde::{Deserialize, Serialize};

/// MFTECmd USN Journal JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UsnJrnlEntry {
    #[serde(alias = "Name")]
    pub name: Option<String>,
    #[serde(alias = "Extension")]
    pub extension: Option<String>,
    #[serde(alias = "EntryNumber")]
    pub entry_number: Option<i64>,
    #[serde(alias = "SequenceNumber")]
    pub sequence_number: Option<i32>,
    #[serde(alias = "ParentEntryNumber")]
    pub parent_entry_number: Option<i64>,
    #[serde(alias = "ParentSequenceNumber")]
    pub parent_sequence_number: Option<i32>,
    #[serde(alias = "ParentPath")]
    pub parent_path: Option<String>,
    #[serde(alias = "UpdateTimestamp")]
    pub update_timestamp: Option<String>,
    #[serde(alias = "UpdateReasons")]
    pub update_reasons: Option<String>,
    #[serde(alias = "FileAttributes")]
    pub file_attributes: Option<String>,
    #[serde(alias = "OffsetToData")]
    pub offset_to_data: Option<i64>,
    #[serde(alias = "SourceFile")]
    pub source_file: Option<String>,
}
