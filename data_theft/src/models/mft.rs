/// MFT artifact models for EZ Tools MFTECmd JSON output
use serde::{Deserialize, Serialize};

/// MFTECmd JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MftEntry {
    #[serde(alias = "EntryNumber")]
    pub entry_number: Option<i64>,
    #[serde(alias = "SequenceNumber")]
    pub sequence_number: Option<i32>,
    #[serde(alias = "InUse")]
    pub in_use: Option<bool>,
    #[serde(alias = "ParentEntryNumber")]
    pub parent_entry_number: Option<i64>,
    #[serde(alias = "ParentSequenceNumber")]
    pub parent_sequence_number: Option<i32>,
    #[serde(alias = "ParentPath")]
    pub parent_path: Option<String>,
    #[serde(alias = "FileName")]
    pub file_name: Option<String>,
    #[serde(alias = "Extension")]
    pub extension: Option<String>,
    #[serde(alias = "FileSize")]
    pub file_size: Option<i64>,
    #[serde(alias = "ReferenceCount")]
    pub reference_count: Option<i32>,
    #[serde(alias = "ReparseTarget")]
    pub reparse_target: Option<String>,
    #[serde(alias = "IsDirectory")]
    pub is_directory: Option<bool>,
    #[serde(alias = "HasAds")]
    pub has_ads: Option<bool>,
    #[serde(alias = "IsAds")]
    pub is_ads: Option<bool>,
    #[serde(alias = "Timestomped")]
    pub timestomped: Option<bool>,
    #[serde(alias = "uSecZeros")]
    pub usec_zeros: Option<bool>,
    #[serde(alias = "Copied")]
    pub copied: Option<bool>,
    #[serde(alias = "SiFlags")]
    pub si_flags: Option<String>,
    #[serde(alias = "NameType")]
    pub name_type: Option<String>,

    // $STANDARD_INFORMATION timestamps
    #[serde(alias = "Created0x10")]
    pub created_0x10: Option<String>,
    #[serde(alias = "LastModified0x10")]
    pub last_modified_0x10: Option<String>,
    #[serde(alias = "LastRecordChange0x10")]
    pub last_record_change_0x10: Option<String>,
    #[serde(alias = "LastAccess0x10")]
    pub last_access_0x10: Option<String>,

    // $FILE_NAME timestamps (harder to manipulate)
    #[serde(alias = "Created0x30")]
    pub created_0x30: Option<String>,
    #[serde(alias = "LastModified0x30")]
    pub last_modified_0x30: Option<String>,
    #[serde(alias = "LastRecordChange0x30")]
    pub last_record_change_0x30: Option<String>,
    #[serde(alias = "LastAccess0x30")]
    pub last_access_0x30: Option<String>,

    #[serde(alias = "LogfileSequenceNumber")]
    pub logfile_sequence_number: Option<i64>,
    #[serde(alias = "SecurityId")]
    pub security_id: Option<i32>,
    #[serde(alias = "ObjectIdFileDroid")]
    pub object_id_file_droid: Option<String>,
    #[serde(alias = "LoggedUtilStream")]
    pub logged_util_stream: Option<String>,
    #[serde(alias = "ZoneIdContents")]
    pub zone_id_contents: Option<String>,
}
