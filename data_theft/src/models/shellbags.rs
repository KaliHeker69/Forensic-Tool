/// Shellbag artifact models for EZ Tools SBECmd JSON output
use serde::{Deserialize, Serialize};

/// SBECmd JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ShellbagEntry {
    #[serde(alias = "SourceFile")]
    pub source_file: Option<String>,
    #[serde(alias = "ShellType")]
    pub shell_type: Option<String>,
    #[serde(alias = "Value")]
    pub value: Option<String>,
    #[serde(alias = "NodeSlot")]
    pub node_slot: Option<String>,
    #[serde(alias = "CreatedOn")]
    pub created_on: Option<String>,
    #[serde(alias = "ModifiedOn")]
    pub modified_on: Option<String>,
    #[serde(alias = "AccessedOn")]
    pub accessed_on: Option<String>,
    #[serde(alias = "LastWriteTime")]
    pub last_write_time: Option<String>,
    #[serde(alias = "MFTEntryNumber")]
    pub mft_entry_number: Option<i64>,
    #[serde(alias = "MFTSequenceNumber")]
    pub mft_sequence_number: Option<i64>,
    #[serde(alias = "AbsolutePath")]
    pub absolute_path: Option<String>,
    #[serde(alias = "ExtensionBlockCount")]
    pub extension_block_count: Option<i32>,
    #[serde(alias = "FirstInteracted")]
    pub first_interacted: Option<String>,
    #[serde(alias = "LastInteracted")]
    pub last_interacted: Option<String>,
}
