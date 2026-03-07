/// Prefetch artifact models for EZ Tools PECmd JSON output
use serde::{Deserialize, Serialize};

/// PECmd JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PrefetchEntry {
    #[serde(alias = "SourceFilename")]
    pub source_filename: Option<String>,
    #[serde(alias = "SourceCreated")]
    pub source_created: Option<String>,
    #[serde(alias = "SourceModified")]
    pub source_modified: Option<String>,
    #[serde(alias = "SourceAccessed")]
    pub source_accessed: Option<String>,
    #[serde(alias = "ExecutableName")]
    pub executable_name: Option<String>,
    #[serde(alias = "Hash")]
    pub hash: Option<String>,
    #[serde(alias = "Size")]
    pub size: Option<i64>,
    #[serde(alias = "Version")]
    pub version: Option<String>,
    #[serde(alias = "RunCount")]
    pub run_count: Option<i32>,
    #[serde(alias = "LastRun")]
    pub last_run: Option<String>,
    #[serde(alias = "PreviousRun0")]
    pub previous_run0: Option<String>,
    #[serde(alias = "PreviousRun1")]
    pub previous_run1: Option<String>,
    #[serde(alias = "PreviousRun2")]
    pub previous_run2: Option<String>,
    #[serde(alias = "PreviousRun3")]
    pub previous_run3: Option<String>,
    #[serde(alias = "PreviousRun4")]
    pub previous_run4: Option<String>,
    #[serde(alias = "PreviousRun5")]
    pub previous_run5: Option<String>,
    #[serde(alias = "PreviousRun6")]
    pub previous_run6: Option<String>,
    #[serde(alias = "Volume0Name")]
    pub volume0_name: Option<String>,
    #[serde(alias = "Volume0Serial")]
    pub volume0_serial: Option<String>,
    #[serde(alias = "Volume0Created")]
    pub volume0_created: Option<String>,
    #[serde(alias = "Volume1Name")]
    pub volume1_name: Option<String>,
    #[serde(alias = "Volume1Serial")]
    pub volume1_serial: Option<String>,
    #[serde(alias = "Volume1Created")]
    pub volume1_created: Option<String>,
    #[serde(alias = "Directories")]
    pub directories: Option<String>,
    #[serde(alias = "FilesLoaded")]
    pub files_loaded: Option<String>,
    #[serde(alias = "ParsingError")]
    pub parsing_error: Option<bool>,
}
