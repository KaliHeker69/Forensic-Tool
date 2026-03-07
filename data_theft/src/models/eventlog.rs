/// Event Log artifact models for EZ Tools EvtxECmd JSON output
use serde::{Deserialize, Serialize};

/// EvtxECmd JSON output entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EvtxEntry {
    #[serde(alias = "ChunkNumber")]
    pub chunk_number: Option<i64>,
    #[serde(alias = "Computer")]
    pub computer: Option<String>,
    #[serde(alias = "Payload")]
    pub payload: Option<String>,
    #[serde(alias = "UserId")]
    pub user_id: Option<String>,
    #[serde(alias = "Channel")]
    pub channel: Option<String>,
    #[serde(alias = "Provider")]
    pub provider: Option<String>,
    #[serde(alias = "EventId")]
    pub event_id: Option<i32>,
    #[serde(alias = "EventRecordId")]
    pub event_record_id: Option<i64>,
    #[serde(alias = "Level")]
    pub level: Option<String>,
    #[serde(alias = "Keywords")]
    pub keywords: Option<String>,
    #[serde(alias = "SourceFile")]
    pub source_file: Option<String>,
    #[serde(alias = "TimeCreated")]
    pub time_created: Option<String>,
    #[serde(alias = "RecordNumber")]
    pub record_number: Option<i64>,
    #[serde(alias = "MapDescription")]
    pub map_description: Option<String>,
    #[serde(alias = "UserName")]
    pub user_name: Option<String>,
    #[serde(alias = "RemoteHost")]
    pub remote_host: Option<String>,
    #[serde(alias = "PayloadData1")]
    pub payload_data1: Option<String>,
    #[serde(alias = "PayloadData2")]
    pub payload_data2: Option<String>,
    #[serde(alias = "PayloadData3")]
    pub payload_data3: Option<String>,
    #[serde(alias = "PayloadData4")]
    pub payload_data4: Option<String>,
    #[serde(alias = "PayloadData5")]
    pub payload_data5: Option<String>,
    #[serde(alias = "PayloadData6")]
    pub payload_data6: Option<String>,
    #[serde(alias = "ExecutableInfo")]
    pub executable_info: Option<String>,
    #[serde(alias = "HiddenRecord")]
    pub hidden_record: Option<bool>,
}

/// USB-related event IDs we care about
pub const USB_PNP_EVENT_IDS: &[i32] = &[20001, 20003]; // System log
pub const FILE_AUDIT_EVENT_IDS: &[i32] = &[4656, 4660, 4663]; // Security log
pub const DRIVER_FRAMEWORK_EVENT_IDS: &[i32] = &[2003, 2100, 2101]; // DriverFrameworks
pub const LOGON_EVENT_IDS: &[i32] = &[4624, 4634]; // Security log - session correlation
