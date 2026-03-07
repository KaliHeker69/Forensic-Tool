use serde::{Deserialize, Serialize};

/// PushNotification record from SrumECmd CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotification {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ExeInfo", alias = "Exe Info", alias = "Application_Path", alias = "App", alias = "exe_info")]
    pub exe_info: Option<String>,

    #[serde(alias = "UserSid", alias = "User SID", alias = "User_SID", alias = "SID", alias = "Sid", alias = "user_sid")]
    pub user_sid: Option<String>,

    #[serde(alias = "UserName", alias = "User Name", alias = "User_Name", alias = "user_name")]
    pub user_name: Option<String>,

    #[serde(alias = "NotificationType", alias = "Notification Type", alias = "Notification_Type", alias = "notification_type")]
    pub notification_type: Option<String>,

    #[serde(alias = "PayloadSize", alias = "Payload Size", alias = "Payload_Size", alias = "payload_size", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub payload_size: Option<u64>,

    #[serde(alias = "NetworkType", alias = "Network Type", alias = "Network_Type", alias = "network_type")]
    pub network_type: Option<String>,
}
