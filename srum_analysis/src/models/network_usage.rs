use serde::{Deserialize, Serialize};

/// NetworkUsages record from SrumECmd CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkUsage {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ExeInfo", alias = "Exe Info", alias = "Executable_Information", alias = "Application_Path", alias = "App", alias = "exe_info")]
    pub exe_info: Option<String>,

    #[serde(alias = "ExeInfoDescription", alias = "Exe Info Description", alias = "exe_info_description")]
    pub exe_info_description: Option<String>,

    #[serde(alias = "UserSid", alias = "User SID", alias = "User_SID", alias = "SID", alias = "Sid", alias = "user_sid")]
    pub user_sid: Option<String>,

    #[serde(alias = "UserName", alias = "User Name", alias = "User_Name", alias = "user_name")]
    pub user_name: Option<String>,

    #[serde(alias = "BytesSent", alias = "Bytes Sent", alias = "Bytes_Sent", alias = "bytes_sent", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub bytes_sent: Option<u64>,

    #[serde(alias = "BytesRecvd", alias = "Bytes Recvd", alias = "BytesReceived", alias = "Bytes Received", alias = "Bytes_Received", alias = "bytes_recvd", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub bytes_recvd: Option<u64>,

    #[serde(alias = "InterfaceType", alias = "Interface Type", alias = "Interface_Type", alias = "interface_type")]
    pub interface_type: Option<String>,

    #[serde(alias = "L2ProfileId", alias = "L2 Profile Id", alias = "L2_Profile_Id", alias = "ProfileId", alias = "l2_profile_id")]
    pub l2_profile_id: Option<String>,

    #[serde(alias = "InterfaceLuid", alias = "Interface Luid", alias = "Interface_Luid", alias = "interface_luid")]
    pub interface_luid: Option<String>,
}

impl NetworkUsage {
    /// Get the application name from the path
    pub fn app_name(&self) -> String {
        self.exe_info
            .as_deref()
            .map(|p| {
                p.rsplit(&['\\', '/'])
                    .next()
                    .unwrap_or(p)
                    .to_string()
            })
            .unwrap_or_else(|| "Unknown".to_string())
    }

    /// Check if this is a wireless connection
    pub fn is_wireless(&self) -> bool {
        self.interface_type
            .as_deref()
            .map(|t| t.to_uppercase().contains("IEEE80211") || t.to_uppercase().contains("WIRELESS") || t.to_uppercase().contains("WIFI"))
            .unwrap_or(false)
    }

    /// Check if this is a wired connection
    pub fn is_wired(&self) -> bool {
        self.interface_type
            .as_deref()
            .map(|t| t.to_uppercase().contains("CSMACD") || t.to_uppercase().contains("ETHERNET"))
            .unwrap_or(false)
    }
}
