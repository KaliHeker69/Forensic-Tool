use serde::{Deserialize, Serialize};

/// NetworkConnections record from SrumECmd CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ConnectedTime", alias = "Connected Time", alias = "Connected_Time", alias = "connected_time", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub connected_time: Option<u64>,

    #[serde(alias = "ConnectStartTime", alias = "Connect Start Time", alias = "ConnectStart", alias = "Connect_Start_Time", alias = "connect_start_time")]
    pub connect_start_time: Option<String>,

    #[serde(alias = "InterfaceLuid", alias = "Interface Luid", alias = "Interface_Luid", alias = "interface_luid")]
    pub interface_luid: Option<String>,

    #[serde(alias = "InterfaceType", alias = "Interface Type", alias = "Interface_Type", alias = "interface_type")]
    pub interface_type: Option<String>,

    #[serde(alias = "L2ProfileId", alias = "L2 Profile Id", alias = "L2_Profile_Id", alias = "ProfileId", alias = "l2_profile_id")]
    pub l2_profile_id: Option<String>,

    #[serde(alias = "L2ProfileFlags", alias = "L2 Profile Flags", alias = "L2_Profile_Flags", alias = "l2_profile_flags")]
    pub l2_profile_flags: Option<String>,
}
