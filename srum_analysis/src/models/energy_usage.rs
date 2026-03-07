use serde::{Deserialize, Serialize};

/// EnergyUsage record from SrumECmd CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyUsage {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ExeInfo", alias = "Exe Info", alias = "Application_Path", alias = "App", alias = "exe_info")]
    pub exe_info: Option<String>,

    #[serde(alias = "UserSid", alias = "User SID", alias = "User_SID", alias = "SID", alias = "Sid", alias = "user_sid")]
    pub user_sid: Option<String>,

    #[serde(alias = "UserName", alias = "User Name", alias = "User_Name", alias = "user_name")]
    pub user_name: Option<String>,

    #[serde(alias = "ChargeLevel", alias = "Charge Level", alias = "Charge_Level", alias = "charge_level", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub charge_level: Option<u64>,

    #[serde(alias = "DesignedCapacity", alias = "Designed Capacity", alias = "Designed_Capacity", alias = "designed_capacity", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub designed_capacity: Option<u64>,

    #[serde(alias = "FullChargedCapacity", alias = "Full Charged Capacity", alias = "Full_Charged_Capacity", alias = "full_charged_capacity", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub full_charged_capacity: Option<u64>,

    #[serde(alias = "CycleCount", alias = "Cycle Count", alias = "Cycle_Count", alias = "cycle_count", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub cycle_count: Option<u64>,
}
