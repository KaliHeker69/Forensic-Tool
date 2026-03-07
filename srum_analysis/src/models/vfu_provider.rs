use serde::{Deserialize, Serialize};

/// VfuProvider (vfuprov) record from SrumECmd CSV
///
/// Tracks Windows Volume Shadow / WFP (Windows Filtering Platform) provider activity.
/// Fields (SrumECmd no-SOFTWARE export):
///   Id, Timestamp, UserId, AppId, ExeInfo, ExeInfoDescription, ExeTimestamp,
///   SidType, Sid, UserName, StartTime, EndTime, Flags, Duration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfuProvider {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ExeInfo", alias = "Exe Info", alias = "exe_info")]
    pub exe_info: Option<String>,

    #[serde(alias = "ExeInfoDescription", alias = "Exe Info Description", alias = "exe_info_description")]
    pub exe_info_description: Option<String>,

    #[serde(alias = "UserSid", alias = "User SID", alias = "User_SID", alias = "SID", alias = "Sid", alias = "user_sid")]
    pub user_sid: Option<String>,

    #[serde(alias = "UserName", alias = "User Name", alias = "User_Name", alias = "user_name")]
    pub user_name: Option<String>,

    #[serde(alias = "StartTime", alias = "Start Time", alias = "start_time")]
    pub start_time: Option<String>,

    #[serde(alias = "EndTime", alias = "End Time", alias = "end_time")]
    pub end_time: Option<String>,

    #[serde(alias = "Flags", alias = "flags")]
    pub flags: Option<String>,

    #[serde(alias = "Duration", alias = "duration")]
    pub duration: Option<String>,
}

impl VfuProvider {
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
}
