use serde::{Deserialize, Serialize};

/// AppResourceUsageInfo record from SrumECmd CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppResourceUsage {
    #[serde(alias = "Timestamp", alias = "TIMESTAMP", alias = "timestamp")]
    pub timestamp: Option<String>,

    #[serde(alias = "ExeInfo", alias = "Exe Info", alias = "Application_Path", alias = "App", alias = "exe_info")]
    pub exe_info: Option<String>,

    #[serde(alias = "ExeInfoDescription", alias = "Exe Info Description", alias = "exe_info_description")]
    pub exe_info_description: Option<String>,

    #[serde(alias = "UserSid", alias = "User SID", alias = "User_SID", alias = "SID", alias = "Sid", alias = "user_sid")]
    pub user_sid: Option<String>,

    #[serde(alias = "UserName", alias = "User Name", alias = "User_Name", alias = "user_name")]
    pub user_name: Option<String>,

    #[serde(alias = "ForegroundCycleTime", alias = "Foreground Cycle Time", alias = "CPU_Foreground_Time", alias = "foreground_cycle_time", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub foreground_cycle_time: Option<u64>,

    #[serde(alias = "BackgroundCycleTime", alias = "Background Cycle Time", alias = "CPU_Background_Time", alias = "background_cycle_time", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub background_cycle_time: Option<u64>,

    #[serde(alias = "FaceTime", alias = "Face Time", alias = "face_time", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub face_time: Option<u64>,

    #[serde(alias = "ForegroundBytesRead", alias = "Foreground Bytes Read", alias = "I/O_Bytes_Read_Foreground", alias = "foreground_bytes_read", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub foreground_bytes_read: Option<u64>,

    #[serde(alias = "ForegroundBytesWritten", alias = "Foreground Bytes Written", alias = "I/O_Bytes_Written_Foreground", alias = "foreground_bytes_written", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub foreground_bytes_written: Option<u64>,

    #[serde(alias = "BackgroundBytesRead", alias = "Background Bytes Read", alias = "I/O_Bytes_Read_Background", alias = "background_bytes_read", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub background_bytes_read: Option<u64>,

    #[serde(alias = "BackgroundBytesWritten", alias = "Background Bytes Written", alias = "I/O_Bytes_Written_Background", alias = "background_bytes_written", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub background_bytes_written: Option<u64>,
}

impl AppResourceUsage {
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

    /// Get total bytes written (foreground + background)
    pub fn total_bytes_written(&self) -> u64 {
        self.foreground_bytes_written.unwrap_or(0) + self.background_bytes_written.unwrap_or(0)
    }

    /// Get total bytes read (foreground + background)
    pub fn total_bytes_read(&self) -> u64 {
        self.foreground_bytes_read.unwrap_or(0) + self.background_bytes_read.unwrap_or(0)
    }

    /// Get total CPU cycle time
    pub fn total_cycle_time(&self) -> u64 {
        self.foreground_cycle_time.unwrap_or(0) + self.background_cycle_time.unwrap_or(0)
    }
}
