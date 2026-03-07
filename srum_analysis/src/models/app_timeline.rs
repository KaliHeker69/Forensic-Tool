use serde::{Deserialize, Serialize};

/// AppTimelineProvider record from SrumECmd CSV
///
/// Tracks application foreground/background timeline activity.
/// Fields (SrumECmd no-SOFTWARE export):
///   Id, Timestamp, ExeInfo, ExeInfoDescription, ExeTimestamp,
///   SidType, Sid, UserName, UserId, AppId, EndTime, DurationMs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTimeline {
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

    #[serde(alias = "EndTime", alias = "End Time", alias = "end_time")]
    pub end_time: Option<String>,

    #[serde(alias = "DurationMs", alias = "Duration Ms", alias = "duration_ms", default, deserialize_with = "crate::models::common::de_opt_u64_srum")]
    pub duration_ms: Option<u64>,
}

impl AppTimeline {
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

    /// Duration in human-readable form
    pub fn duration_display(&self) -> String {
        match self.duration_ms {
            Some(ms) if ms > 0 => {
                let secs = ms / 1000;
                let mins = secs / 60;
                let hours = mins / 60;
                if hours > 0 {
                    format!("{}h {}m {}s", hours, mins % 60, secs % 60)
                } else if mins > 0 {
                    format!("{}m {}s", mins, secs % 60)
                } else {
                    format!("{}.{}s", secs, (ms % 1000) / 100)
                }
            }
            _ => "N/A".to_string(),
        }
    }
}
