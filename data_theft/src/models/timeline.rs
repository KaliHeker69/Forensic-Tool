/// Timeline event model for unified timeline generation
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub source_artifact: String,
    pub description: String,
    pub details: Option<String>,
    pub device_serial: Option<String>,
    pub file_path: Option<String>,
    pub user: Option<String>,
    pub reliability: Reliability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineEventType {
    UsbFirstConnected,
    UsbConnected,
    UsbDisconnected,
    FileCreated,
    FileModified,
    FileAccessed,
    FileDeleted,
    FileRenamed,
    FileCopied,
    FolderBrowsed,
    ApplicationExecuted,
    UserLogon,
    UserLogoff,
    DriverInstalled,
}

impl std::fmt::Display for TimelineEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineEventType::UsbFirstConnected => write!(f, "USB First Connected"),
            TimelineEventType::UsbConnected => write!(f, "USB Connected"),
            TimelineEventType::UsbDisconnected => write!(f, "USB Disconnected"),
            TimelineEventType::FileCreated => write!(f, "File Created"),
            TimelineEventType::FileModified => write!(f, "File Modified"),
            TimelineEventType::FileAccessed => write!(f, "File Accessed"),
            TimelineEventType::FileDeleted => write!(f, "File Deleted"),
            TimelineEventType::FileRenamed => write!(f, "File Renamed"),
            TimelineEventType::FileCopied => write!(f, "File Copied"),
            TimelineEventType::FolderBrowsed => write!(f, "Folder Browsed"),
            TimelineEventType::ApplicationExecuted => write!(f, "Application Executed"),
            TimelineEventType::UserLogon => write!(f, "User Logon"),
            TimelineEventType::UserLogoff => write!(f, "User Logoff"),
            TimelineEventType::DriverInstalled => write!(f, "Driver Installed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reliability {
    VeryHigh,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Reliability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reliability::VeryHigh => write!(f, "Very High"),
            Reliability::High => write!(f, "High"),
            Reliability::Medium => write!(f, "Medium"),
            Reliability::Low => write!(f, "Low"),
        }
    }
}
