//! Data models for Volatility3 plugin outputs

pub mod browser;
pub mod certificates;
pub mod files;
pub mod forensic_metadata;
pub mod malware;
pub mod mft;
pub mod network;
pub mod process;
pub mod registry;
pub mod security;
pub mod services;
pub mod threads;

use chrono::{DateTime, Utc};

pub use forensic_metadata::{
    AnalysisMethodology, AnalystQuickView, ChainOfCustody, EnvironmentSummary, HandleSummary,
    SessionInfo, SystemProfile, UserActivityEvidence, VolatilityInfo,
};
use serde::{Deserialize, Serialize};

/// Unified event for timeline building
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source_plugin: String,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub related_ips: Vec<String>,
    pub related_files: Vec<String>,
    pub risk_score: u8,
}

/// Types of events in the unified timeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessCreated,
    ProcessTerminated,
    NetworkConnection,
    NetworkListen,
    FileAccess,
    FileDownload,
    BrowserVisit,
    RegistryModification,
    ServiceCreated,
    DriverLoaded,
    InjectionDetected,
    SuspiciousActivity,
    DllLoaded,
    MftCreated,
    MftModified,
    UserAssistExecution,
    ScheduledTask,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::ProcessCreated => write!(f, "Process Created"),
            EventType::ProcessTerminated => write!(f, "Process Terminated"),
            EventType::NetworkConnection => write!(f, "Network Connection"),
            EventType::NetworkListen => write!(f, "Network Listen"),
            EventType::FileAccess => write!(f, "File Access"),
            EventType::FileDownload => write!(f, "File Download"),
            EventType::BrowserVisit => write!(f, "Browser Visit"),
            EventType::RegistryModification => write!(f, "Registry Modification"),
            EventType::ServiceCreated => write!(f, "Service Created"),
            EventType::DriverLoaded => write!(f, "Driver Loaded"),
            EventType::InjectionDetected => write!(f, "Injection Detected"),
            EventType::SuspiciousActivity => write!(f, "Suspicious Activity"),
            EventType::DllLoaded => write!(f, "DLL Loaded"),
            EventType::MftCreated => write!(f, "MFT File Created"),
            EventType::MftModified => write!(f, "MFT File Modified"),
            EventType::UserAssistExecution => write!(f, "Program Executed"),
            EventType::ScheduledTask => write!(f, "Scheduled Task"),
        }
    }
}

/// Trait for types that can provide timestamp information
pub trait Timestamped {
    fn timestamp(&self) -> Option<DateTime<Utc>>;
}

/// Trait for types that are associated with a process
pub trait ProcessAssociated {
    fn pid(&self) -> Option<u32>;
    fn process_name(&self) -> Option<&str>;
}
