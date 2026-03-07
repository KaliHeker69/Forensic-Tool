//! Process Rules detection rules

pub mod proc001_orphaned_process;
pub mod proc002_suspicious_parent_child;
pub mod proc003_encoded_command_line;
pub mod proc004_svchost_anomaly;
pub mod proc005_suspicious_dll_path;
pub mod proc006_advanced_command_line;
pub mod proc010_system_process_masquerading;

pub use proc001_orphaned_process::OrphanedProcessRule;
pub use proc002_suspicious_parent_child::SuspiciousParentChildRule;
pub use proc003_encoded_command_line::EncodedCommandLineRule;
pub use proc004_svchost_anomaly::SvchostAnomalyRule;
pub use proc005_suspicious_dll_path::SuspiciousDllPathRule;
pub use proc006_advanced_command_line::AdvancedCommandLineRule;
pub use proc010_system_process_masquerading::SystemProcessMasqueradingRule;
