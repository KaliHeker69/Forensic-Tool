//! Integrity Rules detection rules

pub mod integ001_hidden_process;
pub mod integ002_hidden_hive;
pub mod integ003_timestamp_anomaly;
pub mod integ004_suspicious_kernel_module_path;
pub mod integ005_system_info_anomaly;
pub mod integ006_idt_hook_anomaly;
pub mod integ007_driverirp_hook_anomaly;
pub mod integ008_suspicious_atoms;

pub use integ001_hidden_process::HiddenProcessRule;
pub use integ002_hidden_hive::HiddenHiveRule;
pub use integ003_timestamp_anomaly::TimestampAnomalyRule;
pub use integ004_suspicious_kernel_module_path::SuspiciousKernelModulePathRule;
pub use integ005_system_info_anomaly::SystemInfoAnomalyRule;
pub use integ006_idt_hook_anomaly::IdtHookAnomalyRule;
pub use integ007_driverirp_hook_anomaly::DriverIrpHookAnomalyRule;
pub use integ008_suspicious_atoms::SuspiciousAtomPatternRule;
