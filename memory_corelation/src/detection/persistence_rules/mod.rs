//! Persistence Rules detection rules

pub mod pers001_registry_persistence;
pub mod pers002_suspicious_service;
pub mod pers003_suspicious_scheduled_task;

pub use pers001_registry_persistence::RegistryPersistenceRule;
pub use pers002_suspicious_service::SuspiciousServiceRule;
pub use pers003_suspicious_scheduled_task::SuspiciousScheduledTaskRule;
