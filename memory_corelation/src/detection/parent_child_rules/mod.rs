//! Parent Child Rules detection rules

pub mod proc007_suspicious_parent;
pub mod proc008_lsass_parent;
pub mod proc009_duplicate_system_process;

pub use proc007_suspicious_parent::SuspiciousParentRule;
pub use proc008_lsass_parent::LsassParentRule;
pub use proc009_duplicate_system_process::DuplicateSystemProcessRule;
