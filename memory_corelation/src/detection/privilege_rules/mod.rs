//! Privilege Rules detection rules

pub mod priv001_debug_privilege_abuse;
pub mod priv002_tcb_privilege_abuse;
pub mod priv003_load_driver_privilege_abuse;
pub mod priv004_multi_dangerous_privilege;
pub mod priv005_impersonate_privilege_abuse;

pub use priv001_debug_privilege_abuse::DebugPrivilegeAbuseRule;
pub use priv002_tcb_privilege_abuse::TcbPrivilegeAbuseRule;
pub use priv003_load_driver_privilege_abuse::LoadDriverPrivilegeAbuseRule;
pub use priv004_multi_dangerous_privilege::MultiDangerousPrivilegeRule;
pub use priv005_impersonate_privilege_abuse::ImpersonatePrivilegeAbuseRule;
