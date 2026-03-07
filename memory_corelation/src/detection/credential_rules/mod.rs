//! Credential Rules detection rules

pub mod cred001_lsass_handle;
pub mod cred002_lsass_dll_injection;
pub mod cred003_sensitive_process_injection;
pub mod cred004_suspicious_console_command;
pub mod cred005_cached_credential_artifact;
pub mod cred006_lsass_targeting;
pub mod hndl001_handle_mutex;

pub use cred001_lsass_handle::LsassHandleRule;
pub use cred002_lsass_dll_injection::LsassDllInjectionRule;
pub use cred003_sensitive_process_injection::SensitiveProcessInjectionRule;
pub use cred004_suspicious_console_command::SuspiciousConsoleCommandRule;
pub use cred005_cached_credential_artifact::CachedCredentialArtifactRule;
pub use cred006_lsass_targeting::LsassTargetingRule;
pub use hndl001_handle_mutex::HandleMutexAnalysisRule;
