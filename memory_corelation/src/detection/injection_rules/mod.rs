//! Injection Rules detection rules

pub mod inj001_malfind;
pub mod inj002_rwx_memory;
pub mod inj003_mz_header;
pub mod inj004_process_injection_cmdline;
pub mod inj005_vad_injection;
pub mod inj006_malfind_strings;
pub mod inj007_ldrmodules_hidden_module;

pub use inj001_malfind::MalfindDetectionRule;
pub use inj002_rwx_memory::RwxMemoryRule;
pub use inj003_mz_header::MzHeaderRule;
pub use inj004_process_injection_cmdline::ProcessInjectionCmdlineRule;
pub use inj005_vad_injection::VadInjectionRule;
pub use inj006_malfind_strings::MalfindStringExtractionRule;
pub use inj007_ldrmodules_hidden_module::LdrModulesHiddenModuleRule;
