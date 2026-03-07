//! Mft Rules detection rules

pub mod mft001_executables_in_temp;
pub mod mft002_double_extension;
pub mod mft003_alternate_data_stream;
pub mod mft004_system_file_mimicry;
pub mod mft005_deleted_executable;
pub mod mft006_suspicious_script_file;
pub mod mft007_timestomping;

pub use mft001_executables_in_temp::ExecutablesInTempRule;
pub use mft002_double_extension::DoubleExtensionRule;
pub use mft003_alternate_data_stream::AlternateDataStreamRule;
pub use mft004_system_file_mimicry::SystemFileMimicryRule;
pub use mft005_deleted_executable::DeletedExecutableRule;
pub use mft006_suspicious_script_file::SuspiciousScriptFileRule;
pub use mft007_timestomping::TimestompingDetectionRule;
