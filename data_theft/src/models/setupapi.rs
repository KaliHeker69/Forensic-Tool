/// Setupapi.dev.log parsing models
use serde::{Deserialize, Serialize};

/// Parsed entry from setupapi.dev.log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupapiEntry {
    pub timestamp: Option<String>,
    pub device_description: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub section_name: Option<String>,
    pub driver_status: Option<String>,
    pub raw_line: String,
}
