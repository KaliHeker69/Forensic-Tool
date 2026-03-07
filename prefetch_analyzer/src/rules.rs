//! External Rules Loader
//!
//! Loads detection rules from the external YAML configuration file.

use crate::models::Severity;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Root configuration from rules.yaml
#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub malicious_tools: Vec<ExecutableRule>,
    #[serde(default)]
    pub lolbins: Vec<ExecutableRule>,
    #[serde(default)]
    pub ransomware_tools: Vec<ExecutableRule>,
    #[serde(default)]
    pub suspicious_paths: Vec<PathRule>,
    #[serde(default)]
    pub suspicious_dlls: Vec<DllRule>,
    #[serde(default)]
    pub whitelist: Whitelist,
    #[serde(default)]
    pub installer_executables: Vec<String>,
    #[serde(default)]
    pub installer_dll_patterns: Vec<String>,
}

impl RulesConfig {
    /// Load rules from a YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read rules file: {:?}", path.as_ref()))?;
        
        let config: RulesConfig = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse rules YAML")?;
        
        Ok(config)
    }

    /// Load from embedded default rules if external file not found
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::load(path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Warning: Could not load external rules ({}). Using embedded defaults.", e);
                Self::default()
            }
        }
    }

    /// Get all executable rules combined
    pub fn all_executable_rules(&self) -> Vec<&ExecutableRule> {
        let mut rules = Vec::new();
        rules.extend(self.malicious_tools.iter());
        rules.extend(self.lolbins.iter());
        rules.extend(self.ransomware_tools.iter());
        rules
    }

    /// Check if a path should be whitelisted
    pub fn is_path_whitelisted(&self, path: &str) -> bool {
        let upper = path.to_uppercase();
        self.whitelist.paths.iter().any(|p| upper.contains(&p.to_uppercase()))
    }

    /// Check if an executable should be whitelisted
    pub fn is_executable_whitelisted(&self, exe: &str) -> bool {
        let upper = exe.to_uppercase();
        self.whitelist.executables.iter().any(|e| e.to_uppercase() == upper)
    }

    /// Check if an executable is a known installer
    pub fn is_installer(&self, exe: &str) -> bool {
        let upper = exe.to_uppercase();
        self.installer_executables.iter().any(|p| upper.contains(&p.to_uppercase()))
    }

    /// Check if a DLL is a known installer/runtime DLL
    pub fn is_installer_dll(&self, dll_path: &str) -> bool {
        let upper = dll_path.to_uppercase();
        self.installer_dll_patterns.iter().any(|p| upper.contains(&p.to_uppercase()))
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        // Minimal embedded defaults
        Self {
            malicious_tools: vec![
                ExecutableRule {
                    name: "Mimikatz".to_string(),
                    patterns: vec!["MIMIKATZ".to_string()],
                    severity: SeverityString::Critical,
                    category: "Credential Theft".to_string(),
                    mitre_id: "T1003".to_string(),
                    mitre_name: "OS Credential Dumping".to_string(),
                    description: "Credential theft tool detected".to_string(),
                },
                ExecutableRule {
                    name: "PsExec".to_string(),
                    patterns: vec!["PSEXEC".to_string(), "PSEXEC64".to_string()],
                    severity: SeverityString::High,
                    category: "Lateral Movement".to_string(),
                    mitre_id: "T1570".to_string(),
                    mitre_name: "Lateral Tool Transfer".to_string(),
                    description: "Remote execution tool".to_string(),
                },
            ],
            lolbins: vec![
                ExecutableRule {
                    name: "PowerShell".to_string(),
                    patterns: vec!["POWERSHELL.EXE".to_string()],
                    severity: SeverityString::Medium,
                    category: "Script Engine".to_string(),
                    mitre_id: "T1059.001".to_string(),
                    mitre_name: "PowerShell".to_string(),
                    description: "PowerShell execution".to_string(),
                },
            ],
            ransomware_tools: vec![
                ExecutableRule {
                    name: "VSSAdmin".to_string(),
                    patterns: vec!["VSSADMIN.EXE".to_string()],
                    severity: SeverityString::Critical,
                    category: "Ransomware".to_string(),
                    mitre_id: "T1490".to_string(),
                    mitre_name: "Inhibit System Recovery".to_string(),
                    description: "Shadow copy manipulation".to_string(),
                },
            ],
            suspicious_paths: vec![
                PathRule {
                    pattern: "\\TEMP\\".to_string(),
                    severity: SeverityString::High,
                    description: "Execution from Temp directory".to_string(),
                },
            ],
            suspicious_dlls: vec![
                DllRule {
                    pattern: "MIMILIB.DLL".to_string(),
                    severity: SeverityString::Critical,
                    description: "Mimikatz library detected".to_string(),
                },
            ],
            whitelist: Whitelist::default(),
            installer_executables: vec![
                "VCREDIST".to_string(),
                "SETUP.EXE".to_string(),
                "MSIEXEC.EXE".to_string(),
                "MICROSOFTEDGEUPDATE".to_string(),
            ],
            installer_dll_patterns: vec![
                "MSVCP".to_string(),
                "VCRUNTIME".to_string(),
                "API-MS-WIN".to_string(),
                "WIXSTDBA".to_string(),
            ],
        }
    }
}

/// Detection rule for executables (from YAML)
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutableRule {
    pub name: String,
    pub patterns: Vec<String>,
    pub severity: SeverityString,
    pub category: String,
    pub mitre_id: String,
    pub mitre_name: String,
    pub description: String,
}

impl ExecutableRule {
    /// Check if an executable name matches this rule
    pub fn matches(&self, executable: &str) -> bool {
        let upper = executable.to_uppercase();
        self.patterns.iter().any(|p| upper.contains(&p.to_uppercase()))
    }

    /// Get severity as enum
    pub fn get_severity(&self) -> Severity {
        self.severity.to_severity()
    }
}

/// Detection rule for suspicious paths
#[derive(Debug, Clone, Deserialize)]
pub struct PathRule {
    pub pattern: String,
    pub severity: SeverityString,
    pub description: String,
}

impl PathRule {
    /// Check if a path matches this rule (simple contains for now)
    pub fn matches(&self, path: &str) -> bool {
        let upper_path = path.to_uppercase();
        let pattern = self.pattern.to_uppercase().replace("*", "");
        upper_path.contains(&pattern)
    }

    pub fn get_severity(&self) -> Severity {
        self.severity.to_severity()
    }
}

/// Detection rule for suspicious DLLs
#[derive(Debug, Clone, Deserialize)]
pub struct DllRule {
    pub pattern: String,
    pub severity: SeverityString,
    pub description: String,
}

impl DllRule {
    /// Check if a DLL path matches this rule
    pub fn matches(&self, dll_path: &str) -> bool {
        let upper_path = dll_path.to_uppercase();
        let pattern = self.pattern.to_uppercase()
            .replace("*", "")
            .replace(".DLL", "");
        upper_path.contains(&pattern) && upper_path.ends_with(".DLL")
    }

    pub fn get_severity(&self) -> Severity {
        self.severity.to_severity()
    }
}

/// Whitelist configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Whitelist {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub executables: Vec<String>,
}

/// Severity as string for YAML parsing
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityString {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityString {
    pub fn to_severity(&self) -> Severity {
        match self {
            SeverityString::Critical => Severity::Critical,
            SeverityString::High => Severity::High,
            SeverityString::Medium => Severity::Medium,
            SeverityString::Low => Severity::Low,
            SeverityString::Info => Severity::Info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executable_rule_match() {
        let rule = ExecutableRule {
            name: "Test".to_string(),
            patterns: vec!["MIMIKATZ".to_string()],
            severity: SeverityString::Critical,
            category: "Test".to_string(),
            mitre_id: "T1003".to_string(),
            mitre_name: "Test".to_string(),
            description: "Test".to_string(),
        };
        
        assert!(rule.matches("mimikatz.exe"));
        assert!(rule.matches("MIMIKATZ.EXE"));
        assert!(!rule.matches("notepad.exe"));
    }

    #[test]
    fn test_path_rule_match() {
        let rule = PathRule {
            pattern: "\\TEMP\\".to_string(),
            severity: SeverityString::High,
            description: "Test".to_string(),
        };
        
        assert!(rule.matches("C:\\Windows\\Temp\\evil.exe"));
        assert!(rule.matches("C:\\Users\\user\\AppData\\Local\\Temp\\test.exe"));
        assert!(!rule.matches("C:\\Program Files\\app.exe"));
    }
}
