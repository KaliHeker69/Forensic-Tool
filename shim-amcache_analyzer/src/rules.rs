//! Rules loader for detection patterns

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

/// Raw rule pattern from YAML
#[derive(Debug, Deserialize)]
pub struct RulePattern {
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

/// Raw rules configuration from YAML
#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub suspicious_paths: Vec<RulePattern>,
    #[serde(default)]
    pub suspicious_filenames: Vec<RulePattern>,
    #[serde(default)]
    pub trusted_paths: Vec<RulePattern>,
    #[serde(default)]
    pub trusted_publishers: Vec<String>,
    #[serde(default)]
    pub system_executables: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub risky_temp_paths: Vec<String>,
    #[serde(default)]
    pub legitimate_temp_executables: Vec<RulePattern>,
    #[serde(default)]
    pub legitimate_download_executables: Vec<RulePattern>,
    #[serde(default)]
    pub executable_extensions: Vec<String>,
}

/// Compiled rules with regex patterns
pub struct CompiledRules {
    pub suspicious_paths: Vec<(Regex, String)>,
    pub suspicious_filenames: Vec<(Regex, String)>,
    pub trusted_paths: Vec<Regex>,
    pub trusted_publishers: Vec<String>,
    pub system_executables: HashMap<String, Vec<Regex>>,
    pub risky_temp_paths: Vec<String>,
    pub legitimate_temp_executables: Vec<(Regex, String)>,
    pub legitimate_download_executables: Vec<(Regex, String)>,
    pub executable_extensions: Vec<String>,
}

impl Default for CompiledRules {
    fn default() -> Self {
        Self::builtin()
    }
}

impl CompiledRules {
    fn normalize_path_for_matching(path: &str) -> String {
        let mut normalized = path.to_lowercase().replace('/', "\\");
        if let Some(stripped) = normalized.strip_prefix("\\\\?\\") {
            normalized = stripped.to_string();
        }
        if let Some(stripped) = normalized.strip_prefix("\\??\\") {
            normalized = stripped.to_string();
        }
        normalized
    }

    /// Load rules from a YAML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rules file: {}", path.display()))?;
        Self::from_yaml(&content)
    }

    /// Parse rules from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let config: RulesConfig = serde_yaml::from_str(yaml)
            .context("Failed to parse rules YAML")?;
        Self::compile(config)
    }

    /// Compile raw rules into regex patterns
    fn compile(config: RulesConfig) -> Result<Self> {
        let mut suspicious_paths = Vec::new();
        for rule in config.suspicious_paths {
            let regex = Regex::new(&format!("(?i){}", rule.pattern))
                .with_context(|| format!("Invalid suspicious_paths regex: {}", rule.pattern))?;
            suspicious_paths.push((regex, rule.description));
        }

        let mut suspicious_filenames = Vec::new();
        for rule in config.suspicious_filenames {
            let regex = Regex::new(&format!("(?i){}", rule.pattern))
                .with_context(|| format!("Invalid suspicious_filenames regex: {}", rule.pattern))?;
            suspicious_filenames.push((regex, rule.description));
        }

        let mut trusted_paths = Vec::new();
        for rule in config.trusted_paths {
            let regex = Regex::new(&format!("(?i){}", rule.pattern))
                .with_context(|| format!("Invalid trusted_paths regex: {}", rule.pattern))?;
            trusted_paths.push(regex);
        }

        let mut system_executables = HashMap::new();
        for (exe, paths) in config.system_executables {
            let mut regexes = Vec::new();
            for path in paths {
                let regex = Regex::new(&format!("(?i){}", path))
                    .with_context(|| format!("Invalid system_executables regex for {}: {}", exe, path))?;
                regexes.push(regex);
            }
            system_executables.insert(exe.to_lowercase(), regexes);
        }

        let mut legitimate_temp_executables = Vec::new();
        for rule in config.legitimate_temp_executables {
            let regex = Regex::new(&format!("(?i){}", rule.pattern))
                .with_context(|| format!("Invalid legitimate_temp_executables regex: {}", rule.pattern))?;
            legitimate_temp_executables.push((regex, rule.description));
        }

        let mut legitimate_download_executables = Vec::new();
        for rule in config.legitimate_download_executables {
            let regex = Regex::new(&format!("(?i){}", rule.pattern))
                .with_context(|| format!("Invalid legitimate_download_executables regex: {}", rule.pattern))?;
            legitimate_download_executables.push((regex, rule.description));
        }

        Ok(Self {
            suspicious_paths,
            suspicious_filenames,
            trusted_paths,
            trusted_publishers: config.trusted_publishers.into_iter().map(|s| s.to_lowercase()).collect(),
            system_executables,
            risky_temp_paths: config.risky_temp_paths,
            legitimate_temp_executables,
            legitimate_download_executables,
            executable_extensions: config.executable_extensions,
        })
    }

    /// Get built-in default rules
    pub fn builtin() -> Self {
        let yaml = include_str!("../rules.yaml");
        Self::from_yaml(yaml).expect("Built-in rules should always be valid")
    }

    /// Check if path is trusted
    pub fn is_trusted_path(&self, path: &str) -> bool {
        let path_norm = Self::normalize_path_for_matching(path);
        self.trusted_paths.iter().any(|p| p.is_match(&path_norm))
    }

    /// Check if publisher is trusted
    pub fn is_trusted_publisher(&self, company: Option<&str>, product: Option<&str>) -> bool {
        if let Some(company) = company {
            let company_lower = company.to_lowercase();
            if self.trusted_publishers.iter().any(|p| company_lower.contains(p)) {
                return true;
            }
        }
        if let Some(product) = product {
            let product_lower = product.to_lowercase();
            if self.trusted_publishers.iter().any(|p| product_lower.contains(p)) {
                return true;
            }
        }
        false
    }

    /// Check if extension is executable
    pub fn is_executable_extension(&self, ext: &str) -> bool {
        self.executable_extensions.iter().any(|e| e == ext)
    }

    /// Check suspicious path and return description if matched
    pub fn check_suspicious_path(&self, path: &str) -> Option<&str> {
        let path_lower = Self::normalize_path_for_matching(path);
        for (regex, desc) in &self.suspicious_paths {
            if regex.is_match(&path_lower) {
                return Some(desc.as_str());
            }
        }
        None
    }

    /// Check suspicious filename and return description if matched
    pub fn check_suspicious_filename(&self, filename: &str) -> Option<&str> {
        for (regex, desc) in &self.suspicious_filenames {
            if regex.is_match(filename) {
                return Some(desc.as_str());
            }
        }
        None
    }

    /// Check if system executable is in valid path
    pub fn check_system_executable(&self, filename: &str, path: &str) -> Option<bool> {
        let filename_lower = filename.to_lowercase();
        if let Some(valid_paths) = self.system_executables.get(&filename_lower) {
            let path_norm = Self::normalize_path_for_matching(path);
            let in_valid = valid_paths.iter().any(|p| p.is_match(&path_norm));
            Some(in_valid)
        } else {
            None // Not a monitored system executable
        }
    }

    /// Check if path is in risky temp location
    pub fn is_risky_temp_path(&self, path: &str) -> bool {
        let path_lower = Self::normalize_path_for_matching(path);
        self.risky_temp_paths.iter().any(|p| path_lower.contains(p))
    }

    /// Check if path is a legitimate temp executable (Windows system files that run from temp)
    pub fn is_legitimate_temp_executable(&self, path: &str) -> bool {
        let path_lower = Self::normalize_path_for_matching(path);
        self.legitimate_temp_executables.iter().any(|(regex, _)| regex.is_match(&path_lower))
    }

    /// Check if path is a legitimate executable under Downloads (forensics/admin tooling)
    pub fn is_legitimate_download_executable(&self, path: &str) -> bool {
        let path_lower = Self::normalize_path_for_matching(path);
        self.legitimate_download_executables
            .iter()
            .any(|(regex, _)| regex.is_match(&path_lower))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_rules() {
        let rules = CompiledRules::builtin();
        assert!(!rules.suspicious_paths.is_empty());
        assert!(!rules.trusted_paths.is_empty());
        assert!(!rules.trusted_publishers.is_empty());
    }

    #[test]
    fn test_trusted_path() {
        let rules = CompiledRules::builtin();
        assert!(rules.is_trusted_path("C:\\Windows\\System32\\notepad.exe"));
        assert!(rules.is_trusted_path("C:\\Program Files\\Test\\app.exe"));
        assert!(!rules.is_trusted_path("C:\\Users\\Public\\malware.exe"));
    }

    #[test]
    fn test_trusted_publisher() {
        let rules = CompiledRules::builtin();
        assert!(rules.is_trusted_publisher(Some("Microsoft Corporation"), None));
        assert!(rules.is_trusted_publisher(None, Some("VMware Tools")));
        assert!(!rules.is_trusted_publisher(Some("Unknown Corp"), None));
    }
}
