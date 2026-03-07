// =============================================================================
// NTFS Forensic Analyzer - Rule Engine
// =============================================================================
// Loads detection rules from TOML configuration files and provides
// a structured interface for the analysis engine to evaluate them.
// =============================================================================

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// A single detection rule loaded from the rules TOML file
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub severity: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_toml_table")]
    pub parameters: toml::Value,
}

fn default_true() -> bool {
    true
}

fn default_toml_table() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

// ---------------------------------------------------------------------------
// Whitelist: loaded from a separate TOML file with regex patterns
// ---------------------------------------------------------------------------

/// A single whitelist entry as stored in whitelist.toml
#[derive(Debug, Deserialize)]
struct WhitelistRule {
    #[allow(dead_code)]
    id: Option<String>,
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    pattern: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// Root structure of the whitelist TOML file
#[derive(Debug, Deserialize)]
struct WhitelistFile {
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<WhitelistMetadata>,
    #[serde(default)]
    rules: Vec<WhitelistRule>,
}

#[derive(Debug, Deserialize)]
struct WhitelistMetadata {
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
}

/// Compiled whitelist used at runtime
pub struct WhitelistEngine {
    patterns: Vec<Regex>,
}

impl WhitelistEngine {
    /// Build from a parsed TOML file — compile all enabled patterns
    fn from_file(wf: WhitelistFile) -> Result<Self> {
        let mut patterns = Vec::new();
        for rule in &wf.rules {
            if !rule.enabled {
                continue;
            }
            // All patterns are matched case-insensitively
            let pat = if rule.pattern.starts_with("(?i)") {
                rule.pattern.clone()
            } else {
                format!("(?i){}", rule.pattern)
            };
            let re = Regex::new(&pat)
                .with_context(|| format!("Invalid whitelist regex: {}", rule.pattern))?;
            patterns.push(re);
        }
        Ok(Self { patterns })
    }

    /// Empty whitelist — nothing is excluded
    fn empty() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Return the number of compiled patterns
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check if a path matches any whitelist pattern
    pub fn is_match(&self, path: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(path))
    }
}

// ---------------------------------------------------------------------------
// Rules file (detection rules only — no whitelist)
// ---------------------------------------------------------------------------

/// Root structure of the rules TOML file
#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<RulesMetadata>,
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct RulesMetadata {
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    author: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
}

/// The rule engine manages loading and querying detection rules + whitelist
pub struct RuleEngine {
    rules: Vec<Rule>,
    whitelist: WhitelistEngine,
}

impl RuleEngine {
    /// Load rules from a TOML file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read rules file: {}", path.display()))?;

        let rules_file: RulesFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse rules file: {}", path.display()))?;

        let enabled_count = rules_file.rules.iter().filter(|r| r.enabled).count();
        let total_count = rules_file.rules.len();
        eprintln!(
            "[*] Loaded {} rules ({} enabled, {} disabled)",
            total_count,
            enabled_count,
            total_count - enabled_count
        );

        Ok(Self {
            rules: rules_file.rules,
            whitelist: WhitelistEngine::empty(),
        })
    }

    /// Load a whitelist from a separate TOML file
    pub fn load_whitelist(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read whitelist file: {}", path.display()))?;

        let wf: WhitelistFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse whitelist file: {}", path.display()))?;

        self.whitelist = WhitelistEngine::from_file(wf)?;
        eprintln!(
            "[*] Whitelist active: {} regex pattern(s) compiled from {}",
            self.whitelist.len(),
            path.display()
        );
        Ok(())
    }

    /// Auto-discover and load the default whitelist.toml
    pub fn load_default_whitelist(&mut self) {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let candidates = [
            exe_dir.as_ref().map(|d| d.join("rules/whitelist.toml")),
            exe_dir.as_ref().map(|d| d.join("../rules/whitelist.toml")),
            Some(std::path::PathBuf::from("rules/whitelist.toml")),
            Some(std::path::PathBuf::from("./rules/whitelist.toml")),
        ];

        for candidate in candidates.iter().flatten() {
            if candidate.exists() {
                match self.load_whitelist(candidate) {
                    Ok(()) => return,
                    Err(e) => {
                        eprintln!("[!] Failed to load whitelist {}: {}", candidate.display(), e);
                    }
                }
            }
        }
        // No whitelist found — that's fine, run without exclusions
    }

    /// Load default rules from the embedded rules directory
    pub fn load_default() -> Result<Self> {
        let mut engine = Self::load_default_rules_only()?;
        engine.load_default_whitelist();
        Ok(engine)
    }

    /// Load default rules WITHOUT auto-discovering the whitelist
    pub fn load_default_rules_only() -> Result<Self> {
        // Try to find rules relative to the executable, then fall back to
        // the compile-time known path
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let candidate_paths = [
            exe_dir
                .as_ref()
                .map(|d| d.join("rules/default_rules.toml")),
            exe_dir
                .as_ref()
                .map(|d| d.join("../rules/default_rules.toml")),
            Some(std::path::PathBuf::from("rules/default_rules.toml")),
            Some(std::path::PathBuf::from("./rules/default_rules.toml")),
        ];

        for candidate in candidate_paths.iter().flatten() {
            if candidate.exists() {
                return Self::load_from_file(candidate);
            }
        }

        // If no file found, use embedded default rules
        eprintln!("[!] No external rules file found, using embedded defaults");
        Self::load_embedded_defaults()
    }

    /// Load minimal embedded rules when no external file is available
    fn load_embedded_defaults() -> Result<Self> {
        let default_rules = vec![
            Rule {
                id: "TS-001".to_string(),
                name: "SI Created Before FN Created".to_string(),
                category: "timestomping".to_string(),
                description: "$SI creation time predates $FN creation time".to_string(),
                severity: "High".to_string(),
                enabled: true,
                parameters: toml::Value::Table({
                    let mut t = toml::map::Map::new();
                    t.insert(
                        "min_difference_seconds".to_string(),
                        toml::Value::Integer(60),
                    );
                    t
                }),
            },
            Rule {
                id: "TS-002".to_string(),
                name: "Zero Nanosecond Precision".to_string(),
                category: "timestomping".to_string(),
                description: "Timestamps have suspiciously zero sub-second precision".to_string(),
                severity: "Medium".to_string(),
                enabled: true,
                parameters: toml::Value::Table({
                    let mut t = toml::map::Map::new();
                    t.insert(
                        "min_zero_timestamps".to_string(),
                        toml::Value::Integer(2),
                    );
                    t
                }),
            },
            Rule {
                id: "MO-001".to_string(),
                name: "Mass File Rename (Ransomware Indicator)".to_string(),
                category: "mass_operation".to_string(),
                description: "Large number of files renamed in a short time window".to_string(),
                severity: "Critical".to_string(),
                enabled: true,
                parameters: toml::Value::Table({
                    let mut t = toml::map::Map::new();
                    t.insert("min_renames".to_string(), toml::Value::Integer(50));
                    t.insert("time_window_seconds".to_string(), toml::Value::Integer(60));
                    t
                }),
            },
            Rule {
                id: "MO-002".to_string(),
                name: "Mass File Deletion".to_string(),
                category: "mass_operation".to_string(),
                description: "Large number of files deleted in a short time window".to_string(),
                severity: "High".to_string(),
                enabled: true,
                parameters: toml::Value::Table({
                    let mut t = toml::map::Map::new();
                    t.insert("min_deletions".to_string(), toml::Value::Integer(50));
                    t.insert(
                        "time_window_seconds".to_string(),
                        toml::Value::Integer(120),
                    );
                    t
                }),
            },
        ];

        Ok(Self {
            rules: default_rules,
            whitelist: WhitelistEngine::empty(),
        })
    }

    /// Check if a file path is whitelisted (should be excluded from detection)
    pub fn is_whitelisted(&self, path: &str) -> bool {
        self.whitelist.is_match(path)
    }

    /// Get all enabled rules
    pub fn enabled_rules(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    /// Get enabled rules by category
    pub fn rules_by_category(&self, category: &str) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && r.category == category)
            .collect()
    }

    /// Get a specific rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Get a parameter value from a rule as i64
    pub fn get_param_i64(rule: &Rule, key: &str) -> Option<i64> {
        rule.parameters
            .as_table()
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_integer())
    }

    /// Get a parameter value from a rule as a string array
    pub fn get_param_string_array(rule: &Rule, key: &str) -> Vec<String> {
        rule.parameters
            .as_table()
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all unique categories
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self
            .rules
            .iter()
            .map(|r| r.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        cats.sort();
        cats
    }
}
