use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::{Context, Result};
use regex::Regex;

/// A single detection rule — a list of indicator patterns for one category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    #[serde(default)]
    pub use_regex: bool,
    pub indicators: Vec<String>,
}

/// Compiled regex patterns for path matching
#[derive(Debug, Clone)]
pub struct CompiledPatterns {
    pub patterns: Vec<Regex>,
}

impl CompiledPatterns {
    pub fn from_indicators(indicators: &[String]) -> Self {
        let patterns = indicators
            .iter()
            .filter_map(|pattern| {
                match Regex::new(pattern) {
                    Ok(re) => Some(re),
                    Err(e) => {
                        eprintln!("[!] Invalid regex pattern '{}': {}", pattern, e);
                        None
                    }
                }
            })
            .collect();
        Self { patterns }
    }

    /// Check if any pattern matches the given text
    pub fn is_match(&self, text: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(text))
    }

    /// Return the first matching pattern description (for evidence)
    pub fn first_match(&self, text: &str) -> Option<String> {
        self.patterns.iter().find_map(|re| {
            if re.is_match(text) {
                Some(re.as_str().to_string())
            } else {
                None
            }
        })
    }
}

/// All loaded detection rules
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub suspicious_paths: Vec<String>,
    pub suspicious_paths_regex: Option<CompiledPatterns>,
    pub whitelist_paths_regex: Option<CompiledPatterns>,
    pub benign_system_paths_regex: Option<CompiledPatterns>,
    pub benign_system_processes: Vec<String>,
    pub benign_system_paths: Vec<String>,
    pub anti_forensic_tools: Vec<String>,
    pub credential_tools: Vec<String>,
    pub lateral_movement_tools: Vec<String>,
    pub system_utilities: Vec<String>,
    pub lolbins: Vec<String>,
    pub c2_frameworks: Vec<String>,
    pub rat_tools: Vec<String>,
    pub removable_drives: Vec<String>,
    // Network analyzer rules
    pub non_browser_suspicious: Vec<String>,
    pub browsers: Vec<String>,
    pub archive_tools: Vec<String>,
}

impl RuleSet {
    /// Load rules from the rules directory. Falls back to built-in defaults if files not found.
    pub fn load(rules_dir: &Path) -> Self {
        let mut ruleset = Self::default_rules();

        if !rules_dir.exists() {
            eprintln!("[*] Rules directory not found, using built-in defaults: {}", rules_dir.display());
            return ruleset;
        }

        // Load suspicious paths (regex-based)
        if let Ok(r) = load_rule_file(&rules_dir.join("suspicious_paths.json")) {
            eprintln!("[+] Loaded {} suspicious path rules (regex: {})", r.indicators.len(), r.use_regex);
            if r.use_regex {
                ruleset.suspicious_paths_regex = Some(CompiledPatterns::from_indicators(&r.indicators));
            }
            ruleset.suspicious_paths = r.indicators;
        }

        // Load whitelist paths (always regex)
        if let Ok(r) = load_rule_file(&rules_dir.join("whitelist_paths.json")) {
            eprintln!("[+] Loaded {} whitelist path rules", r.indicators.len());
            ruleset.whitelist_paths_regex = Some(CompiledPatterns::from_indicators(&r.indicators));
        }

        if let Ok(r) = load_rule_file(&rules_dir.join("benign_system_processes.json")) {
            eprintln!("[+] Loaded {} benign system process rules", r.indicators.len());
            ruleset.benign_system_processes = r.indicators;
        }

        if let Ok(r) = load_rule_file(&rules_dir.join("benign_system_paths.json")) {
            eprintln!("[+] Loaded {} benign system path rules (regex: {})", r.indicators.len(), r.use_regex);
            if r.use_regex {
                ruleset.benign_system_paths_regex = Some(CompiledPatterns::from_indicators(&r.indicators));
            }
            ruleset.benign_system_paths = r.indicators;
        }

        if let Ok(r) = load_rule_file(&rules_dir.join("anti_forensic_tools.json")) {
            eprintln!("[+] Loaded {} anti-forensic tool rules", r.indicators.len());
            ruleset.anti_forensic_tools = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("credential_tools.json")) {
            eprintln!("[+] Loaded {} credential tool rules", r.indicators.len());
            ruleset.credential_tools = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("lateral_movement_tools.json")) {
            eprintln!("[+] Loaded {} lateral movement tool rules", r.indicators.len());
            ruleset.lateral_movement_tools = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("system_utilities.json")) {
            eprintln!("[+] Loaded {} system utility rules", r.indicators.len());
            ruleset.system_utilities = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("lolbins.json")) {
            eprintln!("[+] Loaded {} LOLBin rules", r.indicators.len());
            ruleset.lolbins = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("c2_frameworks.json")) {
            eprintln!("[+] Loaded {} C2 framework rules", r.indicators.len());
            ruleset.c2_frameworks = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("rat_tools.json")) {
            eprintln!("[+] Loaded {} RAT tool rules", r.indicators.len());
            ruleset.rat_tools = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("removable_drives.json")) {
            eprintln!("[+] Loaded {} removable drive rules", r.indicators.len());
            ruleset.removable_drives = r.indicators;
        }

        // Network analyzer rules
        if let Ok(r) = load_rule_file(&rules_dir.join("non_browser_suspicious.json")) {
            eprintln!("[+] Loaded {} non-browser suspicious app rules", r.indicators.len());
            ruleset.non_browser_suspicious = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("browsers.json")) {
            eprintln!("[+] Loaded {} browser rules", r.indicators.len());
            ruleset.browsers = r.indicators;
        }
        if let Ok(r) = load_rule_file(&rules_dir.join("archive_tools.json")) {
            eprintln!("[+] Loaded {} archive tool rules", r.indicators.len());
            ruleset.archive_tools = r.indicators;
        }

        ruleset
    }

    /// Check if a path matches suspicious path rules (regex or plain string)
    ///
    /// SrumECmd emits paths like `\Device\HarddiskVolume3\Windows\System32\svchost.exe`
    /// instead of `C:\Windows\System32\svchost.exe`. We normalize the path before matching
    /// so the regex-based whitelist and suspicious-path rules work correctly.
    pub fn is_suspicious_path(&self, path: &str) -> Option<String> {
        // Normalize SrumECmd's \Device\HarddiskVolumeN\ prefix to C:\
        let normalized = normalize_device_path(path);
        let check_path = normalized.as_deref().unwrap_or(path);

        // First check whitelist — if whitelisted, NOT suspicious
        if let Some(ref wl) = self.whitelist_paths_regex {
            if wl.is_match(check_path) || wl.is_match(path) {
                return None;
            }
        }

        // Check regex patterns if available
        if let Some(ref regex_patterns) = self.suspicious_paths_regex {
            return regex_patterns.first_match(check_path)
                .or_else(|| regex_patterns.first_match(path));
        }

        // Fallback to plain string matching
        let path_lower = check_path.to_lowercase();
        for indicator in &self.suspicious_paths {
            if path_lower.contains(&indicator.to_lowercase()) {
                return Some(indicator.clone());
            }
        }
        None
    }

    /// Built-in default rules (used when rule files are not present)
    fn default_rules() -> Self {
        Self {
            suspicious_paths: Vec::new(),

            suspicious_paths_regex: None,
            whitelist_paths_regex: None,
            benign_system_paths_regex: None,
            benign_system_processes: Vec::new(),
            benign_system_paths: Vec::new(),

            anti_forensic_tools: Vec::new(),
            credential_tools: Vec::new(),
            lateral_movement_tools: Vec::new(),
            system_utilities: Vec::new(),
            lolbins: Vec::new(),
            c2_frameworks: Vec::new(),
            rat_tools: Vec::new(),
            removable_drives: Vec::new(),
            non_browser_suspicious: Vec::new(),
            browsers: Vec::new(),
            archive_tools: Vec::new(),
        }
    }
}

/// Load a single rule file
fn load_rule_file(path: &Path) -> Result<DetectionRule> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read rule file: {}", path.display()))?;
    let rule: DetectionRule = serde_json::from_str(&content)
        .context(format!("Failed to parse rule file: {}", path.display()))?;
    Ok(rule)
}

/// Normalize SrumECmd `\Device\HarddiskVolumeN\...` paths to `C:\...`
///
/// SrumECmd (without SOFTWARE hive) emits raw NT device paths like:
///   `\Device\HarddiskVolume3\Windows\System32\svchost.exe`
/// Our regex rules are written against standard Win32 paths like:
///   `C:\Windows\System32\svchost.exe`
///
/// This function strips the device prefix so rule matching works correctly.
pub fn normalize_device_path(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    if lower.starts_with("\\device\\harddiskvolume") {
        // Find the second backslash after \Device\HarddiskVolumeN
        if let Some(pos) = path[1..].find('\\').and_then(|p1| {
            path[p1 + 2..].find('\\').map(|p2| p1 + p2 + 2)
        }) {
            return Some(format!("C:{}", &path[pos..]));
        }
    }
    None
}
