/// Rule engine — loads external JSON rule files from the `rules/` directory.
///
/// All detection/correlation thresholds and indicator lists live in JSON
/// files so analysts can tune them without recompiling. A [`RuleSet`] is
/// built once at startup and passed (by reference) to every parser and
/// analysis module.
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Top-level container for every rule file.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules_dir: PathBuf,
    pub suspicious_tools: HashSet<String>,
    pub malicious_ports: HashSet<u16>,
    pub unusual_network_processes: HashSet<String>,
    pub network_keywords: Vec<String>,
    pub scoring: ScoringRules,
    pub beaconing: BeaconingRules,
    pub process_spoofing: ProcessSpoofingRules,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoringRules {
    pub weights: HashMap<String, u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BeaconingRules {
    pub min_connections: usize,
    pub max_interval_stddev_seconds: u64,
    pub min_interval_seconds: u64,
    pub max_interval_seconds: u64,
    pub exfil_sent_recv_ratio: f64,
    pub exfil_min_bytes_sent: u64,
    pub business_hours_start: u8,
    pub business_hours_end: u8,
    pub business_days: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessSpoofingRules {
    pub legitimate_names: Vec<String>,
}

// ── internal deserialization helpers ──
#[derive(Deserialize)]
struct SuspiciousToolsFile {
    tools: Vec<String>,
}

#[derive(Deserialize)]
struct MaliciousPortsFile {
    ports: Vec<u16>,
}

#[derive(Deserialize)]
struct UnusualProcessesFile {
    processes: Vec<String>,
}

#[derive(Deserialize)]
struct NetworkKeywordsFile {
    keywords: Vec<String>,
}

impl RuleSet {
    /// Load all rule files from `rules_dir`. Missing optional files use sane
    /// defaults so the tool still works out-of-the-box.
    pub fn load(rules_dir: &Path) -> Result<Self> {
        log::info!("Loading rules from {}", rules_dir.display());

        let suspicious_tools = load_json::<SuspiciousToolsFile>(rules_dir, "suspicious_tools.json")
            .map(|f| f.tools.into_iter().map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();

        let malicious_ports = load_json::<MaliciousPortsFile>(rules_dir, "malicious_ports.json")
            .map(|f| f.ports.into_iter().collect())
            .unwrap_or_default();

        let unusual_network_processes =
            load_json::<UnusualProcessesFile>(rules_dir, "unusual_network_processes.json")
                .map(|f| f.processes.into_iter().map(|s| s.to_lowercase()).collect())
                .unwrap_or_default();

        let network_keywords =
            load_json::<NetworkKeywordsFile>(rules_dir, "network_keywords.json")
                .map(|f| f.keywords.into_iter().map(|s| s.to_lowercase()).collect())
                .unwrap_or_default();

        let scoring = load_json::<ScoringRules>(rules_dir, "scoring.json").unwrap_or_else(|_| {
            ScoringRules {
                weights: HashMap::new(),
            }
        });

        let beaconing =
            load_json::<BeaconingRules>(rules_dir, "beaconing.json").unwrap_or_else(|_| {
                BeaconingRules {
                    min_connections: 5,
                    max_interval_stddev_seconds: 60,
                    min_interval_seconds: 30,
                    max_interval_seconds: 7200,
                    exfil_sent_recv_ratio: 3.0,
                    exfil_min_bytes_sent: 1_048_576,
                    business_hours_start: 8,
                    business_hours_end: 18,
                    business_days: vec![
                        "Monday".into(),
                        "Tuesday".into(),
                        "Wednesday".into(),
                        "Thursday".into(),
                        "Friday".into(),
                    ],
                }
            });

        let process_spoofing =
            load_json::<ProcessSpoofingRules>(rules_dir, "process_spoofing.json")
                .unwrap_or_else(|_| ProcessSpoofingRules {
                    legitimate_names: Vec::new(),
                });

        let ruleset = RuleSet {
            rules_dir: rules_dir.to_path_buf(),
            suspicious_tools,
            malicious_ports,
            unusual_network_processes,
            network_keywords,
            scoring,
            beaconing,
            process_spoofing,
        };

        log::info!(
            "Loaded {} suspicious tools, {} malicious ports, {} unusual processes, {} keywords",
            ruleset.suspicious_tools.len(),
            ruleset.malicious_ports.len(),
            ruleset.unusual_network_processes.len(),
            ruleset.network_keywords.len(),
        );

        Ok(ruleset)
    }

    // ── convenience query methods ──

    pub fn is_suspicious_tool(&self, name: &str) -> bool {
        self.suspicious_tools.contains(&name.to_lowercase())
    }

    pub fn is_malicious_port(&self, port: u16) -> bool {
        self.malicious_ports.contains(&port)
    }

    pub fn is_unusual_network_process(&self, name: &str) -> bool {
        self.unusual_network_processes.contains(&name.to_lowercase())
    }

    pub fn matches_network_keyword(&self, text: &str) -> bool {
        let lc = text.to_lowercase();
        self.network_keywords.iter().any(|kw| lc.contains(kw.as_str()))
    }

    /// Look up a scoring weight by rule name; returns 0 if absent.
    pub fn score_weight(&self, rule: &str) -> u8 {
        self.scoring.weights.get(rule).copied().unwrap_or(0)
    }
}

fn load_json<T: serde::de::DeserializeOwned>(dir: &Path, filename: &str) -> Result<T> {
    let path = dir.join(filename);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
    serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse rule file: {}", path.display()))
}
