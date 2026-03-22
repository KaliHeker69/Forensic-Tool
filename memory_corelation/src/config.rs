use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use anyhow::Result;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct WhitelistConfig {
    pub dll_whitelist: Vec<DllWhitelistEntry>,
    #[serde(default)]
    pub process_dll_whitelist: Vec<ProcessDllEntry>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct DllWhitelistEntry {
    pub path_pattern: String,
    pub filenames: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ProcessDllEntry {
    pub process_name: String,
    pub allowed_dlls: Vec<String>,
}

impl WhitelistConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Check if a DLL is whitelisted for a specific process based on name found in config
    pub fn get_allowed_dlls(&self, process_name: &str) -> Option<&[String]> {
         self.process_dll_whitelist.iter()
            .find(|e| e.process_name.eq_ignore_ascii_case(process_name))
            .map(|e| e.allowed_dlls.as_slice())
    }

    pub fn is_whitelisted(&self, dll_path: &str) -> bool {
        let normalized = normalize_path(dll_path);
        
        for entry in &self.dll_whitelist {
            if normalized.contains(&entry.path_pattern) {
                // If specific filenames are provided, check them
                if !entry.filenames.is_empty() {
                    for filename in &entry.filenames {
                        if normalized.ends_with(&filename.to_lowercase()) {
                            return true;
                        }
                    }
                } else {
                    // If no filenames provided, whitelist the entire pattern
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BlacklistConfig {
    pub suspicious_paths: Vec<String>,
}

impl BlacklistConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn is_suspicious(&self, dll_path: &str) -> bool {
        let normalized = normalize_path(dll_path);
        for pattern in &self.suspicious_paths {
            if normalized.contains(pattern) {
                return true;
            }
        }
        false
    }
}

/// Normalize path for consistent comparison:
/// 1. Unify separators to backslash
/// 2. Lowercase
/// 3. Resolve ".." and "." components
fn normalize_path(path: &str) -> String {
    let lower = path.to_lowercase().replace('/', "\\");
    let mut stack = Vec::new();

    for part in lower.split('\\') {
        if part == "." {
            continue;
        } else if part == ".." {
            if !stack.is_empty() {
                // If stack isn't empty, try to pop unless we hit root or another ..
                if let Some(last) = stack.last() {
                    if *last == ".." {
                        stack.push(part);
                    } else if *last != "" {
                        stack.pop();
                    }
                }
            } else {
                stack.push(part);
            }
        } else {
            stack.push(part);
        }
    }
    
    stack.join("\\")
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkTuningConfig {
    #[serde(default = "default_host_role")]
    pub host_role: String,
    #[serde(default)]
    pub allowlisted_processes: Vec<String>,
    #[serde(default)]
    pub browser_processes: Vec<String>,
    #[serde(default)]
    pub common_client_processes: Vec<String>,
    #[serde(default)]
    pub expected_listener_processes: Vec<String>,
    #[serde(default)]
    pub never_network_processes: Vec<String>,
    #[serde(default)]
    pub expected_listener_ports: Vec<u16>,
    #[serde(default)]
    pub suspicious_ports: Vec<u16>,
    #[serde(default)]
    pub high_risk_remote_ports: Vec<u16>,
    #[serde(default)]
    pub allowlisted_ips: Vec<String>,
    #[serde(default)]
    pub allowlisted_subnets: Vec<String>,
}

fn default_host_role() -> String {
    "workstation".to_string()
}

impl Default for NetworkTuningConfig {
    fn default() -> Self {
        Self {
            host_role: default_host_role(),
            allowlisted_processes: vec![
                "system".to_string(),
                "svchost".to_string(),
            ],
            browser_processes: vec![
                "firefox".to_string(),
                "chrome".to_string(),
                "msedge".to_string(),
                "edge".to_string(),
                "brave".to_string(),
                "opera".to_string(),
                "iexplore".to_string(),
            ],
            common_client_processes: vec![
                "teams".to_string(),
                "onedrive".to_string(),
                "outlook".to_string(),
                "thunderbird".to_string(),
                "slack".to_string(),
                "zoom".to_string(),
                "discord".to_string(),
                "code".to_string(),
                "devenv".to_string(),
                "git".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "pip".to_string(),
                "npm".to_string(),
                "cargo".to_string(),
                "wuauclt".to_string(),
                "usoclient".to_string(),
                "msmpeng".to_string(),
                "mssense".to_string(),
                "searchapp".to_string(),
            ],
            expected_listener_processes: vec![
                "system".to_string(),
                "svchost".to_string(),
                "lsass".to_string(),
                "services".to_string(),
                "spoolsv".to_string(),
            ],
            never_network_processes: vec![
                "notepad".to_string(),
                "calc".to_string(),
                "mspaint".to_string(),
                "wordpad".to_string(),
                "write".to_string(),
                "fontdrvhost".to_string(),
                "dwm".to_string(),
                "regedit".to_string(),
            ],
            expected_listener_ports: vec![
                21, 22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445,
                464, 465, 587, 636, 993, 995, 1433, 1434, 3306, 3389, 5432,
                5985, 5986, 8080, 8443, 9200,
            ],
            suspicious_ports: vec![
                4444, 4445, 5555, 6666, 7777, 8888, 9999,
                1337, 31337, 12345, 54321, 2323,
            ],
            high_risk_remote_ports: vec![22, 135, 445, 3389, 5985, 5986],
            allowlisted_ips: vec![],
            allowlisted_subnets: vec!["127.0.0.0/8".to_string()],
        }
    }
}

impl NetworkTuningConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config: Self = serde_json::from_str(&content)?;

        // Ensure empty user config still gets sane defaults.
        let defaults = Self::default();
        if config.browser_processes.is_empty() {
            config.browser_processes = defaults.browser_processes;
        }
        if config.common_client_processes.is_empty() {
            config.common_client_processes = defaults.common_client_processes;
        }
        if config.expected_listener_processes.is_empty() {
            config.expected_listener_processes = defaults.expected_listener_processes;
        }
        if config.never_network_processes.is_empty() {
            config.never_network_processes = defaults.never_network_processes;
        }
        if config.expected_listener_ports.is_empty() {
            config.expected_listener_ports = defaults.expected_listener_ports;
        }
        if config.suspicious_ports.is_empty() {
            config.suspicious_ports = defaults.suspicious_ports;
        }
        if config.high_risk_remote_ports.is_empty() {
            config.high_risk_remote_ports = defaults.high_risk_remote_ports;
        }

        Ok(config)
    }

    pub fn is_browser_process(&self, process_name: &str) -> bool {
        self.browser_processes
            .iter()
            .any(|p| process_matches(process_name, p))
    }

    pub fn is_common_client_process(&self, process_name: &str) -> bool {
        self.common_client_processes
            .iter()
            .any(|p| process_matches(process_name, p))
            || self.is_browser_process(process_name)
    }

    pub fn is_allowlisted_process(&self, process_name: &str) -> bool {
        self.allowlisted_processes
            .iter()
            .any(|p| process_matches(process_name, p))
    }

    pub fn is_expected_network_process(&self, process_name: &str) -> bool {
        self.is_allowlisted_process(process_name)
            || self.is_common_client_process(process_name)
            || role_expected_network_processes(self.host_role.as_str())
                .iter()
                .any(|p| process_matches(process_name, p))
    }

    pub fn is_never_network_process(&self, process_name: &str) -> bool {
        self.never_network_processes
            .iter()
            .any(|p| process_matches(process_name, p))
    }

    pub fn is_expected_listener_process(&self, process_name: &str) -> bool {
        self.expected_listener_processes
            .iter()
            .any(|p| process_matches(process_name, p))
            || role_expected_listener_processes(self.host_role.as_str())
                .iter()
                .any(|p| process_matches(process_name, p))
    }

    pub fn is_expected_listener_port(&self, port: u16) -> bool {
        self.expected_listener_ports.contains(&port)
    }

    pub fn is_suspicious_port(&self, port: u16) -> bool {
        self.suspicious_ports.contains(&port)
    }

    pub fn is_high_risk_remote_port(&self, port: u16) -> bool {
        self.high_risk_remote_ports.contains(&port)
    }

    pub fn is_ip_allowlisted(&self, ip: &str) -> bool {
        if self.allowlisted_ips.iter().any(|a| a == ip) {
            return true;
        }

        self.allowlisted_subnets
            .iter()
            .any(|cidr| ipv4_in_cidr(ip, cidr))
    }
}

fn process_matches(process_name: &str, pattern: &str) -> bool {
    process_name.to_lowercase().contains(&pattern.to_lowercase())
}

fn role_expected_network_processes(role: &str) -> &'static [&'static str] {
    match role.to_lowercase().as_str() {
        "server" => &[
            "svchost", "system", "lsass", "services", "dns", "dhcp",
            "w3wp", "httpd", "nginx", "apache", "sqlservr", "postgres", "mysqld",
        ],
        "domain_controller" | "dc" => &[
            "svchost", "system", "lsass", "services", "dns", "ntds", "kdc", "dfsr",
        ],
        _ => &[
            "svchost", "system", "lsass", "services", "wuauclt", "usoclient",
            "msmpeng", "mssense", "searchapp",
        ],
    }
}

fn role_expected_listener_processes(role: &str) -> &'static [&'static str] {
    match role.to_lowercase().as_str() {
        "server" => &[
            "svchost", "system", "lsass", "services", "w3wp", "httpd", "nginx", "apache",
            "sqlservr", "postgres", "mysqld",
        ],
        "domain_controller" | "dc" => &[
            "svchost", "system", "lsass", "services", "dns", "ntds", "kdc", "dfsr",
        ],
        _ => &[
            "svchost", "system", "lsass", "services", "spoolsv",
        ],
    }
}

fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let (base, prefix) = match cidr.split_once('/') {
        Some((b, p)) => (b, p),
        None => return false,
    };
    let prefix_len: u32 = match prefix.parse::<u32>() {
        Ok(v) if v <= 32 => v,
        _ => return false,
    };

    let ip_u32 = match parse_ipv4_to_u32(ip) {
        Some(v) => v,
        None => return false,
    };
    let base_u32 = match parse_ipv4_to_u32(base) {
        Some(v) => v,
        None => return false,
    };

    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };

    (ip_u32 & mask) == (base_u32 & mask)
}

fn parse_ipv4_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut out = 0u32;
    for part in parts {
        let oct = part.parse::<u8>().ok()?;
        out = (out << 8) | (oct as u32);
    }
    Some(out)
}

static NETWORK_TUNING: OnceLock<NetworkTuningConfig> = OnceLock::new();

pub fn network_tuning() -> &'static NetworkTuningConfig {
    NETWORK_TUNING.get_or_init(|| {
        NetworkTuningConfig::load_from_file("./config/network_tuning.json")
            .unwrap_or_default()
    })
}
