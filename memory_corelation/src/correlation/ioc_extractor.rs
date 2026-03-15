//! IOC (Indicator of Compromise) automatic extractor
//!
//! Scans all parsed forensic data and extracts actionable IOCs:
//! IPs, domains, file paths, registry keys, mutex names, hashes,
//! URLs, and email addresses. Deduplicates and classifies each IOC.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::models::ProcessAssociated;
use crate::parsers::ParsedData;
use crate::Finding;

/// IOC types we can extract
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum IocType {
    IPv4,
    IPv6,
    Domain,
    Url,
    FilePath,
    RegistryKey,
    MutexName,
    Hash,
    EmailAddress,
    UserAgent,
    ProcessName,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::IPv4 => write!(f, "IPv4"),
            IocType::IPv6 => write!(f, "IPv6"),
            IocType::Domain => write!(f, "Domain"),
            IocType::Url => write!(f, "URL"),
            IocType::FilePath => write!(f, "File Path"),
            IocType::RegistryKey => write!(f, "Registry Key"),
            IocType::MutexName => write!(f, "Mutex"),
            IocType::Hash => write!(f, "Hash"),
            IocType::EmailAddress => write!(f, "Email"),
            IocType::UserAgent => write!(f, "User-Agent"),
            IocType::ProcessName => write!(f, "Process"),
        }
    }
}

/// A single extracted IOC
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedIoc {
    /// The IOC value
    pub value: String,
    /// Type classification
    pub ioc_type: IocType,
    /// Sources where this IOC was found
    pub sources: Vec<String>,
    /// Associated PIDs
    pub related_pids: Vec<u32>,
    /// Risk context (e.g., "external", "suspicious port", "persistence key")
    pub context: Vec<String>,
    /// Whether this IOC was associated with a finding
    pub in_finding: bool,
}

/// Complete IOC extraction result
#[derive(Debug, Clone, Serialize)]
pub struct IocReport {
    pub iocs: Vec<ExtractedIoc>,
    pub summary: IocSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocSummary {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
    pub high_confidence: usize,
}

/// Extract all IOCs from parsed data + findings
pub fn extract_iocs(data: &ParsedData, findings: &[Finding]) -> IocReport {
    let mut collector = IocCollector::new();

    collector.extract_from_network(data);
    collector.extract_from_files(data);
    collector.extract_from_registry(data);
    collector.extract_from_handles(data);
    collector.extract_from_browser(data);
    collector.extract_from_processes(data);
    collector.extract_from_services(data);
    collector.mark_finding_iocs(findings);

    collector.build_report()
}

/// Internal collector for deduplication
struct IocCollector {
    /// Map from (ioc_type, value) → ExtractedIoc
    iocs: HashMap<(IocType, String), ExtractedIoc>,
    /// Set of IOC values that appeared in findings
    finding_values: HashSet<String>,
}

impl IocCollector {
    fn new() -> Self {
        Self {
            iocs: HashMap::new(),
            finding_values: HashSet::new(),
        }
    }

    fn add(
        &mut self,
        ioc_type: IocType,
        value: String,
        source: &str,
        pid: Option<u32>,
        context: Option<String>,
    ) {
        // Skip empty/junk values
        if value.is_empty() || value == "?" || value == "-" || value == "*" || value == "N/A" {
            return;
        }

        // Normalize
        let normalized = value.trim().to_string();
        if normalized.is_empty() {
            return;
        }

        let key = (ioc_type, normalized.clone());
        let entry = self.iocs.entry(key).or_insert_with(|| ExtractedIoc {
            value: normalized,
            ioc_type,
            sources: Vec::new(),
            related_pids: Vec::new(),
            context: Vec::new(),
            in_finding: false,
        });

        let source_str = source.to_string();
        if !entry.sources.contains(&source_str) {
            entry.sources.push(source_str);
        }

        if let Some(p) = pid {
            if !entry.related_pids.contains(&p) {
                entry.related_pids.push(p);
            }
        }

        if let Some(ctx) = context {
            if !entry.context.contains(&ctx) {
                entry.context.push(ctx);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Network IOCs
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_network(&mut self, data: &ParsedData) {
        for conn in &data.connections {
            // External IPs
            if conn.is_external() {
                let ctx = if conn.is_suspicious_port() {
                    Some(format!("suspicious port {}", conn.foreign_port))
                } else {
                    Some("external connection".to_string())
                };
                self.add(
                    IocType::IPv4,
                    conn.foreign_addr.clone(),
                    "netscan",
                    Some(conn.pid),
                    ctx,
                );
            }

            // Also capture local addresses (for pivoting analysis)
            if !is_loopback(&conn.local_addr) && !conn.local_addr.starts_with("0.") {
                self.add(
                    IocType::IPv4,
                    conn.local_addr.clone(),
                    "netscan",
                    Some(conn.pid),
                    Some("local endpoint".to_string()),
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // File IOCs
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_files(&mut self, data: &ParsedData) {
        for file in &data.files {
            // Only extract interesting files (executables + staging paths)
            if file.is_executable() || file.is_staging_pattern() {
                let ctx = if file.is_staging_pattern() {
                    Some("staging path".to_string())
                } else if file.is_executable() {
                    Some("executable".to_string())
                } else {
                    None
                };
                self.add(IocType::FilePath, file.name.clone(), "filescan", None, ctx);
            }
        }

        // MFT entries for executables in suspicious locations
        for mft in &data.mft_entries {
            let fname = mft.filename.as_deref().unwrap_or("");
            let lower = fname.to_lowercase();
            if lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".sys")
                || lower.ends_with(".ps1")
                || lower.ends_with(".bat")
            {
                let path = fname.to_string();
                self.add(
                    IocType::FilePath,
                    path,
                    "mftscan",
                    None,
                    Some("MFT entry".to_string()),
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Registry IOCs
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_registry(&mut self, data: &ParsedData) {
        for reg in &data.registry_keys {
            // Persistence keys
            if reg.is_persistence_key() {
                self.add(
                    IocType::RegistryKey,
                    format!("{}\\{}", reg.key, reg.name.as_deref().unwrap_or("")),
                    "registry",
                    None,
                    Some("persistence key".to_string()),
                );

                // Extract data values from persistence keys (may contain file paths, URLs)
                if let Some(ref val) = reg.data {
                    let val_lower = val.to_lowercase();
                    if val_lower.contains(":\\") || val_lower.contains("\\\\") {
                        self.add(
                            IocType::FilePath,
                            val.clone(),
                            "registry:data",
                            None,
                            Some("persistence value".to_string()),
                        );
                    }
                    if val_lower.starts_with("http://") || val_lower.starts_with("https://") {
                        self.add(
                            IocType::Url,
                            val.clone(),
                            "registry:data",
                            None,
                            Some("persistence URL".to_string()),
                        );
                    }
                }
            }

            // Keys with executable data
            if reg.has_executable_data() || reg.has_obfuscated_data() {
                let ctx = if reg.has_obfuscated_data() {
                    "obfuscated data"
                } else {
                    "executable data"
                };
                self.add(
                    IocType::RegistryKey,
                    format!("{}\\{}", reg.key, reg.name.as_deref().unwrap_or("")),
                    "registry",
                    None,
                    Some(ctx.to_string()),
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Handle IOCs (mutexes, named pipes)
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_handles(&mut self, data: &ParsedData) {
        for handle in &data.handles {
            // Mutexes
            if handle.is_mutex_handle() {
                if let Some(ref name) = handle.name {
                    // Skip generic system mutexes
                    let lower = name.to_lowercase();
                    if lower.starts_with("\\basenamedobjects\\")
                        || lower.starts_with("\\kernelobj")
                        || lower.contains("windows")
                        || lower.contains("microsoft")
                    {
                        continue;
                    }
                    self.add(
                        IocType::MutexName,
                        name.clone(),
                        "handles",
                        Some(handle.pid),
                        None,
                    );
                }
            }

            // Sensitive process handles
            if handle.is_sensitive_process_handle() {
                if let Some(ref name) = handle.name {
                    self.add(
                        IocType::ProcessName,
                        name.clone(),
                        "handles",
                        Some(handle.pid),
                        Some("sensitive process handle".to_string()),
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Browser IOCs (URLs, domains)
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_browser(&mut self, data: &ParsedData) {
        // Browser history — only suspicious URLs
        for entry in &data.browser_history {
            if entry.is_suspicious_url() || entry.is_potential_driveby() {
                self.add(
                    IocType::Url,
                    entry.url.clone(),
                    "browser_history",
                    None,
                    Some(if entry.is_potential_driveby() {
                        "potential drive-by"
                    } else {
                        "suspicious URL"
                    }
                    .to_string()),
                );

                if let Some(domain) = entry.domain() {
                    self.add(
                        IocType::Domain,
                        domain.to_string(),
                        "browser_history",
                        None,
                        Some("suspicious domain".to_string()),
                    );
                }
            }
        }

        // Downloads — always interesting
        for dl in &data.downloads {
            self.add(
                IocType::Url,
                dl.url.clone(),
                "browser_downloads",
                None,
                Some(if dl.is_executable() {
                    "executable download"
                } else if dl.was_flagged_dangerous() {
                    "flagged dangerous"
                } else {
                    "download"
                }
                .to_string()),
            );

            if let Some(domain) = dl.domain() {
                self.add(
                    IocType::Domain,
                    domain.to_string(),
                    "browser_downloads",
                    None,
                    None,
                );
            }

            self.add(
                IocType::FilePath,
                dl.target_path.clone(),
                "browser_downloads",
                None,
                Some("download target".to_string()),
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Process IOCs
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_processes(&mut self, data: &ParsedData) {
        // Suspicious process names
        for proc in &data.processes {
            let lower = proc.name.to_lowercase();

            // Process masquerading (e.g., "svch0st.exe")
            let mimics = ["svch0st", "svchosts", "lssas", "lssass", "csvhost", "explore"];
            if mimics.iter().any(|m| lower.contains(m)) {
                self.add(
                    IocType::ProcessName,
                    proc.name.clone(),
                    "pslist",
                    Some(proc.pid),
                    Some("process masquerading".to_string()),
                );
            }
        }

        // Encoded command lines
        for cmd in &data.cmdlines {
            let lower = cmd.args.to_lowercase();
            if lower.contains("-enc ") || lower.contains("-encodedcommand ") {
                self.add(
                    IocType::ProcessName,
                    format!("PID:{} cmd={}", cmd.pid, &cmd.args[..cmd.args.len().min(200)]),
                    "cmdline",
                    Some(cmd.pid),
                    Some("encoded command".to_string()),
                );
            }
        }

        // Malicious DLLs (side-loaded / suspicious paths)
        for dll in &data.dlls {
            let lower = dll.path.to_lowercase();
            let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\"];
            if suspicious_paths.iter().any(|p| lower.contains(p)) {
                self.add(
                    IocType::FilePath,
                    dll.path.clone(),
                    "dlllist",
                    dll.pid(),
                    Some("DLL from suspicious path".to_string()),
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Service IOCs
    // ═══════════════════════════════════════════════════════════════════
    fn extract_from_services(&mut self, data: &ParsedData) {
        for svc in &data.services {
            if svc.is_suspicious_name() || svc.has_suspicious_execution() {
                if let Some(ref binary) = svc.binary_path {
                    self.add(
                        IocType::FilePath,
                        binary.clone(),
                        "svcscan",
                        svc.pid().map(|p| p as u32),
                        Some(format!("suspicious service: {}", svc.name)),
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Cross-reference with findings
    // ═══════════════════════════════════════════════════════════════════
    fn mark_finding_iocs(&mut self, findings: &[Finding]) {
        // Collect all IPs, files, PIDs from findings
        for finding in findings {
            for ip in &finding.related_ips {
                self.finding_values.insert(ip.clone());
            }
            for file in &finding.related_files {
                self.finding_values.insert(file.clone());
            }
        }

        // Mark IOCs that appear in findings
        for ioc in self.iocs.values_mut() {
            if self.finding_values.contains(&ioc.value) {
                ioc.in_finding = true;
            }
        }
    }

    fn build_report(self) -> IocReport {
        let mut iocs: Vec<ExtractedIoc> = self.iocs.into_values().collect();

        // Sort: findings first, then by type, then by value
        iocs.sort_by(|a, b| {
            b.in_finding
                .cmp(&a.in_finding)
                .then_with(|| a.ioc_type.to_string().cmp(&b.ioc_type.to_string()))
                .then_with(|| a.value.cmp(&b.value))
        });

        let total = iocs.len();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut high_confidence = 0;

        for ioc in &iocs {
            *by_type.entry(ioc.ioc_type.to_string()).or_default() += 1;
            if ioc.in_finding || ioc.sources.len() > 1 {
                high_confidence += 1;
            }
        }

        IocReport {
            iocs,
            summary: IocSummary {
                total,
                by_type,
                high_confidence,
            },
        }
    }
}

/// Check if an IP is loopback
fn is_loopback(ip: &str) -> bool {
    ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.")
}

/// Generate STIX 2.1 JSON bundle from IOC report
pub fn to_stix_bundle(report: &IocReport) -> String {
    use serde_json::{json, Value};

    let mut objects: Vec<Value> = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    for ioc in &report.iocs {
        let stix_type = match ioc.ioc_type {
            IocType::IPv4 | IocType::IPv6 => "ipv4-addr",
            IocType::Domain => "domain-name",
            IocType::Url => "url",
            IocType::FilePath => "file",
            IocType::RegistryKey => "windows-registry-key",
            IocType::MutexName => "mutex",
            IocType::Hash => "file",
            IocType::EmailAddress => "email-addr",
            IocType::UserAgent => "user-agent",
            IocType::ProcessName => "process",
        };

        let stix_id = format!(
            "indicator--{:x}",
            {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                ioc.value.hash(&mut hasher);
                ioc.ioc_type.to_string().hash(&mut hasher);
                hasher.finish()
            }
        );

        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "name": format!("{}: {}", ioc.ioc_type, ioc.value),
            "pattern_type": "stix",
            "pattern": format!("[{}:value = '{}']", stix_type, ioc.value),
            "valid_from": now,
            "labels": ioc.context.clone(),
            "x_sources": ioc.sources.clone(),
        }));
    }

    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid_simple()),
        "spec_version": "2.1",
        "objects": objects,
    });

    serde_json::to_string_pretty(&bundle).unwrap_or_default()
}

/// Simple UUID generator
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}-{:04x}-{:04x}",
        nanos % 0xFFFF_FFFF_FFFF_FFFF,
        (nanos >> 16) % 0xFFFF,
        (nanos >> 32) % 0xFFFF
    )
}
