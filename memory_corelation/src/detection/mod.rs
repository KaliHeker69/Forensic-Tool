//! Detection rules for identifying malicious behavior patterns

pub mod certificate_rules;
pub mod chain_rules;
pub mod credential_rules;
pub mod cross_correlation_rules;
pub mod injection_rules;
pub mod integrity_rules;
pub mod mft_rules;
pub mod network_rules;
pub mod parent_child_rules;
pub mod persistence_rules;
pub mod privilege_rules;
pub mod process_rules;
pub mod sid_rules;
pub mod signature_rules;
pub mod thread_rules;

use crate::correlation::CorrelationEngine;
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, FindingCategory, Severity};

/// Detection rule trait
pub trait DetectionRule: Send + Sync {
    /// Unique identifier for this rule
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Description of what this rule detects
    fn description(&self) -> &str;

    /// Base severity level
    fn severity(&self) -> Severity;

    /// MITRE ATT&CK technique ID if applicable
    fn mitre_attack(&self) -> Option<&str> {
        None
    }

    /// Run detection against the parsed data
    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding>;
}

/// Detection engine that runs all rules
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create engine with all default rules
    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();

        // Process rules
        engine.add_rule(Box::new(process_rules::OrphanedProcessRule));
        engine.add_rule(Box::new(process_rules::SuspiciousParentChildRule));
        engine.add_rule(Box::new(process_rules::EncodedCommandLineRule));
        engine.add_rule(Box::new(process_rules::SvchostAnomalyRule));
        engine.add_rule(Box::new(process_rules::SuspiciousDllPathRule::new()));
        engine.add_rule(Box::new(process_rules::AdvancedCommandLineRule));
        engine.add_rule(Box::new(process_rules::SystemProcessMasqueradingRule));

        // Parent-child relationship rules
        engine.add_rule(Box::new(parent_child_rules::SuspiciousParentRule));
        engine.add_rule(Box::new(parent_child_rules::LsassParentRule));
        engine.add_rule(Box::new(parent_child_rules::DuplicateSystemProcessRule));

        // Network rules
        engine.add_rule(Box::new(network_rules::ExternalConnectionRule));
        engine.add_rule(Box::new(network_rules::SuspiciousPortRule));
        engine.add_rule(Box::new(network_rules::BrowserNetworkCorrelationRule));
        engine.add_rule(Box::new(network_rules::UnusualProcessConnectionRule));
        engine.add_rule(Box::new(network_rules::ListeningPortAnalysisRule));
        engine.add_rule(Box::new(network_rules::BeaconingDetectionRule));
        engine.add_rule(Box::new(network_rules::LateralMovementDetectionRule));

        // Injection rules
        engine.add_rule(Box::new(injection_rules::MalfindDetectionRule));
        engine.add_rule(Box::new(injection_rules::RwxMemoryRule));
        engine.add_rule(Box::new(injection_rules::MzHeaderRule));
        engine.add_rule(Box::new(injection_rules::ProcessInjectionCmdlineRule));
        engine.add_rule(Box::new(injection_rules::VadInjectionRule));
        engine.add_rule(Box::new(injection_rules::MalfindStringExtractionRule));
        engine.add_rule(Box::new(injection_rules::LdrModulesHiddenModuleRule));

        // Persistence rules
        engine.add_rule(Box::new(persistence_rules::RegistryPersistenceRule));
        engine.add_rule(Box::new(persistence_rules::SuspiciousServiceRule::new()));
        engine.add_rule(Box::new(persistence_rules::SuspiciousScheduledTaskRule));

        // Signature verification rules
        engine.add_rule(Box::new(signature_rules::UnsignedSystemProcessRule));
        engine.add_rule(Box::new(signature_rules::InvalidSignatureRule));
        engine.add_rule(Box::new(signature_rules::NonMicrosoftSignerRule));

        // Integrity rules (hidden artifact detection)
        engine.add_rule(Box::new(integrity_rules::HiddenProcessRule));
        engine.add_rule(Box::new(integrity_rules::HiddenHiveRule));
        engine.add_rule(Box::new(integrity_rules::TimestampAnomalyRule));
        engine.add_rule(Box::new(integrity_rules::SuspiciousKernelModulePathRule));
        engine.add_rule(Box::new(integrity_rules::SystemInfoAnomalyRule));
        engine.add_rule(Box::new(integrity_rules::IdtHookAnomalyRule));
        engine.add_rule(Box::new(integrity_rules::DriverIrpHookAnomalyRule));
        engine.add_rule(Box::new(integrity_rules::SuspiciousAtomPatternRule));

        // Credential access rules
        engine.add_rule(Box::new(credential_rules::LsassHandleRule));
        engine.add_rule(Box::new(credential_rules::LsassDllInjectionRule::new()));
        engine.add_rule(Box::new(credential_rules::SensitiveProcessInjectionRule));
        engine.add_rule(Box::new(credential_rules::SuspiciousConsoleCommandRule));
        engine.add_rule(Box::new(credential_rules::CachedCredentialArtifactRule));
        engine.add_rule(Box::new(credential_rules::LsassTargetingRule));
        engine.add_rule(Box::new(credential_rules::HandleMutexAnalysisRule));

        // Attack chain rules (multi-plugin correlation)
        engine.add_rule(Box::new(chain_rules::ProcessHollowingChainRule));
        engine.add_rule(Box::new(chain_rules::ReconChainRule));
        engine.add_rule(Box::new(chain_rules::PersistenceChainRule));
        engine.add_rule(Box::new(chain_rules::KernelRootkitChainRule));

        // Thread detection rules
        engine.add_rule(Box::new(thread_rules::OrphanedThreadRule));
        engine.add_rule(Box::new(thread_rules::SuspiciousThreadStartRule));
        engine.add_rule(Box::new(thread_rules::SystemProcessThreadAnomalyRule));
        engine.add_rule(Box::new(thread_rules::ThreadCountAnomalyRule));

        // Privilege abuse detection rules
        engine.add_rule(Box::new(privilege_rules::DebugPrivilegeAbuseRule));
        engine.add_rule(Box::new(privilege_rules::TcbPrivilegeAbuseRule));
        engine.add_rule(Box::new(privilege_rules::LoadDriverPrivilegeAbuseRule));
        engine.add_rule(Box::new(privilege_rules::MultiDangerousPrivilegeRule));
        engine.add_rule(Box::new(privilege_rules::ImpersonatePrivilegeAbuseRule));

        // Certificate detection rules
        engine.add_rule(Box::new(certificate_rules::RogueCACertificateRule));
        engine.add_rule(Box::new(certificate_rules::MimickedCACertificateRule));
        engine.add_rule(Box::new(certificate_rules::KnownMalwareCertificateRule));
        engine.add_rule(Box::new(certificate_rules::SelfSignedRootCertificateRule));
        engine.add_rule(Box::new(certificate_rules::CertificateStoreAnomalyRule));

        // MFT/Filesystem detection rules
        engine.add_rule(Box::new(mft_rules::ExecutablesInTempRule));
        engine.add_rule(Box::new(mft_rules::DoubleExtensionRule));
        engine.add_rule(Box::new(mft_rules::AlternateDataStreamRule));
        engine.add_rule(Box::new(mft_rules::SystemFileMimicryRule));
        engine.add_rule(Box::new(mft_rules::DeletedExecutableRule));
        engine.add_rule(Box::new(mft_rules::SuspiciousScriptFileRule));
        engine.add_rule(Box::new(mft_rules::TimestompingDetectionRule));

        // Cross-plugin correlation rules (highest-value detections)
        engine.add_rule(Box::new(cross_correlation_rules::ThreadInMalfindRegionRule));
        engine.add_rule(Box::new(cross_correlation_rules::PrivilegeInjectionCorrelationRule));
        engine.add_rule(Box::new(cross_correlation_rules::NetworkPrivilegeCorrelationRule));
        engine.add_rule(Box::new(cross_correlation_rules::HiddenProcessCrossCheckRule));
        engine.add_rule(Box::new(cross_correlation_rules::HiddenHiveCrossCheckRule));
        engine.add_rule(Box::new(cross_correlation_rules::DllInjectionHandleCorrelationRule));

        // SID-based detection rules
        engine.add_rule(Box::new(sid_rules::UnexpectedSystemSidRule));
        engine.add_rule(Box::new(sid_rules::IntegrityLevelAnomalyRule));
        engine.add_rule(Box::new(sid_rules::UnknownSidRule));

        engine
    }

    pub fn add_rule(&mut self, rule: Box<dyn DetectionRule>) {
        self.rules.push(rule);
    }

    /// Run all detection rules with deduplication
    pub fn run_all(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            let rule_findings = rule.detect(data, engine);
            findings.extend(rule_findings);
        }

        // Apply MITRE ATT&CK mappings to any finding missing them
        Self::apply_mitre_mappings(&mut findings);

        // Deduplicate findings based on rule_id + related_pids combination
        // This prevents the same issue being reported multiple times from different data sources
        findings = Self::deduplicate_findings(findings);

        // Sort by severity (highest first), then by timestamp
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
        });

        findings
    }

    /// Apply MITRE ATT&CK technique IDs to findings that don't have them
    fn apply_mitre_mappings(findings: &mut [Finding]) {
        for finding in findings.iter_mut() {
            if finding.mitre_attack.is_some() {
                continue;
            }
            if let Some(mitre) = mitre_mapping_for_rule(&finding.rule_id) {
                finding.mitre_attack = Some(mitre.to_string());
            }
        }
    }
    
    /// Deduplicate findings based on rule_id and related_pids
    /// Keeps the first finding for each unique (rule_id, sorted_pids) combination
    fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
        use std::collections::HashSet;
        
        let mut seen: HashSet<String> = HashSet::new();
        let mut unique_findings = Vec::new();
        
        for finding in findings {
            // Create a deduplication key from rule_id and sorted PIDs
            let mut sorted_pids = finding.related_pids.clone();
            sorted_pids.sort();
            let dedup_key = format!("{}:{:?}:{}", 
                finding.rule_id, 
                sorted_pids,
                // Include title hash for cases where same rule reports different issues
                finding.title.chars().take(50).collect::<String>()
            );
            
            if seen.insert(dedup_key) {
                unique_findings.push(finding);
            }
        }
        
        unique_findings
    }

    /// Run only rules at or above a minimum severity
    pub fn run_filtered(
        &self,
        data: &ParsedData,
        engine: &CorrelationEngine,
        min_severity: Severity,
    ) -> Vec<Finding> {
        self.run_all(data, engine)
            .into_iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Get rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&dyn DetectionRule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
    }

    /// List all rule IDs
    pub fn rule_ids(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.id()).collect()
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::with_default_rules()
    }
}

/// Helper to create a finding with standard fields
pub fn create_finding(
    rule: &dyn DetectionRule,
    title: String,
    description: String,
    evidence: Vec<Evidence>,
) -> Finding {
    // Infer category from rule ID prefix
    let category = infer_category_from_rule_id(rule.id());
    
    Finding {
        id: format!("{}_{}", rule.id(), uuid_simple()),
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category,
        severity: rule.severity(),
        title,
        description,
        evidence,
        mitre_attack: rule.mitre_attack().map(|s| s.to_string()),
        timestamp: None,
        related_pids: vec![],
        related_ips: vec![],
        related_files: vec![],
        confidence: 0.8,
        threat_intel: None,
    }
}

/// Create a finding with explicit category
pub fn create_finding_with_category(
    rule: &dyn DetectionRule,
    title: String,
    description: String,
    evidence: Vec<Evidence>,
    category: FindingCategory,
) -> Finding {
    Finding {
        id: format!("{}_{}", rule.id(), uuid_simple()),
        rule_id: rule.id().to_string(),
        rule_name: rule.name().to_string(),
        category,
        severity: rule.severity(),
        title,
        description,
        evidence,
        mitre_attack: rule.mitre_attack().map(|s| s.to_string()),
        timestamp: None,
        related_pids: vec![],
        related_ips: vec![],
        related_files: vec![],
        confidence: 0.8,
        threat_intel: None,
    }
}

/// Infer finding category from rule ID prefix
fn infer_category_from_rule_id(rule_id: &str) -> FindingCategory {
    match rule_id {
        id if id.starts_with("PROC") => FindingCategory::Process,
        id if id.starts_with("NET") => FindingCategory::Network,
        id if id.starts_with("DLL") => FindingCategory::Dll,
        id if id.starts_with("SVC") || id.starts_with("SERV") => FindingCategory::Service,
        id if id.starts_with("REG") => FindingCategory::Registry,
        id if id.starts_with("INJ") || id.starts_with("MALF") => FindingCategory::Injection,
        id if id.starts_with("CRED") || id.starts_with("HNDL") => FindingCategory::Credential,
        id if id.starts_with("PERS") => FindingCategory::Persistence,
        id if id.starts_with("ROOT") || id.starts_with("HIDDEN") || id.starts_with("MOD1") => FindingCategory::Rootkit,
        id if id.starts_with("CHAIN") => FindingCategory::Chain,
        id if id.starts_with("SIG") => FindingCategory::Process,
        id if id.starts_with("THRD") => FindingCategory::Thread,
        id if id.starts_with("PRIV") || id.starts_with("SID") => FindingCategory::Privilege,
        id if id.starts_with("CERT") => FindingCategory::Certificate,
        id if id.starts_with("MFT") => FindingCategory::Filesystem,
        id if id.starts_with("INTEG") => FindingCategory::Integrity,
        id if id.starts_with("XCOR") => FindingCategory::Injection, // Cross-correlation rules
        _ => FindingCategory::Other,
    }
}

/// Generate a simple pseudo-random ID
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos % 0xFFFFFFFF)
}

/// Centralized MITRE ATT&CK technique mapping for all detection rules.
/// Returns the MITRE technique ID(s) for a given rule_id.
fn mitre_mapping_for_rule(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        // Process rules
        "PROC001" => Some("T1036"),          // Masquerading (orphaned process)
        "PROC002" => Some("T1055,T1059"),    // Process Injection + Command Interpreter
        "PROC003" => Some("T1027,T1059.001"),// Obfuscated Files + PowerShell
        "PROC004" => Some("T1036.004"),      // Masquerade Task/Service (svchost anomaly)
        "PROC005" => Some("T1574.001"),      // DLL Search Order Hijacking
        "PROC006" => Some("T1059"),          // Command and Scripting Interpreter
        "PROC010" => Some("T1036.005"),      // Match Legitimate Name or Location

        // Parent-child rules
        "PC001" => Some("T1055,T1059"),      // Suspicious parent-child
        "PC002" => Some("T1003.001"),        // LSASS parent anomaly → OS Credential Dumping
        "PC003" => Some("T1036.005"),        // Duplicate system process

        // Network rules
        "NET001" => Some("T1071"),           // Application Layer Protocol
        "NET002" => Some("T1571"),           // Non-Standard Port
        "NET003" => Some("T1071.001"),       // Web Protocols
        "NET004" => Some("T1071"),           // Unusual process connection
        "NET005" => Some("T1571"),           // Listening port analysis
        "NET006" => Some("T1071,T1573"),     // C2 Beaconing
        "NET007" => Some("T1021,T1570"),     // Remote Services + Lateral Tool Transfer

        // Injection rules
        "INJ001" => Some("T1055"),           // Process Injection (malfind)
        "INJ002" => Some("T1055.012"),       // Process Hollowing (RWX memory)
        "INJ003" => Some("T1055.001"),       // Dynamic-link Library Injection (MZ header)
        "INJ004" => Some("T1055"),           // Process Injection via cmdline
        "INJ005" => Some("T1055.004"),       // Asynchronous Procedure Call (VAD injection)
        "INJ006" => Some("T1055"),           // Malfind string extraction
        "INJ007" => Some("T1055.001"),       // Hidden module from loader lists (ldrmodules)

        // Persistence rules
        "PERS001" => Some("T1547.001"),      // Registry Run Keys
        "PERS002" | "SERV001" => Some("T1543.003"), // Windows Service
        "PERS003" => Some("T1053.005"),      // Scheduled Task

        // Signature rules
        "SIG001" => Some("T1036.001"),       // Invalid Code Signature (unsigned system)
        "SIG002" => Some("T1553.002"),       // Code Signing Policy Modification
        "SIG003" => Some("T1553.002"),       // Non-Microsoft signer

        // Integrity rules (rootkit/hiding)
        "INTEG001" | "HIDDEN001" => Some("T1014"), // Rootkit (hidden process)
        "INTEG002" | "HIDDEN002" => Some("T1014"), // Rootkit (hidden hive)
        "INTEG003" => Some("T1070.006"),     // Timestomp
        "INTEG004" | "MOD1" => Some("T1014"),// Rootkit (suspicious kernel module)
        "INTEG005" => Some("T1082"),         // System Information Discovery
        "INTEG006" => Some("T1014"),         // IDT hook anomaly
        "INTEG007" => Some("T1014"),         // IRP hook anomaly
        "INTEG008" => Some("T1055"),         // Suspicious atom patterns

        // Credential rules
        "CRED001" | "HNDL001" => Some("T1003.001"), // LSASS Memory
        "CRED002" => Some("T1003.001,T1055.001"),    // LSASS DLL Injection
        "CRED003" => Some("T1003"),          // OS Credential Dumping
        "CRED004" => Some("T1059"),          // Suspicious console command
        "CRED005" => Some("T1003.005"),      // Cached Credentials
        "CRED006" => Some("T1003.001"),      // LSASS targeting
        "CRED007" | "HNDL002" => Some("T1003"), // Handle/mutex analysis

        // Chain rules (multi-stage attacks)
        "CHAIN001" => Some("T1055.012"),     // Process Hollowing Chain
        "CHAIN002" => Some("T1082,T1057"),   // Reconnaissance Chain
        "CHAIN003" => Some("T1547,T1543"),   // Persistence Chain
        "CHAIN004" => Some("T1014,T1543.003"), // Kernel rootkit chain

        // Thread rules
        "THRD001" => Some("T1055"),          // Orphaned thread → injection indicator
        "THRD002" => Some("T1055"),          // Suspicious thread start
        "THRD003" => Some("T1055"),          // System process thread anomaly
        "THRD004" => Some("T1055"),          // Thread count anomaly

        // Privilege rules
        "PRIV001" => Some("T1134"),          // Access Token Manipulation (debug privilege)
        "PRIV002" => Some("T1134"),          // TCB privilege abuse
        "PRIV003" => Some("T1543.003"),      // Load driver → kernel module
        "PRIV004" => Some("T1134"),          // Multiple dangerous privileges
        "PRIV005" => Some("T1134.001"),      // Token Impersonation

        // Certificate rules
        "CERT001" => Some("T1553.004"),      // Install Root Certificate (rogue CA)
        "CERT002" => Some("T1553.004"),      // Mimicked CA
        "CERT003" => Some("T1553.002"),      // Known malware cert
        "CERT004" => Some("T1553.004"),      // Self-signed root
        "CERT005" => Some("T1553.004"),      // Certificate store anomaly

        // MFT/Filesystem rules
        "MFT001" => Some("T1204.002"),       // Executables in temp → User Execution
        "MFT002" => Some("T1036.007"),       // Double Extension
        "MFT003" => Some("T1564.004"),       // NTFS Alternate Data Streams
        "MFT004" => Some("T1036.005"),       // System file mimicry
        "MFT005" => Some("T1070.004"),       // File Deletion (deleted executable)
        "MFT006" => Some("T1059.005"),       // Suspicious script → Visual Basic
        "MFT007" => Some("T1070.006"),       // Timestomping

        // Cross-correlation rules
        "XCOR001" => Some("T1055"),          // Thread in malfind region
        "XCOR002" => Some("T1055,T1134"),    // Privilege + injection
        "XCOR003" => Some("T1071,T1134"),    // Network + privilege
        "XCOR004" => Some("T1014"),          // Hidden process cross-check
        "XCOR005" => Some("T1014"),          // Hidden hive cross-check
        "XCOR006" => Some("T1055.001,T1003"),// DLL injection + handle

        // SID rules
        "SID001" => Some("T1134"),           // Unexpected system SID
        "SID002" => Some("T1134"),           // Integrity level anomaly
        "SID003" => Some("T1134"),           // Unknown SID

        _ => None,
    }
}
