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

        // Injection rules
        engine.add_rule(Box::new(injection_rules::MalfindDetectionRule));
        engine.add_rule(Box::new(injection_rules::RwxMemoryRule));
        engine.add_rule(Box::new(injection_rules::MzHeaderRule));
        engine.add_rule(Box::new(injection_rules::ProcessInjectionCmdlineRule));
        engine.add_rule(Box::new(injection_rules::VadInjectionRule));
        engine.add_rule(Box::new(injection_rules::MalfindStringExtractionRule));

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
