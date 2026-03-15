//! Kill Chain Mapping & Attack Progression Analysis
//!
//! Maps findings to Cyber Kill Chain stages and MITRE ATT&CK tactics,
//! computes an attack progression score, and generates an executive narrative.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::{Finding, FindingCategory, Severity};

// ═══════════════════════════════════════════════════════════════════
// Kill Chain Stages
// ═══════════════════════════════════════════════════════════════════

/// Cyber Kill Chain stage (Lockheed Martin model)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum KillChainStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl KillChainStage {
    pub fn all() -> &'static [KillChainStage] {
        &[
            KillChainStage::Reconnaissance,
            KillChainStage::Weaponization,
            KillChainStage::Delivery,
            KillChainStage::Exploitation,
            KillChainStage::Installation,
            KillChainStage::CommandAndControl,
            KillChainStage::ActionsOnObjectives,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "Reconnaissance",
            KillChainStage::Weaponization => "Weaponization",
            KillChainStage::Delivery => "Delivery",
            KillChainStage::Exploitation => "Exploitation",
            KillChainStage::Installation => "Installation",
            KillChainStage::CommandAndControl => "Command & Control",
            KillChainStage::ActionsOnObjectives => "Actions on Objectives",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "Recon",
            KillChainStage::Weaponization => "Weaponize",
            KillChainStage::Delivery => "Deliver",
            KillChainStage::Exploitation => "Exploit",
            KillChainStage::Installation => "Install",
            KillChainStage::CommandAndControl => "C2",
            KillChainStage::ActionsOnObjectives => "Actions",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "🔍",
            KillChainStage::Weaponization => "⚙️",
            KillChainStage::Delivery => "📦",
            KillChainStage::Exploitation => "💥",
            KillChainStage::Installation => "📥",
            KillChainStage::CommandAndControl => "📡",
            KillChainStage::ActionsOnObjectives => "🎯",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            KillChainStage::Reconnaissance => "#58a6ff",
            KillChainStage::Weaponization => "#a371f7",
            KillChainStage::Delivery => "#ffa657",
            KillChainStage::Exploitation => "#ff7b72",
            KillChainStage::Installation => "#d2a8ff",
            KillChainStage::CommandAndControl => "#f78166",
            KillChainStage::ActionsOnObjectives => "#da3633",
        }
    }

    /// Ordinal position (0-6) for progression scoring
    pub fn ordinal(&self) -> u8 {
        match self {
            KillChainStage::Reconnaissance => 0,
            KillChainStage::Weaponization => 1,
            KillChainStage::Delivery => 2,
            KillChainStage::Exploitation => 3,
            KillChainStage::Installation => 4,
            KillChainStage::CommandAndControl => 5,
            KillChainStage::ActionsOnObjectives => 6,
        }
    }
}

impl std::fmt::Display for KillChainStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ═══════════════════════════════════════════════════════════════════
// MITRE ATT&CK Tactics
// ═══════════════════════════════════════════════════════════════════

/// MITRE ATT&CK tactic (Enterprise matrix)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn all() -> &'static [MitreTactic] {
        &[
            MitreTactic::Reconnaissance,
            MitreTactic::ResourceDevelopment,
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
            MitreTactic::Exfiltration,
            MitreTactic::Impact,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "Reconnaissance",
            MitreTactic::ResourceDevelopment => "Resource Development",
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command & Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
        }
    }

    pub fn short_id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
        }
    }

    /// Map to corresponding Kill Chain stage
    pub fn to_kill_chain_stage(&self) -> KillChainStage {
        match self {
            MitreTactic::Reconnaissance | MitreTactic::Discovery => KillChainStage::Reconnaissance,
            MitreTactic::ResourceDevelopment => KillChainStage::Weaponization,
            MitreTactic::InitialAccess => KillChainStage::Delivery,
            MitreTactic::Execution | MitreTactic::PrivilegeEscalation => KillChainStage::Exploitation,
            MitreTactic::Persistence | MitreTactic::DefenseEvasion => KillChainStage::Installation,
            MitreTactic::CommandAndControl => KillChainStage::CommandAndControl,
            MitreTactic::CredentialAccess
            | MitreTactic::LateralMovement
            | MitreTactic::Collection
            | MitreTactic::Exfiltration
            | MitreTactic::Impact => KillChainStage::ActionsOnObjectives,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Technique → Tactic Mapping
// ═══════════════════════════════════════════════════════════════════

/// Map a MITRE ATT&CK technique ID to its tactic(s)
fn technique_to_tactics(technique_id: &str) -> Vec<MitreTactic> {
    // Strip sub-technique suffix for top-level matching
    let base = technique_id.split('.').next().unwrap_or(technique_id);

    match base {
        // Initial Access
        "T1189" | "T1190" | "T1195" | "T1199" | "T1200"
        | "T1566" => vec![MitreTactic::InitialAccess],

        // Execution
        "T1059" | "T1106" | "T1204" | "T1569" | "T1047"
        => vec![MitreTactic::Execution],

        // Persistence
        "T1547" | "T1543" | "T1053" | "T1546" | "T1574"
        => vec![MitreTactic::Persistence],

        // Privilege Escalation
        "T1134" => vec![MitreTactic::PrivilegeEscalation],

        // Defense Evasion
        "T1036" | "T1027" | "T1070" | "T1553" | "T1564"
        | "T1218" | "T1112" | "T1014"
        => vec![MitreTactic::DefenseEvasion],

        // Credential Access
        "T1003" => vec![MitreTactic::CredentialAccess],

        // Discovery
        "T1082" | "T1057" | "T1083" | "T1012" | "T1518"
        | "T1049" | "T1016" | "T1087"
        => vec![MitreTactic::Discovery],

        // Lateral Movement
        "T1021" | "T1570" => vec![MitreTactic::LateralMovement],

        // Command and Control
        "T1071" | "T1573" | "T1571" | "T1095" | "T1572"
        | "T1090" | "T1102"
        => vec![MitreTactic::CommandAndControl],

        // Process Injection → Priv Esc + Defense Evasion
        "T1055" => vec![MitreTactic::PrivilegeEscalation, MitreTactic::DefenseEvasion],

        // Exfiltration
        "T1041" | "T1048" | "T1567" => vec![MitreTactic::Exfiltration],

        // Impact
        "T1485" | "T1486" | "T1490" | "T1489" => vec![MitreTactic::Impact],

        _ => {
            // Fallback: try to guess from technique number range
            vec![]
        }
    }
}

/// Map a Finding to kill chain stages (may belong to multiple)
fn finding_to_kill_chain_stages(finding: &Finding) -> Vec<KillChainStage> {
    let mut stages = HashSet::new();

    // 1) Map via MITRE technique → tactic → stage
    if let Some(ref mitre) = finding.mitre_attack {
        for technique in mitre.split(',') {
            let t = technique.trim();
            let tactics = technique_to_tactics(t);
            for tactic in tactics {
                stages.insert(tactic.to_kill_chain_stage());
            }
        }
    }

    // 2) Map via FindingCategory as fallback
    if stages.is_empty() {
        let stage = match finding.category {
            FindingCategory::Network => KillChainStage::CommandAndControl,
            FindingCategory::Injection | FindingCategory::Thread => KillChainStage::Exploitation,
            FindingCategory::Persistence | FindingCategory::Registry
            | FindingCategory::Service => KillChainStage::Installation,
            FindingCategory::Credential | FindingCategory::Privilege => KillChainStage::ActionsOnObjectives,
            FindingCategory::Process | FindingCategory::Dll => KillChainStage::Exploitation,
            FindingCategory::Filesystem => KillChainStage::Delivery,
            FindingCategory::Certificate | FindingCategory::Integrity
            | FindingCategory::Rootkit => KillChainStage::Installation,
            FindingCategory::Chain => KillChainStage::Exploitation,
            FindingCategory::Other => KillChainStage::Reconnaissance,
        };
        stages.insert(stage);
    }

    let mut result: Vec<_> = stages.into_iter().collect();
    result.sort();
    result
}

// ═══════════════════════════════════════════════════════════════════
// Analysis Structures
// ═══════════════════════════════════════════════════════════════════

/// A finding mapped to a kill chain stage
#[derive(Debug, Clone, Serialize)]
pub struct StagedFinding {
    pub finding_id: String,
    pub rule_name: String,
    pub title: String,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
}

/// Summary for one kill chain stage
#[derive(Debug, Clone, Serialize)]
pub struct StageDetail {
    pub stage: KillChainStage,
    pub findings: Vec<StagedFinding>,
    pub finding_count: usize,
    pub max_severity: String,
    pub techniques: Vec<String>,
}

/// A cell in the MITRE ATT&CK matrix heatmap
#[derive(Debug, Clone, Serialize)]
pub struct MatrixCell {
    pub technique_id: String,
    pub tactic: String,
    pub count: usize,
    pub max_severity: String,
    pub finding_titles: Vec<String>,
}

/// Full attack progression analysis
#[derive(Debug, Clone, Serialize)]
pub struct KillChainAnalysis {
    /// Findings grouped by kill chain stage
    pub stages: BTreeMap<u8, StageDetail>,
    /// MITRE ATT&CK matrix cells (technique × tactic)
    pub matrix_cells: Vec<MatrixCell>,
    /// Attack progression score 0–100
    pub progression_score: u8,
    /// Maximum stage reached
    pub max_stage_reached: String,
    /// Unique MITRE techniques observed
    pub unique_techniques: usize,
    /// Unique MITRE tactics observed
    pub unique_tactics: usize,
    /// Executive narrative summary
    pub executive_summary: String,
}

// ═══════════════════════════════════════════════════════════════════
// Analysis Entry Point
// ═══════════════════════════════════════════════════════════════════

/// Run full kill chain analysis on a set of findings
pub fn analyze_kill_chain(findings: &[Finding]) -> KillChainAnalysis {
    // ── Stage mapping ──
    let mut stages: BTreeMap<u8, StageDetail> = BTreeMap::new();
    for stage in KillChainStage::all() {
        stages.insert(
            stage.ordinal(),
            StageDetail {
                stage: *stage,
                findings: Vec::new(),
                finding_count: 0,
                max_severity: "Info".to_string(),
                techniques: Vec::new(),
            },
        );
    }

    let mut all_techniques: HashSet<String> = HashSet::new();
    let mut all_tactics: HashSet<String> = HashSet::new();

    for finding in findings {
        let kc_stages = finding_to_kill_chain_stages(finding);

        let techniques: Vec<String> = finding
            .mitre_attack
            .as_ref()
            .map(|m| m.split(',').map(|t| t.trim().to_string()).collect())
            .unwrap_or_default();

        for t in &techniques {
            all_techniques.insert(t.clone());
            for tactic in technique_to_tactics(t) {
                all_tactics.insert(tactic.label().to_string());
            }
        }

        let staged = StagedFinding {
            finding_id: finding.rule_id.clone(),
            rule_name: finding.rule_name.clone(),
            title: finding.title.clone(),
            severity: format!("{}", finding.severity),
            mitre_techniques: techniques.clone(),
        };

        for stage in &kc_stages {
            if let Some(detail) = stages.get_mut(&stage.ordinal()) {
                detail.findings.push(staged.clone());
                detail.finding_count += 1;
                // Track max severity
                if severity_rank(&finding.severity) > severity_rank_str(&detail.max_severity) {
                    detail.max_severity = format!("{}", finding.severity);
                }
                // Track unique techniques per stage
                for t in &techniques {
                    if !detail.techniques.contains(t) {
                        detail.techniques.push(t.clone());
                    }
                }
            }
        }
    }

    // ── MITRE matrix cells ──
    let matrix_cells = build_matrix_cells(findings);

    // ── Progression score ──
    let stages_populated: Vec<u8> = stages
        .iter()
        .filter(|(_, d)| d.finding_count > 0)
        .map(|(ord, _)| *ord)
        .collect();

    let max_stage_ordinal = stages_populated.iter().max().copied().unwrap_or(0);
    let max_stage = KillChainStage::all()
        .iter()
        .find(|s| s.ordinal() == max_stage_ordinal)
        .unwrap_or(&KillChainStage::Reconnaissance);

    let progression_score = compute_progression_score(&stages_populated, findings);

    // ── Executive summary ──
    let executive_summary = generate_executive_summary(
        findings,
        &stages,
        progression_score,
        max_stage,
        all_techniques.len(),
    );

    KillChainAnalysis {
        stages,
        matrix_cells,
        progression_score,
        max_stage_reached: max_stage.label().to_string(),
        unique_techniques: all_techniques.len(),
        unique_tactics: all_tactics.len(),
        executive_summary,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Progression Score
// ═══════════════════════════════════════════════════════════════════

fn compute_progression_score(populated_stages: &[u8], findings: &[Finding]) -> u8 {
    if populated_stages.is_empty() {
        return 0;
    }

    // Component 1: Stage reach (max stage ordinal / 6 * 40)
    let max_ordinal = populated_stages.iter().max().copied().unwrap_or(0);
    let reach_score = (max_ordinal as f64 / 6.0 * 40.0) as u8;

    // Component 2: Stage coverage (populated / 7 * 25)
    let unique_stages: HashSet<u8> = populated_stages.iter().copied().collect();
    let coverage_score = (unique_stages.len() as f64 / 7.0 * 25.0) as u8;

    // Component 3: Severity weight (critical=4, high=3, medium=2, low=1, info=0)
    let severity_sum: u32 = findings
        .iter()
        .map(|f| severity_rank(&f.severity) as u32)
        .sum();
    let severity_avg = if findings.is_empty() {
        0.0
    } else {
        severity_sum as f64 / findings.len() as f64
    };
    let severity_score = (severity_avg / 4.0 * 20.0).min(20.0) as u8;

    // Component 4: Continuity bonus — consecutive stages filled
    let mut max_consecutive = 0u8;
    let mut current_run = 0u8;
    for ordinal in 0..=6u8 {
        if unique_stages.contains(&ordinal) {
            current_run += 1;
            max_consecutive = max_consecutive.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let continuity_score = (max_consecutive as f64 / 7.0 * 15.0) as u8;

    (reach_score + coverage_score + severity_score + continuity_score).min(100)
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

// ═══════════════════════════════════════════════════════════════════
// MITRE Matrix
// ═══════════════════════════════════════════════════════════════════

fn build_matrix_cells(findings: &[Finding]) -> Vec<MatrixCell> {
    // Group findings by (technique, tactic)
    let mut cells: HashMap<(String, String), MatrixCell> = HashMap::new();

    for finding in findings {
        let techniques: Vec<String> = finding
            .mitre_attack
            .as_ref()
            .map(|m| m.split(',').map(|t| t.trim().to_string()).collect())
            .unwrap_or_default();

        for tech in &techniques {
            let tactics = technique_to_tactics(tech);
            for tactic in &tactics {
                let key = (tech.clone(), tactic.label().to_string());
                let cell = cells.entry(key).or_insert(MatrixCell {
                    technique_id: tech.clone(),
                    tactic: tactic.label().to_string(),
                    count: 0,
                    max_severity: "Info".to_string(),
                    finding_titles: Vec::new(),
                });
                cell.count += 1;
                if severity_rank(&finding.severity) > severity_rank_str(&cell.max_severity) {
                    cell.max_severity = format!("{}", finding.severity);
                }
                let title_snippet: String = finding.title.chars().take(60).collect();
                if !cell.finding_titles.contains(&title_snippet) && cell.finding_titles.len() < 5 {
                    cell.finding_titles.push(title_snippet);
                }
            }
        }
    }

    let mut result: Vec<MatrixCell> = cells.into_values().collect();
    result.sort_by(|a, b| a.tactic.cmp(&b.tactic).then(a.technique_id.cmp(&b.technique_id)));
    result
}

// ═══════════════════════════════════════════════════════════════════
// Executive Summary Narrative
// ═══════════════════════════════════════════════════════════════════

fn generate_executive_summary(
    findings: &[Finding],
    stages: &BTreeMap<u8, StageDetail>,
    progression_score: u8,
    max_stage: &KillChainStage,
    unique_techniques: usize,
) -> String {
    if findings.is_empty() {
        return "No findings were detected during the analysis. The memory image appears clean based on the current rule set.".to_string();
    }

    let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
    let total = findings.len();
    let populated_stages: Vec<&StageDetail> = stages.values().filter(|d| d.finding_count > 0).collect();

    // ── Threat level assessment ──
    let threat_level = if progression_score >= 70 || critical_count >= 3 {
        "SEVERE"
    } else if progression_score >= 45 || critical_count >= 1 || high_count >= 5 {
        "HIGH"
    } else if progression_score >= 25 || high_count >= 2 {
        "MODERATE"
    } else {
        "LOW"
    };

    let mut narrative = String::new();

    // Opening
    narrative.push_str(&format!(
        "Threat Assessment: {}. The analysis of this memory image identified {} findings across {} technique{} spanning {} of 7 Cyber Kill Chain stages. ",
        threat_level,
        total,
        unique_techniques,
        if unique_techniques != 1 { "s" } else { "" },
        populated_stages.len(),
    ));

    // Progression note
    narrative.push_str(&format!(
        "Attack progression has reached the \"{}\" stage (score: {}/100). ",
        max_stage.label(),
        progression_score,
    ));

    // Critical findings callout
    if critical_count > 0 {
        narrative.push_str(&format!(
            "{} critical-severity finding{} require{} immediate attention. ",
            critical_count,
            if critical_count != 1 { "s" } else { "" },
            if critical_count == 1 { "s" } else { "" },
        ));
    }

    // Summarize active stages
    for detail in stages.values().filter(|d| d.finding_count > 0) {
        match detail.stage {
            KillChainStage::Reconnaissance => {
                narrative.push_str(&format!(
                    "Reconnaissance activity detected ({} finding{}) including system enumeration and network discovery. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            KillChainStage::Delivery => {
                narrative.push_str(&format!(
                    "Delivery mechanisms identified ({} finding{}) — suspicious files or initial access vectors were observed. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            KillChainStage::Exploitation => {
                narrative.push_str(&format!(
                    "Active exploitation evidence ({} finding{}) including process injection, code execution, or privilege escalation. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            KillChainStage::Installation => {
                narrative.push_str(&format!(
                    "Persistence/installation indicators ({} finding{}) suggest the attacker has established footholds via registry, services, or defense evasion. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            KillChainStage::CommandAndControl => {
                narrative.push_str(&format!(
                    "Command-and-control (C2) activity detected ({} finding{}) — network beaconing, suspicious connections, or encrypted channels observed. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            KillChainStage::ActionsOnObjectives => {
                narrative.push_str(&format!(
                    "Actions-on-objectives evidence ({} finding{}) including credential theft, lateral movement, or data staging. ",
                    detail.finding_count,
                    if detail.finding_count != 1 { "s" } else { "" },
                ));
            }
            _ => {}
        }
    }

    // Recommendation
    if threat_level == "SEVERE" || threat_level == "HIGH" {
        narrative.push_str("RECOMMENDATION: Immediate incident response is advised. Isolate the affected host, preserve additional evidence, and initiate threat hunting across the environment.");
    } else if threat_level == "MODERATE" {
        narrative.push_str("RECOMMENDATION: Further investigation is warranted. Priority should be given to the critical and high-severity findings. Monitor the host for additional indicators.");
    } else {
        narrative.push_str("RECOMMENDATION: The findings should be reviewed in context. Low-severity indicators may represent normal system behavior but should be correlated with other data sources.");
    }

    narrative
}
