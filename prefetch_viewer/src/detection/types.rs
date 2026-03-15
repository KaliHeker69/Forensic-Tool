use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Self::Low => 0,
            Self::Medium => 5,
            Self::High => 15,
            Self::Critical => 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCategory {
    ExecutionLocation,
    KnownBadName,
    SensitiveFileReference,
    BeaconingPattern,
    HashMismatch,
    SingleRunTool,
    UncNetworkPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: RuleCategory,
    pub severity: Severity,
    pub rule_name: String,
    pub matched_value: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub file_id: String,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub summary: SeveritySummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl AnalysisResult {
    pub fn compute(file_id: String, findings: Vec<Finding>) -> Self {
        let mut summary = SeveritySummary::default();
        let mut raw_score: u32 = 0;
        for f in &findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
            raw_score += f.severity.score();
        }
        Self {
            file_id,
            findings,
            score: raw_score.min(100),
            summary,
        }
    }
}
