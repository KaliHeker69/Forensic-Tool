//! Risk scoring module for findings

use crate::{Finding, Severity};

/// Calculate overall risk score for an analysis
pub struct RiskScorer;

impl RiskScorer {
    /// Calculate aggregate risk score (0-100)
    pub fn calculate(&self, findings: &[Finding]) -> u8 {
        if findings.is_empty() {
            return 0;
        }

        // Count by severity
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

        // Capped severity contributions prevent any single tier from dominating
        let critical_contrib = ((critical as f64) * 25.0).min(50.0);
        let high_contrib = ((high as f64) * 15.0).min(35.0);
        let medium_contrib = ((medium as f64) * 8.0).min(20.0);
        let low_contrib = ((low as f64) * 3.0).min(10.0);

        let mut score = critical_contrib + high_contrib + medium_contrib + low_contrib;

        // Weight confidence by severity: only High+ findings contribute to confidence multiplier
        // This prevents large numbers of Low/Info findings from diluting the score
        let high_plus: Vec<_> = findings.iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .collect();
        let avg_confidence: f64 = if high_plus.is_empty() {
            findings.iter().map(|f| f.confidence as f64).sum::<f64>()
                / findings.len() as f64
        } else {
            high_plus.iter().map(|f| f.confidence as f64).sum::<f64>()
                / high_plus.len() as f64
        };
        score *= 0.5 + (avg_confidence * 0.5);

        score.min(100.0) as u8
    }

    /// Get risk level description
    pub fn risk_level(score: u8) -> &'static str {
        match score {
            0..=20 => "LOW",
            21..=40 => "MODERATE",
            41..=60 => "ELEVATED",
            61..=80 => "HIGH",
            _ => "CRITICAL",
        }
    }

    /// Get risk level color (for CLI output)
    pub fn risk_color(score: u8) -> &'static str {
        match score {
            0..=20 => "green",
            21..=40 => "yellow",
            41..=60 => "bright yellow",
            61..=80 => "red",
            _ => "bright red",
        }
    }
}

/// Summary statistics for an analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub risk_score: u8,
    pub risk_level: String,
    pub unique_pids: usize,
    pub unique_ips: usize,
    pub unique_files: usize,
}

impl AnalysisSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        use std::collections::HashSet;

        let scorer = RiskScorer;
        let risk_score = scorer.calculate(findings);

        let pids: HashSet<_> = findings.iter().flat_map(|f| &f.related_pids).collect();
        let ips: HashSet<_> = findings.iter().flat_map(|f| &f.related_ips).collect();
        let files: HashSet<_> = findings.iter().flat_map(|f| &f.related_files).collect();

        Self {
            total_findings: findings.len(),
            critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info_count: findings.iter().filter(|f| f.severity == Severity::Info).count(),
            risk_score,
            risk_level: RiskScorer::risk_level(risk_score).to_string(),
            unique_pids: pids.len(),
            unique_ips: ips.len(),
            unique_files: files.len(),
        }
    }
}
