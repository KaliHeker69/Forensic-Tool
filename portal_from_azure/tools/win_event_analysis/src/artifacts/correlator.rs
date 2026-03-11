//! Cross-Artifact Correlator - Correlate findings across MFT, Registry, and USN data
//! Provides unified timeline and cross-referenced detection

use std::collections::HashMap;
use chrono::{DateTime, NaiveDateTime, Utc};

use super::mft_analyzer::{MftRecord, Detection, DetectionType, MftAnalyzer};
use super::behavioral_analyzer::{BehaviorAlert, BehaviorType, BehavioralAnalyzer};
use super::config::Severity;

// =============================================================================
// CORRELATION TYPES
// =============================================================================

#[derive(Debug, Clone)]
pub enum CorrelationType {
    TimestompingConfirmation,   // MFT SI<FN + Shimcache mismatch
    FileLifecycle,               // Create -> Modify -> Delete across artifacts
    PersistenceValidation,       // Registry key -> actual binary in MFT
    AntiForensicsChain,          // Multiple anti-forensics indicators
    AttackSequence,              // Ordered attack events
}

impl std::fmt::Display for CorrelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationType::TimestompingConfirmation => write!(f, "Timestomping Confirmation"),
            CorrelationType::FileLifecycle => write!(f, "File Lifecycle"),
            CorrelationType::PersistenceValidation => write!(f, "Persistence Validation"),
            CorrelationType::AntiForensicsChain => write!(f, "Anti-Forensics Chain"),
            CorrelationType::AttackSequence => write!(f, "Attack Sequence"),
        }
    }
}

// =============================================================================
// CORRELATED FINDING
// =============================================================================

#[derive(Debug, Clone)]
pub struct CorrelatedFinding {
    pub correlation_type: CorrelationType,
    pub severity: Severity,
    pub description: String,
    pub sources: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub confidence: f64,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub details: String,
}

// =============================================================================
// UNIFIED TIMELINE
// =============================================================================

#[derive(Debug, Clone)]
pub struct UnifiedTimelineEntry {
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub file_path: String,
    pub description: String,
    pub mitre_technique: String,
}

impl UnifiedTimelineEntry {
    pub fn to_csv_row(&self) -> String {
        format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            self.timestamp,
            self.source,
            self.event_type,
            self.severity,
            self.file_path,
            self.description,
            self.mitre_technique,
        )
    }
}

// =============================================================================
// CROSS-ARTIFACT CORRELATOR
// =============================================================================

pub struct CrossArtifactCorrelator {
    mft_detections: Vec<Detection>,
    behavior_alerts: Vec<BehaviorAlert>,
    correlated_findings: Vec<CorrelatedFinding>,
    unified_timeline: Vec<UnifiedTimelineEntry>,
}

impl CrossArtifactCorrelator {
    pub fn new() -> Self {
        CrossArtifactCorrelator {
            mft_detections: Vec::new(),
            behavior_alerts: Vec::new(),
            correlated_findings: Vec::new(),
            unified_timeline: Vec::new(),
        }
    }

    /// Load MFT detections
    pub fn load_mft_detections(&mut self, detections: Vec<Detection>) {
        self.mft_detections = detections;
    }

    /// Load behavioral alerts
    pub fn load_behavior_alerts(&mut self, alerts: Vec<BehaviorAlert>) {
        self.behavior_alerts = alerts;
    }

    /// Run correlation analysis
    pub fn correlate(&mut self) -> &Vec<CorrelatedFinding> {
        self.correlated_findings.clear();

        // Correlate timestomping with other evidence
        self.correlate_timestomping();

        // Correlate anti-forensics chain
        self.correlate_anti_forensics();

        // Build attack sequence
        self.build_attack_sequence();

        &self.correlated_findings
    }

    /// Build unified timeline from all sources
    pub fn build_unified_timeline(&mut self) -> &Vec<UnifiedTimelineEntry> {
        self.unified_timeline.clear();

        // Add MFT detections to timeline
        for detection in &self.mft_detections {
            self.unified_timeline.push(UnifiedTimelineEntry {
                timestamp: detection.timestamp.clone(),
                source: "MFT".to_string(),
                event_type: detection.detection_type.clone(),
                severity: detection.severity.clone(),
                file_path: detection.file_path.clone(),
                description: detection.description.clone(),
                mitre_technique: detection.mitre_technique.clone(),
            });
        }

        // Add behavioral alerts to timeline
        for alert in &self.behavior_alerts {
            self.unified_timeline.push(UnifiedTimelineEntry {
                timestamp: alert.timestamp.clone(),
                source: "Behavioral".to_string(),
                event_type: alert.behavior_type.to_string(),
                severity: alert.severity.to_string(),
                file_path: String::new(),
                description: alert.description.clone(),
                mitre_technique: alert.mitre_techniques.join(", "),
            });
        }

        // Sort by timestamp
        self.unified_timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        &self.unified_timeline
    }

    /// Correlate timestomping evidence across artifacts
    fn correlate_timestomping(&mut self) {
        let timestomped: Vec<&Detection> = self.mft_detections
            .iter()
            .filter(|d| d.detection_type == "Timestomping" || d.detection_type == "Timestomping (Subsecond Zeros)")
            .collect();

        if timestomped.is_empty() {
            return;
        }

        // Check if any anti-forensics behavioral alert exists
        let has_anti_forensics = self.behavior_alerts
            .iter()
            .any(|a| matches!(a.behavior_type, BehaviorType::AntiForensics));

        if has_anti_forensics {
            let mut timeline_events: Vec<TimelineEvent> = Vec::new();
            
            for ts in &timestomped {
                timeline_events.push(TimelineEvent {
                    timestamp: ts.timestamp.clone(),
                    source: "MFT".to_string(),
                    event_type: "Timestomping".to_string(),
                    details: ts.file_path.clone(),
                });
            }

            self.correlated_findings.push(CorrelatedFinding {
                correlation_type: CorrelationType::TimestompingConfirmation,
                severity: Severity::Critical,
                description: format!(
                    "Timestomping confirmed: {} files with SI<FN mismatch and anti-forensics activity",
                    timestomped.len()
                ),
                sources: vec!["MFT".to_string(), "Behavioral".to_string()],
                timeline: timeline_events,
                confidence: 0.95,
                mitre_techniques: vec!["T1070.006".to_string()],
            });
        }
    }

    /// Correlate anti-forensics chain
    fn correlate_anti_forensics(&mut self) {
        let mut af_indicators: Vec<TimelineEvent> = Vec::new();

        // Collect anti-forensics from MFT
        for detection in &self.mft_detections {
            if detection.detection_type.contains("Deleted") 
                || detection.detection_type.contains("Timestomping") 
            {
                af_indicators.push(TimelineEvent {
                    timestamp: detection.timestamp.clone(),
                    source: "MFT".to_string(),
                    event_type: detection.detection_type.clone(),
                    details: detection.file_path.clone(),
                });
            }
        }

        // Check for anti-forensics behavioral alerts
        for alert in &self.behavior_alerts {
            if matches!(alert.behavior_type, BehaviorType::AntiForensics) {
                for evidence in &alert.evidence {
                    af_indicators.push(TimelineEvent {
                        timestamp: evidence.timestamp.clone(),
                        source: "Behavioral".to_string(),
                        event_type: alert.behavior_type.to_string(),
                        details: evidence.indicator.clone(),
                    });
                }
            }
        }

        if af_indicators.len() >= 3 {
            // Sort by timestamp
            af_indicators.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

            self.correlated_findings.push(CorrelatedFinding {
                correlation_type: CorrelationType::AntiForensicsChain,
                severity: Severity::Critical,
                description: format!(
                    "Anti-forensics chain detected: {} indicators across {} sources",
                    af_indicators.len(),
                    vec!["MFT", "Behavioral"].len()
                ),
                sources: vec!["MFT".to_string(), "Behavioral".to_string()],
                timeline: af_indicators,
                confidence: 0.9,
                mitre_techniques: vec![
                    "T1070".to_string(),
                    "T1070.001".to_string(),
                    "T1070.004".to_string(),
                    "T1070.006".to_string(),
                ],
            });
        }
    }

    /// Build comprehensive attack sequence
    fn build_attack_sequence(&mut self) {
        // Check for multiple critical behavioral alerts
        let critical_alerts: Vec<&BehaviorAlert> = self.behavior_alerts
            .iter()
            .filter(|a| matches!(a.severity, Severity::Critical))
            .collect();

        if critical_alerts.len() >= 2 {
            let mut timeline_events: Vec<TimelineEvent> = Vec::new();
            let mut attack_phases: Vec<String> = Vec::new();

            for alert in &critical_alerts {
                timeline_events.push(TimelineEvent {
                    timestamp: alert.timestamp.clone(),
                    source: "Behavioral".to_string(),
                    event_type: alert.behavior_type.to_string(),
                    details: alert.description.clone(),
                });
                attack_phases.push(alert.behavior_type.to_string());
            }

            self.correlated_findings.push(CorrelatedFinding {
                correlation_type: CorrelationType::AttackSequence,
                severity: Severity::Critical,
                description: format!(
                    "Attack sequence detected: {}",
                    attack_phases.join(" → ")
                ),
                sources: vec!["Behavioral".to_string()],
                timeline: timeline_events,
                confidence: 0.85,
                mitre_techniques: critical_alerts
                    .iter()
                    .flat_map(|a| a.mitre_techniques.clone())
                    .collect(),
            });
        }
    }

    /// Get correlated findings
    pub fn get_findings(&self) -> &Vec<CorrelatedFinding> {
        &self.correlated_findings
    }

    /// Get unified timeline
    pub fn get_timeline(&self) -> &Vec<UnifiedTimelineEntry> {
        &self.unified_timeline
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        
        summary.insert("mft_detections".to_string(), self.mft_detections.len());
        summary.insert("behavior_alerts".to_string(), self.behavior_alerts.len());
        summary.insert("correlated_findings".to_string(), self.correlated_findings.len());
        summary.insert("timeline_entries".to_string(), self.unified_timeline.len());

        // Count by correlation type
        for finding in &self.correlated_findings {
            let key = format!("correlation_{}", finding.correlation_type);
            *summary.entry(key).or_insert(0) += 1;
        }

        // Critical findings
        let critical = self.correlated_findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        summary.insert("critical_findings".to_string(), critical);

        summary
    }

    /// Export unified timeline to CSV
    pub fn export_timeline(&self, output_path: &str) -> Result<(), std::io::Error> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(output_path)?;
        
        writeln!(file, "Timestamp,Source,EventType,Severity,FilePath,Description,MitreTechnique")?;
        
        for entry in &self.unified_timeline {
            writeln!(file, "{}", entry.to_csv_row())?;
        }

        Ok(())
    }
}

impl Default for CrossArtifactCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// FORENSIC SCORER
// =============================================================================

/// Calculate an overall forensic score based on findings
pub fn calculate_forensic_score(
    mft_detections: &[Detection],
    behavior_alerts: &[BehaviorAlert],
    correlated_findings: &[CorrelatedFinding],
) -> ForensicScore {
    let mut score = 0;
    let mut factors: Vec<String> = Vec::new();

    // Timestomping (high weight)
    let timestomping_count = mft_detections
        .iter()
        .filter(|d| d.detection_type.contains("Timestomping"))
        .count();
    if timestomping_count > 0 {
        score += 50;
        factors.push(format!("Timestomping: {} files", timestomping_count));
    }

    // Credential dumping (very high weight)
    let cred_dump = behavior_alerts
        .iter()
        .filter(|a| matches!(a.behavior_type, BehaviorType::CredentialDumping))
        .count();
    if cred_dump > 0 {
        score += 40;
        factors.push("Credential Dumping detected".to_string());
    }

    // Anti-forensics (high weight)
    let anti_forensics = behavior_alerts
        .iter()
        .filter(|a| matches!(a.behavior_type, BehaviorType::AntiForensics))
        .count();
    if anti_forensics > 0 {
        score += 40;
        factors.push("Anti-Forensics activity detected".to_string());
    }

    // Lateral movement (medium weight)
    let lateral = behavior_alerts
        .iter()
        .filter(|a| matches!(a.behavior_type, BehaviorType::LateralMovement))
        .count();
    if lateral > 0 {
        score += 25;
        factors.push("Lateral Movement detected".to_string());
    }

    // Correlated findings bonus
    if !correlated_findings.is_empty() {
        score += correlated_findings.len() * 10;
        factors.push(format!("{} cross-artifact correlations", correlated_findings.len()));
    }

    // Deleted suspicious files
    let deleted = mft_detections
        .iter()
        .filter(|d| d.detection_type == "Deleted File")
        .count();
    if deleted > 0 {
        score += (deleted * 5).min(30);
        factors.push(format!("{} suspicious deleted files", deleted));
    }

    // Determine verdict
    let verdict = if score >= 100 {
        "CRITICAL - Active compromise likely"
    } else if score >= 60 {
        "HIGH - Significant suspicious activity"
    } else if score >= 30 {
        "MEDIUM - Investigation recommended"
    } else if score > 0 {
        "LOW - Minor anomalies detected"
    } else {
        "CLEAN - No significant indicators"
    };

    ForensicScore {
        score: score.min(200),
        verdict: verdict.to_string(),
        factors,
    }
}

#[derive(Debug, Clone)]
pub struct ForensicScore {
    pub score: usize,
    pub verdict: String,
    pub factors: Vec<String>,
}
