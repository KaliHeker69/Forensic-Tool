//! INTEG003 – TimestampAnomalyRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect timestamp anomalies in process structures
/// Tampered timestamps are indicators of anti-forensics
pub struct TimestampAnomalyRule;

impl DetectionRule for TimestampAnomalyRule {
    fn id(&self) -> &str {
        "INTEG003"
    }

    fn name(&self) -> &str {
        "Process Timestamp Anomaly"
    }

    fn description(&self) -> &str {
        "Detects processes with suspicious timestamps (future dates, epoch, etc.)"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1070.006") // Indicator Removal: Timestomp
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        use chrono::{TimeZone, Utc};
        
        let mut findings = Vec::new();
        
        // Common suspicious timestamps
        let unix_epoch = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let windows_epoch = Utc.with_ymd_and_hms(1601, 1, 1, 0, 0, 0).unwrap();
        let now = Utc::now();
        
        for proc in &data.processes {
            if let Some(create_time) = proc.create_time {
                let mut anomaly_reason = None;
                
                // Check for UNIX epoch (01-01-1970)
                if create_time.date_naive() == unix_epoch.date_naive() {
                    anomaly_reason = Some("UNIX epoch (1970-01-01) - possible default/unset value");
                }
                
                // Check for Windows epoch (extremely old)
                if create_time < windows_epoch {
                    anomaly_reason = Some("Before Windows epoch (1601) - corrupted timestamp");
                }
                
                // Check for future timestamps
                if create_time > now + chrono::Duration::hours(24) {
                    anomaly_reason = Some("Future timestamp - possible timestomping or clock skew");
                }
                
                if let Some(reason) = anomaly_reason {
                    let mut finding = create_finding(
                        self,
                        format!("Timestamp anomaly: {} (PID {})", proc.name, proc.pid),
                        format!(
                            "Process '{}' (PID {}) has an anomalous creation timestamp: {:?}. \
                            Reason: {}",
                            proc.name, proc.pid, create_time, reason
                        ),
                        vec![Evidence {
                            source_plugin: "psscan".to_string(),
                            source_file: String::new(),
                            line_number: None,
                            data: format!("CreateTime: {:?}", create_time),
                        }],
                    );
                    finding.related_pids = vec![proc.pid];
                    finding.confidence = 0.60;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
