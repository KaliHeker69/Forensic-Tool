//! PERS003 – SuspiciousScheduledTaskRule
use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, Severity};

/// Detect suspicious scheduled tasks from scheduled_tasks plugin
pub struct SuspiciousScheduledTaskRule;

impl DetectionRule for SuspiciousScheduledTaskRule {
    fn id(&self) -> &str {
        "PERS003"
    }

    fn name(&self) -> &str {
        "Suspicious Scheduled Task"
    }

    fn description(&self) -> &str {
        "Detects scheduled task actions indicative of persistence or execution abuse"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1053.005")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();

        for task in &data.scheduled_task_records {
            let task_name = task
                .get("Task Name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)");
            let action = task
                .get("Action")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = task
                .get("Action Arguments")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action_type = task
                .get("Action Type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let action_blob = format!("{} {} {}", action_type, action, args).to_lowercase();

            let suspicious = action_blob.contains("powershell")
                || action_blob.contains("cmd.exe")
                || action_blob.contains("wscript")
                || action_blob.contains("cscript")
                || action_blob.contains("mshta")
                || action_blob.contains("-enc")
                || action_blob.contains("\\temp\\")
                || action_blob.contains("\\appdata\\")
                || action_blob.contains("inject.x64.exe");

            if !suspicious {
                continue;
            }

            let mut finding = create_finding(
                self,
                format!("Suspicious scheduled task: {}", task_name),
                format!(
                    "Scheduled task '{}' has suspicious execution characteristics. Type: '{}' Action: '{}' Args: '{}'",
                    task_name, action_type, action, args
                ),
                vec![Evidence {
                    source_plugin: "scheduled_tasks".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!(
                        "TaskName:{} Type:{} Action:{} Args:{}",
                        task_name, action_type, action, args
                    ),
                }],
            );

            finding.confidence = 0.85;
            findings.push(finding);
        }

        findings
    }
}

// Persistence detection rules

