use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::collections::HashSet;

use crate::detection::types::Finding;
use crate::state::SharedState;

#[derive(Serialize, Clone)]
pub struct ExecutionEvent {
    pub id: String,
    pub name: String,
    pub prefetch_hash: String,
    pub timestamp_ms: i64,
    pub lane: String,
    pub run_count: u32,
    pub file_refs_count: usize,
}

#[derive(Serialize)]
pub struct TimelineSummary {
    pub total_events: usize,
    pub unique_exe_count: usize,
    pub total_files: usize,
    pub span_display: String,
    pub start_ms: i64,
    pub end_ms: i64,
}

#[derive(Serialize)]
pub struct TimelinePayload {
    pub events: Vec<ExecutionEvent>,
    pub summary: TimelineSummary,
}

fn classify_lane(findings: &[Finding]) -> &'static str {
    // Priority: cred → recon → net → exec → system
    for f in findings {
        for t in &f.mitre_techniques {
            if t.starts_with("T1003") || t.starts_with("T1555") || t.starts_with("T1212") {
                return "cred";
            }
        }
    }
    for f in findings {
        for t in &f.mitre_techniques {
            if t.starts_with("T1046") || t.starts_with("T1018") || t.starts_with("T1087")
                || t.starts_with("T1482") || t.starts_with("T1069")
                || t.starts_with("T1558")
            {
                return "recon";
            }
        }
    }
    for f in findings {
        for t in &f.mitre_techniques {
            if t.starts_with("T1021") || t.starts_with("T1572") || t.starts_with("T1567")
                || t.starts_with("T1071") || t.starts_with("T1219")
            {
                return "net";
            }
        }
    }
    for f in findings {
        for t in &f.mitre_techniques {
            if t.starts_with("T1059") || t.starts_with("T1055") || t.starts_with("T1204")
                || t.starts_with("T1036") || t.starts_with("T1574")
            {
                return "exec";
            }
        }
    }
    for f in findings {
        match f.rule_name.as_str() {
            "sensitive_file_refs" => return "cred",
            "unc_path_refs" => return "net",
            "execution_location" | "known_bad_name" | "single_run_tool" | "hash_mismatch" => {
                return "exec"
            }
            _ => {}
        }
    }
    "system"
}

fn format_span(ms: i64) -> String {
    if ms <= 0 {
        return "–".to_string();
    }
    let total_mins = ms / 60_000;
    let hours = total_mins / 60;
    let mins = total_mins % 60;
    let days = hours / 24;
    let hrs = hours % 24;
    if days > 0 {
        format!("{days}d {hrs}h")
    } else if hrs > 0 {
        format!("{hrs}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

pub async fn get_timeline(State(state): State<SharedState>) -> Json<TimelinePayload> {
    let state = state.read().await;
    let mut events: Vec<ExecutionEvent> = Vec::new();
    let mut unique_exes: HashSet<String> = HashSet::new();

    for entry in state.entries.values() {
        let pf = &entry.parsed;
        let findings = &entry.analysis.findings;
        let lane = classify_lane(findings);

        unique_exes.insert(pf.header.exe_name.clone());

        for ts in &pf.header.last_run_times {
            events.push(ExecutionEvent {
                id: entry.id.clone(),
                name: pf.header.exe_name.clone(),
                prefetch_hash: pf.header.prefetch_hash.clone(),
                timestamp_ms: ts.timestamp_millis(),
                lane: lane.to_string(),
                run_count: pf.header.run_count,
                file_refs_count: pf.file_metrics.len(),
            });
        }
    }

    events.sort_by_key(|e| e.timestamp_ms);
    let total_events = events.len();
    let total_files = state.entries.len();
    let start_ms = events.first().map(|e| e.timestamp_ms).unwrap_or(0);
    let end_ms = events.last().map(|e| e.timestamp_ms).unwrap_or(0);

    Json(TimelinePayload {
        summary: TimelineSummary {
            total_events,
            unique_exe_count: unique_exes.len(),
            total_files,
            span_display: format_span(end_ms - start_ms),
            start_ms,
            end_ms,
        },
        events,
    })
}
