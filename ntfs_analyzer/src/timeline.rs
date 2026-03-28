// =============================================================================
// NTFS Forensic Analyzer - Timeline Generator
// =============================================================================
// Aggregates timestamps from all NTFS artifact sources (MFT $SI, MFT $FN,
// USN Journal, I30 indexes) into a unified, chronologically
// sorted timeline. Supports filtering by date range, source, and path.
// =============================================================================

use chrono::{DateTime, Utc};
use rayon::prelude::*;
use std::collections::HashMap;

use crate::correlation::parse_timestamp;
use crate::models::*;

/// Generate a unified timeline from all NTFS artifact sources
pub fn generate_timeline(
    input: &NtfsInput,
    date_start: Option<DateTime<Utc>>,
    date_end: Option<DateTime<Utc>>,
) -> Vec<TimelineEvent> {
    let (mft_events, usn_events) = rayon::join(
        || build_mft_events(input, date_start, date_end),
        || build_usn_events(input, date_start, date_end),
    );
    let i30_events = build_i30_events(input, date_start, date_end);

    let mut events = Vec::with_capacity(mft_events.len() + usn_events.len() + i30_events.len());
    events.extend(mft_events);
    events.extend(usn_events);
    events.extend(i30_events);

    events.par_sort_unstable_by_key(|e| e.timestamp);
    events
}

fn build_mft_events(
    input: &NtfsInput,
    date_start: Option<DateTime<Utc>>,
    date_end: Option<DateTime<Utc>>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for entry in &input.mft_entries {
        let path = entry
            .full_path
            .clone()
            .or_else(|| entry.file_names.first().map(|f| f.name.clone()))
            .unwrap_or_else(|| format!("MFT#{}", entry.entry_id));

        let state_tag = if entry.flags.in_use {
            ""
        } else {
            " [DELETED]"
        };

        if let Some(si) = &entry.standard_info {
            let si_timestamps = [
                ("CREATED", &si.created),
                ("MODIFIED", &si.modified),
                ("ACCESSED", &si.accessed),
                ("MFT_MODIFIED", &si.mft_modified),
            ];
            for (event_type, ts_opt) in &si_timestamps {
                if let Some(ts_str) = ts_opt {
                    if let Some(ts) = parse_timestamp(ts_str) {
                        if !in_range(ts, date_start, date_end) {
                            continue;
                        }
                        let mut metadata = HashMap::new();
                        metadata.insert("entry_id".to_string(), entry.entry_id.to_string());
                        if !entry.flags.in_use {
                            metadata.insert("deleted".to_string(), "true".to_string());
                        }

                        events.push(TimelineEvent {
                            timestamp: ts,
                            source: "MFT_SI".to_string(),
                            event_type: event_type.to_string(),
                            path: format!("{}{}", path, state_tag),
                            entry_id: Some(entry.entry_id),
                            description: format!(
                                "[$SI] File {} (MFT#{})",
                                event_type.to_lowercase(),
                                entry.entry_id
                            ),
                            metadata,
                        });
                    }
                }
            }
        }

        for fn_attr in &entry.file_names {
            let fn_timestamps = [
                ("CREATED", &fn_attr.created),
                ("MODIFIED", &fn_attr.modified),
                ("ACCESSED", &fn_attr.accessed),
                ("MFT_MODIFIED", &fn_attr.mft_modified),
            ];
            for (event_type, ts_opt) in &fn_timestamps {
                if let Some(ts_str) = ts_opt {
                    if let Some(ts) = parse_timestamp(ts_str) {
                        if !in_range(ts, date_start, date_end) {
                            continue;
                        }
                        let mut metadata = HashMap::new();
                        metadata.insert("entry_id".to_string(), entry.entry_id.to_string());
                        metadata.insert("fn_name".to_string(), fn_attr.name.clone());
                        if let Some(ns) = &fn_attr.namespace {
                            metadata.insert("namespace".to_string(), ns.clone());
                        }

                        events.push(TimelineEvent {
                            timestamp: ts,
                            source: "MFT_FN".to_string(),
                            event_type: event_type.to_string(),
                            path: format!("{}{}", path, state_tag),
                            entry_id: Some(entry.entry_id),
                            description: format!(
                                "[$FN:{}] File {} (MFT#{})",
                                fn_attr.namespace.as_deref().unwrap_or("WIN32"),
                                event_type.to_lowercase(),
                                entry.entry_id
                            ),
                            metadata,
                        });
                    }
                }
            }
        }
    }

    events
}

fn build_usn_events(
    input: &NtfsInput,
    date_start: Option<DateTime<Utc>>,
    date_end: Option<DateTime<Utc>>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for usn in &input.usn_records {
        if let Some(ts) = parse_timestamp(&usn.timestamp) {
            if !in_range(ts, date_start, date_end) {
                continue;
            }

            let reasons = if usn.reason_decoded.is_empty() {
                usn_reasons::decode_reason_flags(usn.reason_flags)
            } else {
                usn.reason_decoded.clone()
            };

            let mut metadata = HashMap::new();
            metadata.insert("usn".to_string(), usn.usn.to_string());
            metadata.insert("mft_entry_id".to_string(), usn.mft_entry_id.to_string());
            metadata.insert(
                "reason_flags".to_string(),
                format!("0x{:08X}", usn.reason_flags),
            );
            if let Some(parent) = usn.parent_entry_id {
                metadata.insert("parent_entry_id".to_string(), parent.to_string());
            }

            events.push(TimelineEvent {
                timestamp: ts,
                source: "USN".to_string(),
                event_type: reasons.join("|"),
                path: usn.filename.clone(),
                entry_id: Some(usn.mft_entry_id),
                description: format!(
                    "[USN#{}] {} - {}",
                    usn.usn,
                    usn.filename,
                    reasons.join(", ")
                ),
                metadata,
            });
        }
    }

    events
}

fn build_i30_events(
    input: &NtfsInput,
    date_start: Option<DateTime<Utc>>,
    date_end: Option<DateTime<Utc>>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for i30 in &input.i30_entries {
        let source = if i30.from_slack { "I30_SLACK" } else { "I30" };
        let state_tag = if i30.from_slack {
            " [RECOVERED FROM SLACK]"
        } else {
            ""
        };

        let i30_timestamps = [
            ("CREATED", &i30.created),
            ("MODIFIED", &i30.modified),
            ("ACCESSED", &i30.accessed),
            ("MFT_MODIFIED", &i30.mft_modified),
        ];

        for (event_type, ts_opt) in &i30_timestamps {
            if let Some(ts_str) = ts_opt {
                if let Some(ts) = parse_timestamp(ts_str) {
                    if !in_range(ts, date_start, date_end) {
                        continue;
                    }
                    let mut metadata = HashMap::new();
                    metadata.insert("file_entry_id".to_string(), i30.file_entry_id.to_string());
                    metadata.insert(
                        "parent_entry_id".to_string(),
                        i30.parent_entry_id.to_string(),
                    );
                    if i30.from_slack {
                        metadata.insert("from_slack".to_string(), "true".to_string());
                    }

                    events.push(TimelineEvent {
                        timestamp: ts,
                        source: source.to_string(),
                        event_type: event_type.to_string(),
                        path: format!("{}{}", i30.filename, state_tag),
                        entry_id: Some(i30.file_entry_id),
                        description: format!(
                            "[{}] {} {} (parent MFT#{})",
                            source,
                            i30.filename,
                            event_type.to_lowercase(),
                            i30.parent_entry_id
                        ),
                        metadata,
                    });
                }
            }
        }
    }

    events
}

/// Check if a timestamp falls within the optional date range
fn in_range(
    ts: DateTime<Utc>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> bool {
    if let Some(s) = start {
        if ts < s {
            return false;
        }
    }
    if let Some(e) = end {
        if ts > e {
            return false;
        }
    }
    true
}

/// Export timeline to CSV format
pub fn timeline_to_csv(events: &[TimelineEvent]) -> String {
    let mut csv = String::from("Timestamp,Source,EventType,Path,EntryID,Description\n");
    for event in events {
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            event.timestamp.to_rfc3339(),
            event.source,
            event.event_type,
            event.path.replace('"', "\"\""),
            event
                .entry_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            event.description.replace('"', "\"\""),
        ));
    }
    csv
}

/// Export timeline to bodyfile format (Sleuth Kit compatible)
/// Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
pub fn timeline_to_bodyfile(events: &[TimelineEvent]) -> String {
    let mut body = String::new();
    for event in events {
        let ts_epoch = event.timestamp.timestamp();
        let (atime, mtime, ctime, crtime) = match event.event_type.as_str() {
            "ACCESSED" => (ts_epoch, 0, 0, 0),
            "MODIFIED" => (0, ts_epoch, 0, 0),
            "MFT_MODIFIED" => (0, 0, ts_epoch, 0),
            "CREATED" => (0, 0, 0, ts_epoch),
            _ => (0, 0, 0, 0),
        };
        body.push_str(&format!(
            "0|{} ({})|{}|0|0|0|0|{}|{}|{}|{}\n",
            event.path,
            event.source,
            event.entry_id.unwrap_or(0),
            atime,
            mtime,
            ctime,
            crtime
        ));
    }
    body
}
