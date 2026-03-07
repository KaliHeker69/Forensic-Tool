use crate::models::common::{TimelineEvent, parse_timestamp};
use crate::models::app_resource::AppResourceUsage;
use crate::models::app_timeline::AppTimeline;
use crate::models::network_usage::NetworkUsage;
use crate::models::network_conn::NetworkConnection;
use crate::models::vfu_provider::VfuProvider;
use crate::analyzers::app_analyzer::format_bytes;

/// Build a unified timeline from all SRUM tables
pub fn build_timeline(
    app_records: &[AppResourceUsage],
    net_records: &[NetworkUsage],
    conn_records: &[NetworkConnection],
    app_timeline_records: &[AppTimeline],
    vfu_records: &[VfuProvider],
) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = Vec::new();

    // Add AppResourceUsage events
    for record in app_records {
        if let Some(ref ts) = record.timestamp {
            events.push(TimelineEvent {
                timestamp: ts.clone(),
                event_type: "Application Execution".to_string(),
                source_table: "AppResourceUsageInfo".to_string(),
                application: record.exe_info.clone(),
                user: record.user_name.clone().or_else(|| record.user_sid.clone()),
                details: format!(
                    "CPU Cycles: {} | Bytes Read: {} | Bytes Written: {} | FaceTime: {}",
                    record.total_cycle_time(),
                    format_bytes(record.total_bytes_read()),
                    format_bytes(record.total_bytes_written()),
                    record.face_time.unwrap_or(0),
                ),
            });
        }
    }

    // Add NetworkUsage events
    for record in net_records {
        if let Some(ref ts) = record.timestamp {
            events.push(TimelineEvent {
                timestamp: ts.clone(),
                event_type: "Network Activity".to_string(),
                source_table: "NetworkUsages".to_string(),
                application: record.exe_info.clone(),
                user: record.user_name.clone().or_else(|| record.user_sid.clone()),
                details: format!(
                    "Sent: {} | Received: {} | Interface: {} | Network: {}",
                    format_bytes(record.bytes_sent.unwrap_or(0)),
                    format_bytes(record.bytes_recvd.unwrap_or(0)),
                    record.interface_type.as_deref().unwrap_or("Unknown"),
                    record.l2_profile_id.as_deref().unwrap_or("Unknown"),
                ),
            });
        }
    }

    // Add NetworkConnection events
    for record in conn_records {
        let ts = record.connect_start_time.as_ref()
            .or(record.timestamp.as_ref());
        if let Some(ts) = ts {
            events.push(TimelineEvent {
                timestamp: ts.clone(),
                event_type: "Network Connection".to_string(),
                source_table: "NetworkConnections".to_string(),
                application: None,
                user: None,
                details: format!(
                    "Duration: {}s | Interface: {} | Profile: {}",
                    record.connected_time.unwrap_or(0),
                    record.interface_type.as_deref().unwrap_or("Unknown"),
                    record.l2_profile_id.as_deref().unwrap_or("Unknown"),
                ),
            });
        }
    }

    // Add AppTimeline events
    for record in app_timeline_records {
        if let Some(ref ts) = record.timestamp {
            events.push(TimelineEvent {
                timestamp: ts.clone(),
                event_type: "App Timeline".to_string(),
                source_table: "AppTimelineProvider".to_string(),
                application: record.exe_info.clone(),
                user: record.user_name.clone().or_else(|| record.user_sid.clone()),
                details: format!(
                    "Duration: {} | End: {}",
                    record.duration_display(),
                    record.end_time.as_deref().unwrap_or("N/A"),
                ),
            });
        }
    }

    // Add VfuProvider events
    for record in vfu_records {
        if let Some(ref ts) = record.timestamp {
            events.push(TimelineEvent {
                timestamp: ts.clone(),
                event_type: "VFU Activity".to_string(),
                source_table: "VfuProvider".to_string(),
                application: record.exe_info.clone(),
                user: record.user_name.clone().or_else(|| record.user_sid.clone()),
                details: format!(
                    "Start: {} | End: {} | Duration: {} | Flags: {}",
                    record.start_time.as_deref().unwrap_or("N/A"),
                    record.end_time.as_deref().unwrap_or("N/A"),
                    record.duration.as_deref().unwrap_or("N/A"),
                    record.flags.as_deref().unwrap_or("0"),
                ),
            });
        }
    }

    // Sort by timestamp
    events.sort_by(|a, b| {
        let ts_a = parse_timestamp(&a.timestamp);
        let ts_b = parse_timestamp(&b.timestamp);
        ts_a.cmp(&ts_b)
    });

    events
}
