use crate::models::*;
use crate::rules::RuleSet;
use std::collections::HashMap;

/// Detect data exfiltration indicators.
pub fn detect(events: &mut [NetEvent], rules: &RuleSet) {
    detect_high_upload(events, rules);
    detect_off_hours(events, rules);
}

/// Flag processes with suspiciously high bytes_sent / bytes_recv ratio.
fn detect_high_upload(events: &mut [NetEvent], rules: &RuleSet) {
    // Aggregate per process
    let mut agg: HashMap<String, (u64, u64)> = HashMap::new();
    for ev in events.iter() {
        let name = ev
            .process_name
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let entry = agg.entry(name).or_default();
        entry.0 += ev.bytes_sent.unwrap_or(0);
        entry.1 += ev.bytes_recv.unwrap_or(0);
    }

    let flagged: Vec<String> = agg
        .into_iter()
        .filter(|(_, (sent, recv))| {
            *sent >= rules.beaconing.exfil_min_bytes_sent
                && *recv > 0
                && (*sent as f64 / *recv as f64) >= rules.beaconing.exfil_sent_recv_ratio
        })
        .map(|(name, _)| name)
        .collect();

    for ev in events.iter_mut() {
        let name = ev
            .process_name
            .as_deref()
            .unwrap_or("unknown")
            .to_lowercase();
        if flagged.contains(&name) && !ev.tags.contains(&Tag::DataExfiltration) {
            ev.tags.push(Tag::DataExfiltration);
            ev.tags.push(Tag::HighBytesSent);
        }
    }
}

/// Flag connections outside business hours.
fn detect_off_hours(events: &mut [NetEvent], rules: &RuleSet) {
    for ev in events.iter_mut() {
        if let Some(ts) = ev.timestamp {
            let hour = ts.time().hour() as u8;
            let weekday = ts.format("%A").to_string();
            let is_business_day = rules.beaconing.business_days.contains(&weekday);
            let is_business_hour =
                hour >= rules.beaconing.business_hours_start
                    && hour < rules.beaconing.business_hours_end;

            if (!is_business_day || !is_business_hour)
                && ev.direction == Some(Direction::Outbound)
                && !ev.tags.contains(&Tag::OffHours)
            {
                ev.tags.push(Tag::OffHours);
            }
        }
    }
}

use chrono::Timelike;
