use crate::models::*;
use crate::rules::RuleSet;
use std::collections::HashMap;

/// Detect beaconing patterns and C2 indicators.
pub fn detect(events: &mut [NetEvent], rules: &RuleSet) {
    detect_beaconing(events, rules);
    detect_dga(events);
}

/// Group connections by (process, remote_addr), check for periodic intervals.
fn detect_beaconing(events: &mut [NetEvent], rules: &RuleSet) {
    // Group timestamped events by (process, remote_ip)
    let mut groups: HashMap<(String, String), Vec<i64>> = HashMap::new();

    for ev in events.iter() {
        if let (Some(ts), Some(ip)) = (ev.timestamp, ev.remote_addr) {
            let process = ev
                .process_name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let key = (process, ip.to_string());
            groups.entry(key).or_default().push(ts.timestamp());
        }
    }

    let mut beaconing_keys: Vec<(String, String)> = Vec::new();

    for (key, mut timestamps) in groups {
        if timestamps.len() < rules.beaconing.min_connections {
            continue;
        }
        timestamps.sort();

        let intervals: Vec<i64> = timestamps.windows(2).map(|w| w[1] - w[0]).collect();
        if intervals.is_empty() {
            continue;
        }

        // Check interval range
        let all_in_range = intervals.iter().all(|&iv| {
            iv >= rules.beaconing.min_interval_seconds as i64
                && iv <= rules.beaconing.max_interval_seconds as i64
        });
        if !all_in_range {
            continue;
        }

        // Check standard deviation
        let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|&iv| {
                let diff = iv as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / intervals.len() as f64;
        let stddev = variance.sqrt();

        if stddev <= rules.beaconing.max_interval_stddev_seconds as f64 {
            beaconing_keys.push(key);
        }
    }

    // Tag matching events
    for ev in events.iter_mut() {
        if let Some(ip) = ev.remote_addr {
            let process = ev
                .process_name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let key = (process, ip.to_string());
            if beaconing_keys.contains(&key) && !ev.tags.contains(&Tag::Beaconing) {
                ev.tags.push(Tag::Beaconing);
                ev.tags.push(Tag::C2Indicator);
            }
        }
    }
}

/// Flag high-entropy domain names (potential DGA).
fn detect_dga(events: &mut [NetEvent]) {
    for ev in events.iter_mut() {
        if let Some(host) = &ev.hostname {
            if is_high_entropy(host) && !ev.tags.contains(&Tag::DgaDomain) {
                ev.tags.push(Tag::DgaDomain);
            }
        }
    }
}

fn is_high_entropy(domain: &str) -> bool {
    // Strip TLD for entropy calculation
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let label = parts[0];
    if label.len() < 8 {
        return false;
    }
    let entropy = shannon_entropy(label);
    entropy > 3.5
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
