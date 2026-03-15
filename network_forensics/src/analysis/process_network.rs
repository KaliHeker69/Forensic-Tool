use crate::models::*;
use crate::rules::RuleSet;
use std::collections::HashMap;

/// Build per-process network attribution map.
pub fn build_process_map(events: &[NetEvent], rules: &RuleSet) -> Vec<ProcessNetworkEntry> {
    let mut map: HashMap<String, ProcessAgg> = HashMap::new();

    for ev in events {
        let name = ev
            .process_name
            .as_deref()
            .unwrap_or("unknown")
            .to_lowercase();
        let entry = map.entry(name.clone()).or_insert_with(|| ProcessAgg {
            pid: ev.pid,
            bytes_sent: 0,
            bytes_recv: 0,
            destinations: std::collections::HashSet::new(),
            count: 0,
        });

        entry.bytes_sent += ev.bytes_sent.unwrap_or(0);
        entry.bytes_recv += ev.bytes_recv.unwrap_or(0);
        entry.count += 1;

        if let Some(ip) = &ev.remote_addr {
            entry.destinations.insert(ip.to_string());
        }
        if let Some(host) = &ev.hostname {
            entry.destinations.insert(host.clone());
        }
    }

    map.into_iter()
        .map(|(name, agg)| {
            let suspicious = rules.is_unusual_network_process(&name);
            let reason = if suspicious {
                Some(format!(
                    "{} should not normally make network connections",
                    name
                ))
            } else {
                None
            };
            ProcessNetworkEntry {
                process_name: name,
                pid: agg.pid,
                total_bytes_sent: agg.bytes_sent,
                total_bytes_recv: agg.bytes_recv,
                unique_destinations: agg.destinations.into_iter().collect(),
                connection_count: agg.count,
                suspicious,
                reason,
            }
        })
        .collect()
}

struct ProcessAgg {
    pid: Option<u32>,
    bytes_sent: u64,
    bytes_recv: u64,
    destinations: std::collections::HashSet<String>,
    count: usize,
}
