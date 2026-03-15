use crate::ingest::ioc::IocIngestor;
use crate::models::*;
use std::collections::HashMap;

/// Build the network infrastructure profile from all events.
pub fn profile(
    events: &[NetEvent],
    ioc: Option<&IocIngestor>,
    ) -> Vec<InfrastructureEntry> {
    let mut map: HashMap<String, InfraAgg> = HashMap::new();

    for ev in events {
        let key = if let Some(ip) = &ev.remote_addr {
            ip.to_string()
        } else if let Some(host) = &ev.hostname {
            host.clone()
        } else {
            continue;
        };

        let entry = map.entry(key.clone()).or_insert_with(|| {
            let classification = if let Some(ip) = ev.remote_addr {
                if ip.is_loopback() {
                    IpClassification::Loopback
                } else if is_private_ip(ip) {
                    IpClassification::PrivateRfc1918
                } else {
                    IpClassification::Public
                }
            } else {
                IpClassification::Public
            };
            InfraAgg {
                classification,
                first_seen: ev.timestamp,
                last_seen: ev.timestamp,
                sources: Vec::new(),
                count: 0,
                total_bytes: 0,
            }
        });

        if let Some(ts) = ev.timestamp {
            entry.first_seen = Some(
                entry
                    .first_seen
                    .map_or(ts, |existing| existing.min(ts)),
            );
            entry.last_seen = Some(
                entry
                    .last_seen
                    .map_or(ts, |existing| existing.max(ts)),
            );
        }

        if !entry.sources.contains(&ev.source) {
            entry.sources.push(ev.source);
        }
        entry.count += 1;
        entry.total_bytes += ev.bytes_sent.unwrap_or(0) + ev.bytes_recv.unwrap_or(0);

        // Check IOC match
        if let Some(ioc_ingestor) = ioc {
            let _ = ioc_ingestor; // IOC tagging already done on events
            for tag in &ev.tags {
                if matches!(tag, Tag::IocMatch(_)) {
                    entry.classification = IpClassification::IocMatch;
                }
            }
        }
    }

    map.into_iter()
        .map(|(key, agg)| InfrastructureEntry {
            ip_or_hostname: key,
            classification: agg.classification,
            first_seen: agg.first_seen,
            last_seen: agg.last_seen,
            seen_in_sources: agg.sources,
            connection_count: agg.count,
            total_bytes: agg.total_bytes,
            risk_score: 0, // will be filled by scorer
        })
        .collect()
}

struct InfraAgg {
    classification: IpClassification,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    sources: Vec<ArtifactSource>,
    count: usize,
    total_bytes: u64,
}
