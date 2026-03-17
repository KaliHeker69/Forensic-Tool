pub mod timeline;
pub mod process_network;
pub mod lateral_movement;
pub mod beaconing;
pub mod correlation;
pub mod persistence;
pub mod exfiltration;
pub mod infrastructure;
pub mod scorer;

use crate::ingest::ioc::IocIngestor;
use crate::models::*;
use crate::rules::RuleSet;

/// Run all analysis modules in order and produce a ForensicReport.
pub fn run_analysis(
    mut events: Vec<NetEvent>,
    rules: &RuleSet,
    ioc: Option<&IocIngestor>,
    metadata: ReportMetadata,
) -> ForensicReport {
    // 1. IOC tagging (before scoring so matches get scored)
    if let Some(ioc_ingestor) = ioc {
        ioc_ingestor.tag_events(&mut events);
    }

    // 2. Timeline (sort + dedup)
    timeline::build_timeline(&mut events);

    // 3. Process → Network Attribution
    let process_network_map = process_network::build_process_map(&events, rules);

    // 4. Lateral Movement Detection
    let lateral_movement = lateral_movement::detect(&events);

    // 5. Beaconing / C2 Heuristics
    beaconing::detect(&mut events, rules);

    // 6. Persistence (already tagged during ingestion — nothing extra needed here)
    // Tags were applied by evtx/registry/filesystem parsers.

    // 7. Exfiltration Indicators
    exfiltration::detect(&mut events, rules);

    // 8. Multi-signal correlation (cross-module behavior chains)
    correlation::detect(&mut events, rules);

    // 9. Infrastructure Profiler
    let infrastructure = infrastructure::profile(&events, ioc);

    // 10. IOC match entries
    let ioc_matches = build_ioc_match_entries(&events);

    // 11. Anomaly Scorer (runs last, after all tags are set)
    scorer::score_all(&mut events, rules);

    // Build summary
    let summary = build_summary(&events, &lateral_movement);

    // Partition flagged events
    let flagged_events: Vec<NetEvent> = events
        .iter()
        .filter(|e| !e.tags.is_empty() || e.risk_score > 0)
        .cloned()
        .collect();

    ForensicReport {
        metadata,
        summary,
        timeline: events,
        flagged_events,
        process_network_map,
        lateral_movement,
        infrastructure,
        ioc_matches,
    }
}

fn build_summary(events: &[NetEvent], lateral: &[LateralMovementEntry]) -> ExecutiveSummary {
    use std::collections::{HashMap, HashSet};

    let mut external_ips = HashSet::new();
    let mut internal_ips = HashSet::new();
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut beaconing_detected = false;
    let mut exfiltration_indicators = false;

    for ev in events {
        if ev.risk_score >= 67 {
            high += 1;
        } else if ev.risk_score >= 34 {
            medium += 1;
        } else {
            low += 1;
        }

        if let Some(ip) = &ev.remote_addr {
            let s = ip.to_string();
            if is_private_ip(*ip) {
                internal_ips.insert(s.clone());
            } else {
                external_ips.insert(s.clone());
            }
            *ip_counts.entry(s).or_default() += 1;
        }

        for tag in &ev.tags {
            match tag {
                Tag::Beaconing => beaconing_detected = true,
                Tag::DataExfiltration => exfiltration_indicators = true,
                _ => {}
            }
        }
    }

    let mut top_suspicious: Vec<(String, usize)> = ip_counts.into_iter().collect();
    top_suspicious.sort_by(|a, b| b.1.cmp(&a.1));
    top_suspicious.truncate(10);

    let timeline_start = events.iter().filter_map(|e| e.timestamp).min();
    let timeline_end = events.iter().filter_map(|e| e.timestamp).max();

    ExecutiveSummary {
        total_connections: events.len(),
        unique_external_ips: external_ips.len(),
        unique_internal_ips: internal_ips.len(),
        high_risk_events: high,
        medium_risk_events: medium,
        low_risk_events: low,
        top_suspicious_ips: top_suspicious,
        timeline_start,
        timeline_end,
        lateral_movement_detected: !lateral.is_empty(),
        beaconing_detected,
        exfiltration_indicators,
    }
}

fn build_ioc_match_entries(events: &[NetEvent]) -> Vec<IocMatchEntry> {
    let mut matches = Vec::new();
    for ev in events {
        for tag in &ev.tags {
            if let Tag::IocMatch(indicator) = tag {
                let (itype, ivalue) = indicator
                    .split_once(':')
                    .unwrap_or(("unknown", indicator));
                matches.push(IocMatchEntry {
                    indicator: ivalue.to_string(),
                    indicator_type: itype.to_string(),
                    matched_in: ev.source,
                    event_timestamp: ev.timestamp,
                    context: ev.raw_evidence.clone(),
                });
            }
        }
    }
    matches
}
