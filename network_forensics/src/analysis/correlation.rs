use crate::models::*;
use crate::rules::RuleSet;
use std::collections::{HashMap, HashSet};

/// Multi-signal correlation stage.
///
/// Promotes events when independent weak indicators align across process,
/// destination, and behavioral dimensions.
pub fn detect(events: &mut [NetEvent], rules: &RuleSet) {
    enrich_base_signals(events, rules);
    correlate_process_chains(events);
    correlate_shared_external_infrastructure(events);
    correlate_lateral_patterns(events);
}

fn enrich_base_signals(events: &mut [NetEvent], rules: &RuleSet) {
    for ev in events.iter_mut() {
        // Infer direction when live artifacts do not explicitly include it.
        if ev.direction == Some(Direction::Unknown) || ev.direction.is_none() {
            if let Some(remote) = ev.remote_addr {
                if is_private_ip(remote) {
                    ev.direction = Some(Direction::Lateral);
                } else {
                    ev.direction = Some(Direction::Outbound);
                }
            }
        }

        if let Some(port) = ev.remote_port {
            if rules.is_malicious_port(port) && !ev.tags.contains(&Tag::KnownMaliciousPort) {
                ev.tags.push(Tag::KnownMaliciousPort);
            }
        }

        if let Some(proc_name) = &ev.process_name {
            if rules.is_unusual_network_process(proc_name)
                && !ev.tags.contains(&Tag::SuspiciousProcess)
            {
                ev.tags.push(Tag::SuspiciousProcess);
            }

            if rules.is_suspicious_tool(proc_name)
                && !ev.tags.contains(&Tag::NetworkToolExecution)
            {
                ev.tags.push(Tag::NetworkToolExecution);
            }
        }

        if rules.matches_network_keyword(&ev.raw_evidence)
            && !ev.tags.contains(&Tag::NetworkToolExecution)
        {
            ev.tags.push(Tag::NetworkToolExecution);
        }
    }
}

fn correlate_process_chains(events: &mut [NetEvent]) {
    #[derive(Default)]
    struct ProcSignals {
        indices: Vec<usize>,
        external_ips: HashSet<String>,
        has_beaconing: bool,
        has_exfil: bool,
        has_offhours: bool,
        has_unsigned: bool,
        has_ioc: bool,
        malicious_port_hits: usize,
    }

    let mut by_process: HashMap<String, ProcSignals> = HashMap::new();

    for (idx, ev) in events.iter().enumerate() {
        let process = ev
            .process_name
            .as_deref()
            .unwrap_or("unknown")
            .to_lowercase();

        let entry = by_process.entry(process).or_default();
        entry.indices.push(idx);

        if let Some(ip) = ev.remote_addr {
            if !is_private_ip(ip) {
                entry.external_ips.insert(ip.to_string());
            }
        }

        for tag in &ev.tags {
            match tag {
                Tag::Beaconing => entry.has_beaconing = true,
                Tag::DataExfiltration | Tag::HighBytesSent => entry.has_exfil = true,
                Tag::OffHours => entry.has_offhours = true,
                Tag::UnsignedProcess => entry.has_unsigned = true,
                Tag::IocMatch(_) => entry.has_ioc = true,
                Tag::KnownMaliciousPort => entry.malicious_port_hits += 1,
                _ => {}
            }
        }
    }

    for (_, signals) in by_process {
        let mut strength = 0u8;
        if signals.has_beaconing {
            strength += 1;
        }
        if signals.has_exfil {
            strength += 1;
        }
        if signals.has_offhours {
            strength += 1;
        }
        if signals.has_unsigned {
            strength += 1;
        }
        if signals.has_ioc {
            strength += 2;
        }
        if signals.malicious_port_hits > 0 {
            strength += 1;
        }
        if !signals.external_ips.is_empty() {
            strength += 1;
        }

        // Require at least two independent signals before promoting.
        if strength < 2 {
            continue;
        }

        for idx in signals.indices {
            let ev = &mut events[idx];
            if !ev.tags.contains(&Tag::C2Indicator) {
                ev.tags.push(Tag::C2Indicator);
            }
            if !ev
                .tags
                .iter()
                .any(|t| matches!(t, Tag::Custom(s) if s == "correlation_process_chain"))
            {
                ev.tags
                    .push(Tag::Custom("correlation_process_chain".to_string()));
            }
        }
    }
}

fn correlate_shared_external_infrastructure(events: &mut [NetEvent]) {
    let mut remote_to_processes: HashMap<String, HashSet<String>> = HashMap::new();

    for ev in events.iter() {
        if let Some(ip) = ev.remote_addr {
            if !is_private_ip(ip) {
                let proc = ev
                    .process_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_lowercase();
                remote_to_processes
                    .entry(ip.to_string())
                    .or_default()
                    .insert(proc);
            }
        }
    }

    let hotspot_ips: HashSet<String> = remote_to_processes
        .into_iter()
        .filter(|(_, procs)| procs.len() >= 3)
        .map(|(ip, _)| ip)
        .collect();

    if hotspot_ips.is_empty() {
        return;
    }

    for ev in events.iter_mut() {
        if let Some(ip) = ev.remote_addr {
            let ip_s = ip.to_string();
            if hotspot_ips.contains(&ip_s) {
                if !ev
                    .tags
                    .iter()
                    .any(|t| matches!(t, Tag::Custom(s) if s == "correlation_shared_external_ip"))
                {
                    ev.tags
                        .push(Tag::Custom("correlation_shared_external_ip".to_string()));
                }
            }
        }
    }
}

fn correlate_lateral_patterns(events: &mut [NetEvent]) {
    for ev in events.iter_mut() {
        let Some(remote) = ev.remote_addr else {
            continue;
        };
        if !is_private_ip(remote) {
            continue;
        }

        let lateral_port = matches!(ev.remote_port, Some(445 | 3389 | 5985 | 5986 | 135));
        let has_auth_tag = ev.tags.iter().any(|tag| {
            matches!(
                tag,
                Tag::AdminShareAccess | Tag::PassTheHash | Tag::RdpAccess
            )
        });

        if lateral_port || has_auth_tag {
            if !ev.tags.contains(&Tag::LateralMovement) {
                ev.tags.push(Tag::LateralMovement);
            }
            if !ev
                .tags
                .iter()
                .any(|t| matches!(t, Tag::Custom(s) if s == "correlation_lateral_chain"))
            {
                ev.tags
                    .push(Tag::Custom("correlation_lateral_chain".to_string()));
            }
        }
    }
}
