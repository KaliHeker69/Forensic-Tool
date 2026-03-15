use crate::models::*;
use crate::rules::RuleSet;

/// Assign a risk score (0–100) to every event based on its tags and rule weights.
pub fn score_all(events: &mut [NetEvent], rules: &RuleSet) {
    for ev in events.iter_mut() {
        let mut score: u32 = 0;

        for tag in &ev.tags {
            let weight = match tag {
                Tag::SuspiciousProcess => rules.score_weight("suspicious_process_outbound"),
                Tag::KnownMaliciousPort => rules.score_weight("known_malicious_port"),
                Tag::OffHours => rules.score_weight("off_hours_connection"),
                Tag::HighEntropy => rules.score_weight("high_entropy_domain"),
                Tag::ProcessSpoofing => rules.score_weight("process_name_spoofing"),
                Tag::Beaconing => rules.score_weight("beaconing_pattern"),
                Tag::DgaDomain => rules.score_weight("dga_domain"),
                Tag::BitsAbuse => rules.score_weight("bits_external_url"),
                Tag::LateralMovement => rules.score_weight("lateral_movement_type3"),
                Tag::RdpAccess => rules.score_weight("rdp_access"),
                Tag::PassTheHash => rules.score_weight("pass_the_hash"),
                Tag::AdminShareAccess => rules.score_weight("admin_share_access"),
                Tag::PersistenceMechanism => rules.score_weight("service_persistence_network"),
                Tag::DataExfiltration => rules.score_weight("high_bytes_sent_ratio"),
                Tag::HighBytesSent => 0, // already counted via DataExfiltration
                Tag::NetworkToolExecution => rules.score_weight("network_tool_execution"),
                Tag::C2Indicator => 0, // tagged alongside more specific indicators
                Tag::UnsignedProcess => rules.score_weight("suspicious_process_outbound"),
                Tag::IocMatch(_) => rules.score_weight("ioc_match"),
                Tag::Custom(s) if s.starts_with("firewall_") => {
                    rules.score_weight("firewall_rule_change")
                }
                Tag::Custom(_) => 0,
            };
            score += weight as u32;
        }

        // Check port-based scoring
        if let Some(port) = ev.remote_port {
            if rules.is_malicious_port(port) && !ev.tags.contains(&Tag::KnownMaliciousPort) {
                score += rules.score_weight("known_malicious_port") as u32;
            }
        }

        // Check unusual process
        if let Some(proc) = &ev.process_name {
            if rules.is_unusual_network_process(proc)
                && ev.direction == Some(Direction::Outbound)
                && !ev.tags.contains(&Tag::SuspiciousProcess)
            {
                score += rules.score_weight("unusual_process_network") as u32;
            }
        }

        // Check IP-only destination on common port
        if ev.hostname.is_none() && ev.remote_addr.is_some() {
            if let Some(port) = ev.remote_port {
                if port == 80 || port == 443 {
                    score += rules.score_weight("ip_only_destination_common_port") as u32;
                }
            }
        }

        // PowerShell network activity
        if ev.source == ArtifactSource::EventLogPowerShell
            || ev.source == ArtifactSource::PowerShellHistory
        {
            if !ev.tags.contains(&Tag::C2Indicator) {
                // already scored
            } else {
                score += rules.score_weight("powershell_network_activity") as u32;
            }
        }

        ev.risk_score = score.min(100) as u8;
    }
}
