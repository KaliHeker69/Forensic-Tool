use crate::models::*;

/// Detect lateral movement patterns from tagged events.
pub fn detect(events: &[NetEvent]) -> Vec<LateralMovementEntry> {
    let mut entries = Vec::new();

    for ev in events {
        let method = if ev.tags.contains(&Tag::PassTheHash) {
            Some("Pass-the-Hash (NTLM without Kerberos)")
        } else if ev.tags.contains(&Tag::AdminShareAccess) {
            Some("Admin share access (C$/ADMIN$)")
        } else if ev.tags.contains(&Tag::RdpAccess) {
            Some("RDP session")
        } else if ev.tags.contains(&Tag::LateralMovement) {
            match ev.source {
                ArtifactSource::EventLogSecurity => Some("Network logon (Type 3)"),
                _ => Some("Lateral movement indicator"),
            }
        } else {
            None
        };

        if let Some(method) = method {
            let source_ip = ev
                .remote_addr
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let dest_ip = ev
                .local_addr
                .map(|ip| ip.to_string())
                .or_else(|| ev.hostname.clone())
                .unwrap_or_else(|| "local".to_string());

            entries.push(LateralMovementEntry {
                timestamp: ev.timestamp,
                source_ip,
                dest_ip,
                method: method.to_string(),
                username: ev.username.clone(),
                evidence: ev.raw_evidence.clone(),
            });
        }
    }

    entries
}
