use crate::models::NetEvent;

/// Sort events chronologically and de-duplicate identical connection tuples.
pub fn build_timeline(events: &mut Vec<NetEvent>) {
    // Sort by timestamp (None timestamps go to the end)
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Deduplicate exact-near-duplicates only. Keep distinct records even when
    // some fields are missing (common in live PowerShell snapshots).
    events.dedup_by(|a, b| {
        a.local_addr == b.local_addr
            && a.local_port == b.local_port
            && a.remote_addr == b.remote_addr
            && a.remote_port == b.remote_port
            && a.process_name == b.process_name
            && a.pid == b.pid
            && a.protocol == b.protocol
            && a.source == b.source
            && a.tags == b.tags
            && match (a.timestamp, b.timestamp) {
                (Some(ta), Some(tb)) => (ta - tb).num_seconds().abs() <= 1,
                (None, None) => a.raw_evidence == b.raw_evidence,
                _ => false,
            }
    });
}
