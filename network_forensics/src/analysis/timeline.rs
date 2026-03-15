use crate::models::NetEvent;

/// Sort events chronologically and de-duplicate identical connection tuples.
pub fn build_timeline(events: &mut Vec<NetEvent>) {
    // Sort by timestamp (None timestamps go to the end)
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Deduplicate: same (src, dst, port, process, timestamp) within 1s window
    events.dedup_by(|a, b| {
        a.local_addr == b.local_addr
            && a.remote_addr == b.remote_addr
            && a.remote_port == b.remote_port
            && a.process_name == b.process_name
            && match (a.timestamp, b.timestamp) {
                (Some(ta), Some(tb)) => (ta - tb).num_seconds().abs() <= 1,
                (None, None) => true,
                _ => false,
            }
    });
}
