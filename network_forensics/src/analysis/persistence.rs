use crate::models::*;

/// Persistence detection — most tagging is done during ingestion.
/// This module can add cross-source correlation if needed.
pub fn detect(events: &[NetEvent]) -> Vec<&NetEvent> {
    events
        .iter()
        .filter(|e| e.tags.contains(&Tag::PersistenceMechanism))
        .collect()
}
