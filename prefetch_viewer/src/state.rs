use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::parser::types::PrefetchFile;
use crate::detection::types::AnalysisResult;

pub type SharedState = Arc<RwLock<AppState>>;

pub struct PrefetchEntry {
    pub id: String,
    pub parsed: PrefetchFile,
    pub analysis: AnalysisResult,
    pub raw_size: usize,
}

pub struct AppState {
    pub entries: HashMap<String, PrefetchEntry>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}
