use std::collections::HashMap;

pub struct HiveEntry {
    pub id: String,
    pub name: String,
    pub data: Vec<u8>,
    pub size: usize,
    pub log1_data: Option<Vec<u8>>,
    pub log2_data: Option<Vec<u8>>,
}

pub struct AppState {
    pub hives: HashMap<String, HiveEntry>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            hives: HashMap::new(),
        }
    }
}
