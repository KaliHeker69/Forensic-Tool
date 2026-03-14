use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;
use notatin::cell_value::CellValue;
use notatin::parser::Parser;
use notatin::parser_builder::ParserBuilder;
use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;

use crate::state::HiveEntry;

// ── Data structures for template rendering ──────────────────────

pub struct KeyChild {
    pub name: String,
    pub path: String,
    pub has_children: bool,
    pub num_values: usize,
}

pub struct RegValue {
    pub name: String,
    pub data_type: String,
    pub data: String,
    pub is_default: bool,
}

pub struct KeyInfo {
    pub path: String,
    pub pretty_path: String,
    pub last_written: String,
    pub num_values: usize,
    pub num_sub_keys: usize,
}

pub struct SearchResult {
    pub path: String,
    pub match_type: String,
    pub name: String,
    pub preview: String,
}

// ── Parser creation ─────────────────────────────────────────────

pub fn create_parser(entry: &HiveEntry) -> Result<Parser, String> {
    let cursor = Cursor::new(entry.data.clone());
    let mut builder = ParserBuilder::from_file(cursor);
    builder.recover_deleted(false);

    if let Some(ref log1) = entry.log1_data {
        builder.with_transaction_log(Cursor::new(log1.clone()));
    }
    if let Some(ref log2) = entry.log2_data {
        builder.with_transaction_log(Cursor::new(log2.clone()));
    }

    builder.build().map_err(|e| format!("Parser error: {:?}", e))
}

pub fn validate_hive(data: &[u8]) -> Result<(), String> {
    let mut builder = ParserBuilder::from_file(Cursor::new(data.to_vec()));
    builder.recover_deleted(false);
    let mut parser = builder
        .build()
        .map_err(|e| format!("Parser error: {:?}", e))?;

    parser
        .get_root_key()
        .map_err(|e| format!("Failed to read root key: {:?}", e))?
        .ok_or_else(|| "No root key found".to_string())?;

    Ok(())
}

pub fn validate_full_traversal(entry: &HiveEntry) -> Result<(), String> {
    let mut parser = create_parser(entry)?;
    let root = parser
        .get_root_key()
        .map_err(|e| format!("Failed to read root key: {:?}", e))?
        .ok_or_else(|| "No root key found".to_string())?;
    let root_path = root.path.clone();

    let mut stack = vec![root_path.clone()];
    let mut visited: HashSet<String> = HashSet::new();
    let mut visited_keys = 0usize;

    while let Some(path) = stack.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }

        let mut key = if path == root_path {
            parser
                .get_root_key()
                .map_err(|e| format!("Failed to read root key: {:?}", e))?
                .ok_or_else(|| "No root key found".to_string())?
        } else {
            parser
                .get_key(&path, true)
                .map_err(|e| format!("Failed to read key '{}': {:?}", path, e))?
                .ok_or_else(|| format!("Key not found during traversal: {}", path))?
        };

        for val in key.value_iter() {
            let _ = val.get_content();
        }

        let children = key.read_sub_keys(&mut parser);
        for child in children {
            stack.push(child.path.clone());
        }

        visited_keys += 1;
    }

    tracing::info!(
        "Validated full traversal for '{}' ({} keys)",
        entry.name,
        visited_keys
    );

    Ok(())
}

pub fn load_hive_from_path(path: &Path) -> Result<HiveEntry, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let size = data.len();
    let id = uuid::Uuid::new_v4().to_string();

    let log1_path_candidates = [
        path.with_extension("LOG1"),
        Path::new(&format!("{}.LOG1", path.display())).to_path_buf(),
    ];
    let log2_path_candidates = [
        path.with_extension("LOG2"),
        Path::new(&format!("{}.LOG2", path.display())).to_path_buf(),
    ];

    let mut log1_data = None;
    let mut found_log1_path = None;
    for candidate in log1_path_candidates {
        if let Ok(data) = std::fs::read(&candidate) {
            log1_data = Some(data);
            found_log1_path = Some(candidate);
            break;
        }
    }

    let mut log2_data = None;
    let mut found_log2_path = None;
    for candidate in log2_path_candidates {
        if let Ok(data) = std::fs::read(&candidate) {
            log2_data = Some(data);
            found_log2_path = Some(candidate);
            break;
        }
    }

    if let Some(log1_path) = found_log1_path {
        tracing::info!("Found transaction log: {}", log1_path.display());
    }
    if let Some(log2_path) = found_log2_path {
        tracing::info!("Found transaction log: {}", log2_path.display());
    }

    // Validate that the hive is parseable
    let test_entry = HiveEntry {
        id: id.clone(),
        name: name.clone(),
        data: data.clone(),
        size,
        log1_data: log1_data.clone(),
        log2_data: log2_data.clone(),
    };
    validate_hive(&test_entry.data)?;

    Ok(HiveEntry {
        id,
        name,
        data,
        size,
        log1_data,
        log2_data,
    })
}

// ── Tree navigation ─────────────────────────────────────────────

fn extract_children(key: &mut CellKeyNode, parser: &mut Parser) -> Vec<KeyChild> {
    let sub_keys = key.read_sub_keys(parser);
    sub_keys
        .into_iter()
        .map(|mut sk| {
            // Some hives do not reliably populate offset metadata for all keys,
            // so detect children by explicitly reading the immediate subkeys.
            let has_children = !sk.read_sub_keys(parser).is_empty();
            let num_values = sk.value_iter().count();

            KeyChild {
                name: sk.key_name.clone(),
                path: sk.path.clone(),
                has_children,
                num_values,
            }
        })
        .collect()
}

pub fn get_root_children(entry: &HiveEntry) -> Result<(String, Vec<KeyChild>), String> {
    let mut parser = create_parser(entry)?;
    let mut root = parser
        .get_root_key()
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "No root key found".to_string())?;

    let root_path = root.path.clone();
    let children = extract_children(&mut root, &mut parser);
    Ok((root_path, children))
}

pub fn get_children_at_path(entry: &HiveEntry, key_path: &str) -> Result<Vec<KeyChild>, String> {
    let mut parser = create_parser(entry)?;
    let mut key = parser
        .get_key(key_path, true)
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| format!("Key not found: {}", key_path))?;

    Ok(extract_children(&mut key, &mut parser))
}

// ── Value extraction ────────────────────────────────────────────

fn format_cell_value(content: &CellValue, data_type_str: &str) -> String {
    match content {
        CellValue::None => "(value not set)".to_string(),
        CellValue::String(s) => s.clone(),
        CellValue::MultiString(v) => v.join(" | "),
        CellValue::U32(n) => {
            if data_type_str.contains("DWORD") {
                format!("0x{:08x} ({})", n, n)
            } else {
                format!("{}", n)
            }
        }
        CellValue::I32(n) => format!("{}", n),
        CellValue::U64(n) => {
            if data_type_str.contains("QWORD") {
                format!("0x{:016x} ({})", n, n)
            } else {
                format!("{}", n)
            }
        }
        CellValue::I64(n) => format!("{}", n),
        CellValue::Binary(b) => {
            if b.len() <= 64 {
                b.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<_>>().join(" ")
            } else {
                let preview: String = b[..64]
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{} ... ({} bytes total)", preview, b.len())
            }
        }
        CellValue::Error => "(error reading value)".to_string(),
    }
}

fn format_data_type(val: &CellKeyValue) -> String {
    format!("{:?}", val.data_type)
}

pub fn get_values_at_path(
    entry: &HiveEntry,
    key_path: &str,
) -> Result<(KeyInfo, Vec<RegValue>), String> {
    let mut parser = create_parser(entry)?;

    let key = if key_path.is_empty() {
        parser
            .get_root_key()
            .map_err(|e| format!("{:?}", e))?
            .ok_or_else(|| "No root key found".to_string())?
    } else {
        parser
            .get_key(key_path, true)
            .map_err(|e| format!("{:?}", e))?
            .ok_or_else(|| format!("Key not found: {}", key_path))?
    };

    let num_sub_keys = key.cell_sub_key_offsets_absolute.len();
    let timestamp = key.last_key_written_date_and_time();

    let key_info = KeyInfo {
        path: key.path.clone(),
        pretty_path: key.get_pretty_path().to_string(),
        last_written: timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        num_values: key.value_iter().count(),
        num_sub_keys,
    };

    let mut values: Vec<RegValue> = key
        .value_iter()
        .map(|val| {
            let data_type_str = format_data_type(&val);
            let (content, _logs) = val.get_content();
            let data = format_cell_value(&content, &data_type_str);
            let is_default = val.get_pretty_name() == "(default)";

            RegValue {
                name: val.get_pretty_name(),
                data_type: data_type_str,
                data,
                is_default,
            }
        })
        .collect();

    // Sort: (Default) first, then alphabetical
    values.sort_by(|a, b| match (a.is_default, b.is_default) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok((key_info, values))
}

// ── Search ──────────────────────────────────────────────────────

pub fn search_hive(
    entry: &HiveEntry,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, String> {
    let mut parser = create_parser(entry)?;
    let query_lower = query.to_lowercase();
    let mut results = Vec::new();

    let root = parser
        .get_root_key()
        .map_err(|e| format!("{:?}", e))?
        .ok_or_else(|| "No root key found".to_string())?;
    let root_path = root.path;
    let mut stack = vec![root_path.clone()];

    while let Some(path) = stack.pop() {
        if results.len() >= max_results {
            break;
        }

        let mut key = if path == root_path {
            parser
                .get_root_key()
                .map_err(|e| format!("{:?}", e))?
                .ok_or_else(|| "No root key found".to_string())?
        } else {
            parser
                .get_key(&path, true)
                .map_err(|e| format!("{:?}", e))?
                .ok_or_else(|| format!("Key not found: {}", path))?
        };

        let sub_keys = key.read_sub_keys(&mut parser);
        for sub_key in sub_keys {
            stack.push(sub_key.path.clone());
        }

        if key.key_name.to_lowercase().contains(&query_lower) {
            results.push(SearchResult {
                path: key.path.clone(),
                match_type: "Key".to_string(),
                name: key.key_name.clone(),
                preview: String::new(),
            });
        }

        for val in key.value_iter() {
            if results.len() >= max_results {
                break;
            }
            let name = val.get_pretty_name();
            let (content, _) = val.get_content();
            let data_str = format!("{}", content);

            if name.to_lowercase().contains(&query_lower)
                || data_str.to_lowercase().contains(&query_lower)
            {
                results.push(SearchResult {
                    path: key.path.clone(),
                    match_type: format!("{:?}", val.data_type),
                    name,
                    preview: if data_str.len() > 100 {
                        format!("{}...", &data_str[..100])
                    } else {
                        data_str
                    },
                });
            }
        }
    }

    Ok(results)
}
