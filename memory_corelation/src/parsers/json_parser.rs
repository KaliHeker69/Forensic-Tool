//! JSON parser for Volatility3 outputs (TreeGrid format)

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Result, Vol3Error};

/// JSON Parser for Volatility3 TreeGrid format
pub struct JsonParser;

impl JsonParser {
    /// Parse a JSON file into a vector of typed records
    ///
    /// Volatility3 JSON output uses a TreeGrid format with:
    /// - "columns": array of column definitions
    /// - "rows": array of data rows (can be nested for tree output)
    pub fn parse<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
        let file = File::open(path).map_err(|e| Vol3Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        let json: Value = serde_json::from_reader(reader).map_err(|e| Vol3Error::JsonParse {
            path: path.display().to_string(),
            source: e,
        })?;

        // Handle TreeGrid format
        if let Some(columns) = json.get("columns") {
            if let Some(rows) = json.get("rows") {
                return Self::parse_treegrid::<T>(columns, rows, path);
            }
        }

        // Try parsing as a simple array
        if let Some(arr) = json.as_array() {
            let mut results = Vec::new();
            for item in arr {
                match serde_json::from_value(item.clone()) {
                    Ok(record) => results.push(record),
                    Err(e) => {
                        log::warn!("Failed to parse record in {}: {}", path.display(), e);
                    }
                }
            }
            return Ok(results);
        }

        // Try parsing as a single object containing an array
        for key in ["data", "results", "records", "items"] {
            if let Some(arr) = json.get(key).and_then(|v| v.as_array()) {
                let mut results = Vec::new();
                for item in arr {
                    match serde_json::from_value(item.clone()) {
                        Ok(record) => results.push(record),
                        Err(e) => {
                            log::warn!("Failed to parse record in {}: {}", path.display(), e);
                        }
                    }
                }
                return Ok(results);
            }
        }

        Ok(Vec::new())
    }

    /// Parse TreeGrid format (columns + rows)
    fn parse_treegrid<T: DeserializeOwned>(
        columns: &Value,
        rows: &Value,
        path: &Path,
    ) -> Result<Vec<T>> {
        // Extract column names
        let column_names: Vec<String> = columns
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| {
                        c.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        if column_names.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        Self::parse_rows(&column_names, rows, &mut results, path);
        Ok(results)
    }

    /// Recursively parse rows (handles nested tree structure)
    fn parse_rows<T: DeserializeOwned>(
        columns: &[String],
        rows: &Value,
        results: &mut Vec<T>,
        path: &Path,
    ) {
        if let Some(arr) = rows.as_array() {
            for row in arr {
                // Each row is an object with "values" and optionally "children"
                if let Some(values) = row.get("values").or(row.as_array().map(|_| row)) {
                    // Build a JSON object from column names and values
                    let mut obj = serde_json::Map::new();

                    if let Some(values_arr) = values.as_array() {
                        for (i, col_name) in columns.iter().enumerate() {
                            if let Some(val) = values_arr.get(i) {
                                obj.insert(col_name.clone(), val.clone());
                            }
                        }
                    }

                    if !obj.is_empty() {
                        match serde_json::from_value(Value::Object(obj)) {
                            Ok(record) => results.push(record),
                            Err(e) => {
                                log::warn!("Failed to parse TreeGrid row in {}: {}", path.display(), e);
                            }
                        }
                    }
                }

                // Handle nested children
                if let Some(children) = row.get("children") {
                    Self::parse_rows(columns, children, results, path);
                }
            }
        }
    }

    /// Parse raw JSON into untyped Value
    pub fn parse_raw(path: &Path) -> Result<Value> {
        let file = File::open(path).map_err(|e| Vol3Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).map_err(|e| Vol3Error::JsonParse {
            path: path.display().to_string(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_simple_array() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(
            file,
            r#"[{{"PID": 1, "Name": "System"}}, {{"PID": 4, "Name": "smss.exe"}}]"#
        )
        .unwrap();

        #[derive(Debug, serde::Deserialize)]
        struct TestProcess {
            #[serde(alias = "PID")]
            pid: u32,
            #[serde(alias = "Name")]
            name: String,
        }

        let result: Vec<TestProcess> = JsonParser::parse(file.path()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].pid, 1);
    }

    #[test]
    fn test_parse_treegrid() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        writeln!(
            file,
            r#"{{
                "columns": [{{"name": "PID"}}, {{"name": "Name"}}],
                "rows": [
                    {{"values": [1, "System"]}},
                    {{"values": [4, "smss.exe"]}}
                ]
            }}"#
        )
        .unwrap();

        #[derive(Debug, serde::Deserialize)]
        struct TestProcess {
            #[serde(alias = "PID")]
            pid: u32,
            #[serde(alias = "Name")]
            name: String,
        }

        let result: Vec<TestProcess> = JsonParser::parse(file.path()).unwrap();
        assert_eq!(result.len(), 2);
    }
}
