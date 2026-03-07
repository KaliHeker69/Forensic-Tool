//! JSONL (JSON Lines) parser for Volatility3 outputs
//!
//! Parses JSONL format where each line is a valid JSON object.
//! This is easier to parse than CSV and handles nested structures natively.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::de::DeserializeOwned;

use crate::error::{Result, Vol3Error};

/// JSONL Parser for Volatility3 plugin outputs
///
/// JSONL (JSON Lines) format has one JSON object per line, making it:
/// - Easy to stream (no need to load entire file)
/// - Self-describing (no header ambiguity)
/// - Robust to special characters (no escaping issues)
pub struct JsonlParser;

impl JsonlParser {
    /// Parse a JSONL file into a vector of typed records
    ///
    /// Each non-empty line is parsed as a JSON object.
    /// Empty lines and lines that fail to parse are skipped with warnings.
    pub fn parse<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
        let file = File::open(path).map_err(|e| Vol3Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        let mut records = Vec::new();
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    log::warn!(
                        "Failed to read line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            // Skip empty lines
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Try to parse the line as JSON
            match serde_json::from_str::<T>(trimmed) {
                Ok(record) => records.push(record),
                Err(e) => {
                    log::debug!(
                        "Failed to parse line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                }
            }
        }

        Ok(records)
    }

    /// Parse a JSONL file into a vector of raw JSON values
    ///
    /// Useful for dynamic processing when the schema is unknown.
    pub fn parse_raw(path: &Path) -> Result<Vec<serde_json::Value>> {
        let file = File::open(path).map_err(|e| Vol3Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        let mut records = Vec::new();
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    log::warn!(
                        "Failed to read line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(value) => records.push(value),
                Err(e) => {
                    log::debug!(
                        "Failed to parse line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                }
            }
        }

        Ok(records)
    }

    /// Get the count of valid records without fully parsing
    pub fn count_records(path: &Path) -> Result<usize> {
        let file = File::open(path).map_err(|e| Vol3Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);

        let count = reader
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .filter(|l| serde_json::from_str::<serde_json::Value>(l.trim()).is_ok())
            .count();

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_simple_jsonl() {
        let mut file = NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(file, r#"{{"PID": 4, "ImageFileName": "System", "PPID": 0}}"#).unwrap();
        writeln!(file, r#"{{"PID": 108, "ImageFileName": "smss.exe", "PPID": 4}}"#).unwrap();

        #[derive(Debug, serde::Deserialize)]
        struct TestProcess {
            #[serde(alias = "PID")]
            pid: u32,
            #[serde(alias = "ImageFileName")]
            name: String,
            #[serde(alias = "PPID")]
            ppid: u32,
        }

        let result: Vec<TestProcess> = JsonlParser::parse(file.path()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].pid, 4);
        assert_eq!(result[0].name, "System");
        assert_eq!(result[1].ppid, 4);
    }

    #[test]
    fn test_skip_empty_lines() {
        let mut file = NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(file).unwrap(); // Empty first line (like Volatility output)
        writeln!(file, r#"{{"PID": 4, "Name": "System"}}"#).unwrap();
        writeln!(file).unwrap(); // Another empty line
        writeln!(file, r#"{{"PID": 108, "Name": "smss.exe"}}"#).unwrap();
        writeln!(file).unwrap(); // Trailing empty line

        #[derive(Debug, serde::Deserialize)]
        struct TestProcess {
            #[serde(alias = "PID")]
            pid: u32,
            #[serde(alias = "Name")]
            name: String,
        }

        let result: Vec<TestProcess> = JsonlParser::parse(file.path()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_skip_malformed_lines() {
        let mut file = NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(file, r#"{{"PID": 4, "Name": "System"}}"#).unwrap();
        writeln!(file, "this is not valid json").unwrap();
        writeln!(file, r#"{{"PID": 108, "Name": "smss.exe"}}"#).unwrap();

        #[derive(Debug, serde::Deserialize)]
        struct TestProcess {
            #[serde(alias = "PID")]
            pid: u32,
            #[serde(alias = "Name")]
            name: String,
        }

        let result: Vec<TestProcess> = JsonlParser::parse(file.path()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_raw() {
        let mut file = NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(file).unwrap();
        writeln!(file, r#"{{"key": "value", "num": 42}}"#).unwrap();

        let result = JsonlParser::parse_raw(file.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["key"], "value");
        assert_eq!(result[0]["num"], 42);
    }
}
