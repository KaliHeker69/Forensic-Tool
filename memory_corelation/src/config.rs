use serde::Deserialize;
use std::fs;
use std::path::Path;
use anyhow::Result;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct WhitelistConfig {
    pub dll_whitelist: Vec<DllWhitelistEntry>,
    #[serde(default)]
    pub process_dll_whitelist: Vec<ProcessDllEntry>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct DllWhitelistEntry {
    pub path_pattern: String,
    pub filenames: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ProcessDllEntry {
    pub process_name: String,
    pub allowed_dlls: Vec<String>,
}

impl WhitelistConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Check if a DLL is whitelisted for a specific process based on name found in config
    pub fn get_allowed_dlls(&self, process_name: &str) -> Option<&[String]> {
         self.process_dll_whitelist.iter()
            .find(|e| e.process_name.eq_ignore_ascii_case(process_name))
            .map(|e| e.allowed_dlls.as_slice())
    }

    pub fn is_whitelisted(&self, dll_path: &str) -> bool {
        let normalized = normalize_path(dll_path);
        
        for entry in &self.dll_whitelist {
            if normalized.contains(&entry.path_pattern) {
                // If specific filenames are provided, check them
                if !entry.filenames.is_empty() {
                    for filename in &entry.filenames {
                        if normalized.ends_with(&filename.to_lowercase()) {
                            return true;
                        }
                    }
                } else {
                    // If no filenames provided, whitelist the entire pattern
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BlacklistConfig {
    pub suspicious_paths: Vec<String>,
}

impl BlacklistConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn is_suspicious(&self, dll_path: &str) -> bool {
        let normalized = normalize_path(dll_path);
        for pattern in &self.suspicious_paths {
            if normalized.contains(pattern) {
                return true;
            }
        }
        false
    }
}

/// Normalize path for consistent comparison:
/// 1. Unify separators to backslash
/// 2. Lowercase
/// 3. Resolve ".." and "." components
fn normalize_path(path: &str) -> String {
    let lower = path.to_lowercase().replace('/', "\\");
    let mut stack = Vec::new();

    for part in lower.split('\\') {
        if part == "." {
            continue;
        } else if part == ".." {
            if !stack.is_empty() {
                // If stack isn't empty, try to pop unless we hit root or another ..
                if let Some(last) = stack.last() {
                    if *last == ".." {
                        stack.push(part);
                    } else if *last != "" {
                        stack.pop();
                    }
                }
            } else {
                stack.push(part);
            }
        } else {
            stack.push(part);
        }
    }
    
    stack.join("\\")
}
