// =============================================================================
// Browser Forensics — Extension Code File Extractor
// =============================================================================
// Inventories all code files (JS, HTML, CSS, JSON, WASM) within browser
// extension directories for forensic review.
// =============================================================================

use std::path::Path;
use walkdir::WalkDir;
use crate::models::ExtensionCodeFile;

/// Relevant extension file types for forensic analysis.
const CODE_EXTENSIONS: &[(&str, &str)] = &[
    ("js", "js"),
    ("jsx", "js"),
    ("ts", "js"),
    ("tsx", "js"),
    ("mjs", "js"),
    ("html", "html"),
    ("htm", "html"),
    ("css", "css"),
    ("json", "json"),
    ("wasm", "wasm"),
    ("xul", "html"),
];

/// Extract code file inventory from a Chromium Extensions/ directory.
pub fn extract_chromium_extension_files(profile_dir: &Path) -> Vec<ExtensionCodeFile> {
    let ext_dir = profile_dir.join("Extensions");
    if !ext_dir.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();

    // Walk each extension directory
    if let Ok(entries) = std::fs::read_dir(&ext_dir) {
        for entry in entries.flatten() {
            let ext_id_dir = entry.path();
            if !ext_id_dir.is_dir() {
                continue;
            }
            let ext_id = entry.file_name().to_string_lossy().to_string();

            // Try to get extension name from manifest
            let ext_name = find_extension_name(&ext_id_dir);

            // Walk all code files in this extension
            for walker_entry in WalkDir::new(&ext_id_dir)
                .max_depth(10)
                .into_iter()
                .flatten()
            {
                let fpath = walker_entry.path();
                if !fpath.is_file() {
                    continue;
                }

                let extension = fpath
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();

                if let Some(&(_, ftype)) = CODE_EXTENSIONS.iter().find(|&&(ext, _)| ext == extension.as_str()) {
                    let metadata = std::fs::metadata(fpath);
                    let size = metadata.map(|m| m.len()).unwrap_or(0);

                    files.push(ExtensionCodeFile {
                        extension_id: ext_id.clone(),
                        extension_name: ext_name.clone(),
                        file_path: fpath.to_string_lossy().to_string(),
                        file_type: ftype.to_string(),
                        file_size: size,
                    });
                }
            }
        }
    }

    files
}

/// Extract code file inventory from a Firefox extensions directory.
pub fn extract_firefox_extension_files(profile_dir: &Path) -> Vec<ExtensionCodeFile> {
    let ext_dir = profile_dir.join("extensions");
    if !ext_dir.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&ext_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext_id = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                // Unpacked extension
                let ext_name = find_extension_name(&path);
                walk_extension_code_files(&path, &ext_id, &ext_name, &mut files);
            } else if path.extension().map_or(false, |e| e == "xpi") {
                // XPI files are ZIPs — just record the .xpi file itself
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                files.push(ExtensionCodeFile {
                    extension_id: ext_id,
                    extension_name: None,
                    file_path: path.to_string_lossy().to_string(),
                    file_type: "xpi".to_string(),
                    file_size: size,
                });
            }
        }
    }

    files
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_extension_name(ext_dir: &Path) -> Option<String> {
    // Try manifest.json first
    let manifest = ext_dir.join("manifest.json");
    if manifest.exists() {
        if let Ok(raw) = std::fs::read_to_string(&manifest) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                    return Some(name.to_string());
                }
            }
        }
    }

    // Try sub-directories (Chromium: extension_id/version/manifest.json)
    if let Ok(entries) = std::fs::read_dir(ext_dir) {
        for entry in entries.flatten() {
            let mpath = entry.path().join("manifest.json");
            if mpath.exists() {
                if let Ok(raw) = std::fs::read_to_string(&mpath) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                        if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

fn walk_extension_code_files(
    dir: &Path,
    ext_id: &str,
    ext_name: &Option<String>,
    files: &mut Vec<ExtensionCodeFile>,
) {
    for walker_entry in WalkDir::new(dir).max_depth(10).into_iter().flatten() {
        let fpath = walker_entry.path();
        if !fpath.is_file() {
            continue;
        }

        let extension = fpath
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        if let Some(&(_, ftype)) = CODE_EXTENSIONS.iter().find(|&&(ext, _)| ext == extension.as_str()) {
            let size = std::fs::metadata(fpath).map(|m| m.len()).unwrap_or(0);
            files.push(ExtensionCodeFile {
                extension_id: ext_id.to_string(),
                extension_name: ext_name.clone(),
                file_path: fpath.to_string_lossy().to_string(),
                file_type: ftype.to_string(),
                file_size: size,
            });
        }
    }
}
