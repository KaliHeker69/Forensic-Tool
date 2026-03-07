// =============================================================================
// Browser Forensics — Evidence Directory Scanner
// =============================================================================
// Scans an evidence directory for browser profile folders.
// Detects: Chrome, Edge, Brave, Firefox, Tor Browser
// =============================================================================

use std::path::{Path, PathBuf};
use crate::models::Browser;

/// A detected browser profile on disk.
#[derive(Debug)]
pub struct DetectedProfile {
    pub browser: Browser,
    pub profile_name: String,
    pub profile_path: PathBuf,
}

/// Scan the evidence directory for browser artifact folders.
///
/// Expected layout:
/// ```text
/// evidence/
///   chrome/          (or "Google/Chrome/User Data")
///     Default/
///     Profile 1/
///   brave/           (or "BraveSoftware/Brave-Browser/User Data")
///   edge/            (or "Microsoft/Edge/User Data")
///   firefox/         (or "Mozilla/Firefox/Profiles")
///     xxxxxxxx.default-release/
///   tor-browser/
/// ```
pub fn scan_evidence_dir(dir: &Path) -> Vec<DetectedProfile> {
    let mut profiles = Vec::new();

    if !dir.is_dir() {
        eprintln!("[!] Evidence directory does not exist: {:?}", dir);
        return profiles;
    }

    // Iterate over top-level entries
    let entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten().collect(),
        Err(e) => {
            eprintln!("[!] Cannot read evidence dir: {}", e);
            return profiles;
        }
    };

    for entry in &entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry
            .file_name()
            .to_string_lossy()
            .to_lowercase();

        if let Some(browser) = folder_to_browser(&name) {
            match browser {
                Browser::Chrome | Browser::Edge | Browser::Brave => {
                    collect_chromium_profiles(&path, browser, &mut profiles);
                }
                Browser::Firefox => {
                    collect_firefox_profiles(&path, &mut profiles);
                }
                _ => {}
            }
        }
    }

    // Also check for nested Windows-style paths
    // e.g., evidence/AppData/Local/Google/Chrome/User Data
    let chrome_win = dir.join("AppData/Local/Google/Chrome/User Data");
    if chrome_win.is_dir() {
        collect_chromium_profiles(&chrome_win, Browser::Chrome, &mut profiles);
    }
    let edge_win = dir.join("AppData/Local/Microsoft/Edge/User Data");
    if edge_win.is_dir() {
        collect_chromium_profiles(&edge_win, Browser::Edge, &mut profiles);
    }
    let brave_win = dir.join("AppData/Local/BraveSoftware/Brave-Browser/User Data");
    if brave_win.is_dir() {
        collect_chromium_profiles(&brave_win, Browser::Brave, &mut profiles);
    }
    let ff_win = dir.join("AppData/Roaming/Mozilla/Firefox/Profiles");
    if ff_win.is_dir() {
        collect_firefox_profiles(&ff_win, &mut profiles);
    }

    // Linux-style paths
    let chrome_linux = dir.join(".config/google-chrome");
    if chrome_linux.is_dir() {
        collect_chromium_profiles(&chrome_linux, Browser::Chrome, &mut profiles);
    }
    let brave_linux = dir.join(".config/BraveSoftware/Brave-Browser");
    if brave_linux.is_dir() {
        collect_chromium_profiles(&brave_linux, Browser::Brave, &mut profiles);
    }
    let edge_linux = dir.join(".config/microsoft-edge");
    if edge_linux.is_dir() {
        collect_chromium_profiles(&edge_linux, Browser::Edge, &mut profiles);
    }
    let ff_linux = dir.join(".mozilla/firefox");
    if ff_linux.is_dir() {
        collect_firefox_profiles(&ff_linux, &mut profiles);
    }

    // Tor Browser detection
    check_tor_browser(dir, &mut profiles);

    profiles
}

/// Map a folder name to a browser type.
fn folder_to_browser(name: &str) -> Option<Browser> {
    match name {
        "chrome" | "google-chrome" | "google_chrome" | "chromium" => Some(Browser::Chrome),
        "edge" | "microsoft-edge" | "msedge" => Some(Browser::Edge),
        "brave" | "brave-browser" | "brave_browser" => Some(Browser::Brave),
        "firefox" | "mozilla-firefox" | "mozilla" => Some(Browser::Firefox),
        "tor" | "tor-browser" | "tor_browser" | "torbrowser" => Some(Browser::Firefox),
        _ => None,
    }
}

/// Check if a directory looks like a Chromium profile (has History or Cookies).
fn is_chromium_profile(dir: &Path) -> bool {
    dir.join("History").exists()
        || dir.join("Cookies").exists()
        || dir.join("Network/Cookies").exists()
        || dir.join("Preferences").exists()
        || dir.join("Bookmarks").exists()
        || dir.join("Login Data").exists()
}

/// Check if a directory looks like a Firefox profile.
fn is_firefox_profile(dir: &Path) -> bool {
    dir.join("places.sqlite").exists()
        || dir.join("cookies.sqlite").exists()
        || dir.join("logins.json").exists()
        || dir.join("key4.db").exists()
}

/// Collect Chromium-based profiles from a User Data directory.
fn collect_chromium_profiles(user_data_dir: &Path, browser: Browser, out: &mut Vec<DetectedProfile>) {
    // Check if user_data_dir itself is a profile
    if is_chromium_profile(user_data_dir) {
        let name = user_data_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        out.push(DetectedProfile {
            browser: browser.clone(),
            profile_name: name,
            profile_path: user_data_dir.to_path_buf(),
        });
        return;
    }

    // Look for profile sub-directories (Default, Profile 1, Profile 2, etc.)
    if let Ok(entries) = std::fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if is_chromium_profile(&path) {
                let name = entry.file_name().to_string_lossy().to_string();
                out.push(DetectedProfile {
                    browser: browser.clone(),
                    profile_name: name,
                    profile_path: path,
                });
            }
        }
    }
}

/// Collect Firefox profiles from a Profiles directory.
fn collect_firefox_profiles(profiles_dir: &Path, out: &mut Vec<DetectedProfile>) {
    // Check if profiles_dir itself is a profile
    if is_firefox_profile(profiles_dir) {
        let name = profiles_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        out.push(DetectedProfile {
            browser: Browser::Firefox,
            profile_name: name,
            profile_path: profiles_dir.to_path_buf(),
        });
        return;
    }

    // Look for profile sub-directories (xxxxxxxx.default-release, etc.)
    if let Ok(entries) = std::fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if is_firefox_profile(&path) {
                let name = entry.file_name().to_string_lossy().to_string();
                out.push(DetectedProfile {
                    browser: Browser::Firefox,
                    profile_name: name,
                    profile_path: path,
                });
            }
        }
    }
}

/// Look for Tor Browser bundle in the evidence directory.
fn check_tor_browser(dir: &Path, profiles: &mut Vec<DetectedProfile>) {
    let candidates = [
        dir.join("tor-browser"),
        dir.join("torbrowser"),
        dir.join("tor_browser"),
        dir.join("Tor Browser"),
    ];

    for candidate in &candidates {
        if !candidate.is_dir() {
            continue;
        }
        // Tor Browser has a Firefox profile inside Browser/TorBrowser/Data/Browser/profile.default
        let tor_profile = candidate.join("Browser/TorBrowser/Data/Browser/profile.default");
        if is_firefox_profile(&tor_profile) {
            profiles.push(DetectedProfile {
                browser: Browser::Firefox,
                profile_name: "Tor Browser".to_string(),
                profile_path: tor_profile,
            });
            continue;
        }
        // Also check simpler layouts
        if is_firefox_profile(candidate) {
            profiles.push(DetectedProfile {
                browser: Browser::Firefox,
                profile_name: "Tor Browser".to_string(),
                profile_path: candidate.clone(),
            });
        }
    }
}
