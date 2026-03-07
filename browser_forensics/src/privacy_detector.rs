// =============================================================================
// Browser Forensics — Private / Incognito / Tor Session Detector
// =============================================================================
// Detects indicators of private browsing, incognito mode, Tor usage,
// and other privacy-related configurations.
// =============================================================================

use crate::models::*;

/// Analyze all artifact collections for privacy indicators.
pub fn detect_privacy_indicators(input: &ForensicInput) -> Vec<PrivacyIndicator> {
    let mut indicators = Vec::new();

    for coll in &input.artifacts {
        let browser = coll.browser.to_string();
        let profile = coll.profile_name.clone();

        // --- Tor Browser detection ---
        detect_tor_browser(coll, &browser, &profile, &mut indicators);

        // --- Incognito / private browsing indicators in preferences ---
        detect_incognito_preferences(coll, &browser, &profile, &mut indicators);

        // --- .onion URLs in history ---
        detect_onion_urls(coll, &browser, &profile, &mut indicators);

        // --- VPN/Proxy indicators ---
        detect_vpn_proxy(coll, &browser, &profile, &mut indicators);

        // --- Privacy-focused extensions ---
        detect_privacy_extensions(coll, &browser, &profile, &mut indicators);

        // --- Brave-specific indicators ---
        detect_brave_privacy(coll, &browser, &profile, &mut indicators);

        // --- Suspicious patterns ---
        detect_suspicious_patterns(coll, &browser, &profile, &mut indicators);
    }

    indicators
}

// ---------------------------------------------------------------------------
// Individual detectors
// ---------------------------------------------------------------------------

fn detect_tor_browser(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    // Check profile name
    if let Some(ref pn) = coll.profile_name {
        let pn_lower = pn.to_lowercase();
        if pn_lower.contains("tor") {
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "tor".into(),
                evidence: format!("Profile name indicates Tor Browser: '{}'", pn),
                severity: "critical".into(),
            });
        }
    }

    // Check profile path
    if let Some(ref pp) = coll.profile_path {
        let pp_lower = pp.to_lowercase();
        if pp_lower.contains("tor") || pp_lower.contains("torbrowser") {
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "tor".into(),
                evidence: format!("Profile path indicates Tor Browser: '{}'", pp),
                severity: "critical".into(),
            });
        }
    }

    // Brave Tor indicators
    if let Some(ref tor) = coll.brave_tor {
        if tor.tor_enabled == Some(true) {
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "tor".into(),
                evidence: "Brave Tor mode was enabled".into(),
                severity: "critical".into(),
            });
        }
        if let Some(ref urls) = tor.onion_urls_found {
            if !urls.is_empty() {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "tor".into(),
                    evidence: format!("{} .onion URLs found in Brave Tor data", urls.len()),
                    severity: "critical".into(),
                });
            }
        }
    }
}

fn detect_incognito_preferences(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    for pref in &coll.preferences {
        let key_lower = pref.key.to_lowercase();

        // Incognito/private mode settings
        if key_lower.contains("incognito") || key_lower.contains("private") {
            let val_str = serde_json::to_string(&pref.value).unwrap_or_default();
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "incognito".into(),
                evidence: format!("Preference '{}' = {}", pref.key, val_str),
                severity: "high".into(),
            });
        }

        // "Do Not Track" enabled
        if key_lower.contains("do_not_track") || key_lower.contains("donottrack") {
            if pref.value == serde_json::Value::Bool(true) || pref.value == serde_json::json!(1) {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "privacy_mode".into(),
                    evidence: "Do Not Track enabled".into(),
                    severity: "low".into(),
                });
            }
        }

        // DNS over HTTPS
        if key_lower.contains("dns_over_https") || key_lower.contains("doh") {
            let val_str = serde_json::to_string(&pref.value).unwrap_or_default();
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "privacy_mode".into(),
                evidence: format!("DNS over HTTPS configured: {}", val_str),
                severity: "medium".into(),
            });
        }

        // Session restore disabled (may indicate desire to not persist history)
        if key_lower.contains("session.restore_on_startup") {
            if pref.value == serde_json::json!(1) {
                // 1 = restore last session; 5 = open specific pages (default)
                // Not necessarily suspicious
            }
        }

        // Safe browsing disabled
        if key_lower.contains("safebrowsing.enabled") {
            if pref.value == serde_json::Value::Bool(false) {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "privacy_mode".into(),
                    evidence: "Safe Browsing disabled — may indicate evasion".into(),
                    severity: "medium".into(),
                });
            }
        }
    }
}

fn detect_onion_urls(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    let mut onion_count = 0;
    let mut onion_examples = Vec::new();

    for entry in &coll.history {
        if entry.url.contains(".onion") {
            onion_count += 1;
            if onion_examples.len() < 5 {
                onion_examples.push(entry.url.clone());
            }
        }
    }

    for entry in &coll.bookmarks {
        if entry.url.contains(".onion") {
            onion_count += 1;
            if onion_examples.len() < 5 {
                onion_examples.push(entry.url.clone());
            }
        }
    }

    for entry in &coll.downloads {
        if entry.url.contains(".onion") {
            onion_count += 1;
        }
    }

    if onion_count > 0 {
        indicators.push(PrivacyIndicator {
            browser: browser.into(),
            profile: profile.clone(),
            indicator_type: "tor".into(),
            evidence: format!(
                "{} .onion URL(s) found. Examples: {}",
                onion_count,
                onion_examples.join(", ")
            ),
            severity: "critical".into(),
        });
    }
}

fn detect_vpn_proxy(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    for pref in &coll.preferences {
        let key_lower = pref.key.to_lowercase();
        if key_lower.contains("proxy") {
            let val_str = serde_json::to_string(&pref.value).unwrap_or_default();
            if val_str != "null" && val_str != "{}" && val_str != "\"\"" {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "vpn".into(),
                    evidence: format!("Proxy configuration detected: {} = {}", pref.key, val_str),
                    severity: "high".into(),
                });
            }
        }
    }

    // Check history for known VPN/proxy services
    let vpn_domains = [
        "nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com",
        "mullvad.net", "privateinternetaccess.com", "windscribe.com",
        "tunnelbear.com", "hide.me", "cyberghost", "ivpn.net",
    ];

    for entry in &coll.history {
        let url_lower = entry.url.to_lowercase();
        for domain in &vpn_domains {
            if url_lower.contains(domain) {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "vpn".into(),
                    evidence: format!("VPN service accessed: {}", entry.url),
                    severity: "medium".into(),
                });
                break;
            }
        }
    }
}

fn detect_privacy_extensions(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    let privacy_ext_patterns = [
        ("ublock", "Ad/tracker blocker"),
        ("adblock", "Ad blocker"),
        ("privacy badger", "Tracker blocker"),
        ("ghostery", "Tracker blocker"),
        ("noscript", "Script blocker"),
        ("https everywhere", "HTTPS enforcer"),
        ("cookie autodelete", "Cookie cleaner"),
        ("decentraleyes", "CDN privacy"),
        ("canvas blocker", "Fingerprint protection"),
        ("chameleon", "User-agent spoofer"),
        ("user-agent switcher", "User-agent spoofer"),
        ("vpn", "VPN extension"),
        ("proxy", "Proxy extension"),
        ("tor", "Tor-related extension"),
        ("privacy", "Privacy extension"),
        ("cleaner", "Data cleaner"),
        ("history eraser", "History eraser"),
        ("click&clean", "Data cleaner"),
    ];

    for ext in &coll.extensions {
        let name_lower = ext
            .name
            .as_deref()
            .unwrap_or("")
            .to_lowercase();
        let id_lower = ext.id.to_lowercase();

        for (pattern, category) in &privacy_ext_patterns {
            if name_lower.contains(pattern) || id_lower.contains(pattern) {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "privacy_mode".into(),
                    evidence: format!(
                        "{}: {} ({})",
                        category,
                        ext.name.as_deref().unwrap_or(&ext.id),
                        ext.id
                    ),
                    severity: "medium".into(),
                });
                break;
            }
        }
    }
}

fn detect_brave_privacy(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    // Check Brave Shields
    for shield in &coll.brave_shields {
        if shield.fingerprint_block.as_deref() == Some("aggressive") {
            indicators.push(PrivacyIndicator {
                browser: browser.into(),
                profile: profile.clone(),
                indicator_type: "privacy_mode".into(),
                evidence: format!("Brave Shields aggressive fingerprint blocking on {}", shield.site),
                severity: "medium".into(),
            });
        }
    }

    // Check for Brave Wallet (might be relevant for crypto investigations)
    if !coll.brave_wallet.is_empty() {
        indicators.push(PrivacyIndicator {
            browser: browser.into(),
            profile: profile.clone(),
            indicator_type: "privacy_mode".into(),
            evidence: format!("Brave Wallet with {} entries found", coll.brave_wallet.len()),
            severity: "medium".into(),
        });
    }
}

fn detect_suspicious_patterns(
    coll: &ArtifactCollection,
    browser: &str,
    profile: &Option<String>,
    indicators: &mut Vec<PrivacyIndicator>,
) {
    // Check for very sparse history (might indicate clearing)
    if coll.history.len() < 5 && !coll.cookies.is_empty() && coll.cookies.len() > 50 {
        indicators.push(PrivacyIndicator {
            browser: browser.into(),
            profile: profile.clone(),
            indicator_type: "privacy_mode".into(),
            evidence: format!(
                "Sparse history ({} entries) but many cookies ({}) — possible history clearing",
                coll.history.len(),
                coll.cookies.len()
            ),
            severity: "high".into(),
        });
    }

    // Check for suspicious search queries in history
    let suspicious_terms = [
        "delete history", "clear browsing data", "incognito",
        "antiforensic", "anti-forensic", "clear cookies",
        "browser cleaner", "evidence destroyer", "privacy cleaner",
        "how to delete", "erase history", "bleachbit",
    ];

    for entry in &coll.history {
        let url_lower = entry.url.to_lowercase();
        for term in &suspicious_terms {
            if url_lower.contains(term) {
                indicators.push(PrivacyIndicator {
                    browser: browser.into(),
                    profile: profile.clone(),
                    indicator_type: "privacy_mode".into(),
                    evidence: format!("Anti-forensic search detected: {}", entry.url),
                    severity: "high".into(),
                });
                break;
            }
        }
    }
}
