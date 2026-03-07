use crate::models::common::{Finding, FindingCategory, Severity};
use crate::models::network_conn::NetworkConnection;

/// Analyze NetworkConnections records for suspicious patterns
pub fn analyze(records: &[NetworkConnection]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut finding_id = 0;

    // Track unique SSIDs/profiles
    let mut seen_profiles: Vec<String> = Vec::new();

    for record in records {
        let connected_time = record.connected_time.unwrap_or(0);

        // 1. Extremely long connections (>24 hours in seconds)
        if connected_time > 86_400 {
            finding_id += 1;
            findings.push(Finding {
                id: format!("CONN-LONG-{:04}", finding_id),
                severity: Severity::Low,
                category: FindingCategory::ConnectionAnomaly,
                title: "Long-Duration Connection".to_string(),
                description: format!(
                    "Network connection lasted {} hours — potential persistent connection or VPN tunnel",
                    connected_time / 3600
                ),
                evidence: vec![
                    format!("Connected Time: {} seconds ({:.1} hours)", connected_time, connected_time as f64 / 3600.0),
                    format!("Interface: {}", record.interface_type.as_deref().unwrap_or("Unknown")),
                    format!("Network Profile: {}", record.l2_profile_id.as_deref().unwrap_or("Unknown")),
                    format!("Connect Start: {}", record.connect_start_time.as_deref().unwrap_or("N/A")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: None,
                user: None,
            });
        }

        // 2. Track unique network profiles for SSID analysis
        if let Some(ref profile) = record.l2_profile_id {
            if !profile.is_empty() && !seen_profiles.contains(profile) {
                seen_profiles.push(profile.clone());
            }
        }

        // 3. Very short connections in rapid succession (potential scanning)
        if connected_time > 0 && connected_time < 5 {
            finding_id += 1;
            findings.push(Finding {
                id: format!("CONN-SHORT-{:04}", finding_id),
                severity: Severity::Low,
                category: FindingCategory::ConnectionAnomaly,
                title: "Very Short Connection".to_string(),
                description: format!(
                    "Network connection lasted only {} seconds — could indicate scanning or connectivity issues",
                    connected_time
                ),
                evidence: vec![
                    format!("Connected Time: {} seconds", connected_time),
                    format!("Interface: {}", record.interface_type.as_deref().unwrap_or("Unknown")),
                    format!("Network Profile: {}", record.l2_profile_id.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: None,
                user: None,
            });
        }
    }

    // 4. Report connected network profiles (informational)
    if !seen_profiles.is_empty() {
        finding_id += 1;
        findings.push(Finding {
            id: format!("CONN-PROFILES-{:04}", finding_id),
            severity: Severity::Info,
            category: FindingCategory::ConnectionAnomaly,
            title: "Network Profiles Summary".to_string(),
            description: format!(
                "System connected to {} unique network profile(s) during the analysis period",
                seen_profiles.len()
            ),
            evidence: seen_profiles.iter().map(|p| format!("Profile: {}", p)).collect(),
            timestamp: None,
            app_path: None,
            user: None,
        });
    }

    findings
}
