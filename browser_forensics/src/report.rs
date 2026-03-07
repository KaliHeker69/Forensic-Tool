// =============================================================================
// Browser Forensics — Report Builder
// =============================================================================
// Reads ForensicInput, builds ForensicReport with summary statistics,
// automated timeline, and privacy indicators.
// =============================================================================

use chrono::Utc;

use crate::models::*;
use crate::timeline;
use crate::privacy_detector;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the forensic report from raw input.
pub fn build_report(input: ForensicInput) -> ForensicReport {
    // Compute timeline across all artifacts
    let timeline_events = timeline::build_timeline(&input);

    // Detect privacy indicators
    let privacy_indicators = privacy_detector::detect_privacy_indicators(&input);

    let mut summary = compute_summary(&input);
    summary.total_timeline_events = timeline_events.len();
    summary.total_privacy_indicators = privacy_indicators.len();

    ForensicReport {
        report_generated: Utc::now().to_rfc3339(),
        tool_version: TOOL_VERSION.to_string(),
        case_info: input.case_info,
        summary,
        artifacts: input.artifacts,
        timeline: timeline_events,
        privacy_indicators,
        dns_cache: input.dns_cache,
        prefetch: input.prefetch,
        jump_lists: input.jump_lists,
        zone_identifiers: input.zone_identifiers,
    }
}

fn compute_summary(input: &ForensicInput) -> ReportSummary {
    let mut total_history = 0usize;
    let mut total_downloads = 0usize;
    let mut total_cookies = 0usize;
    let mut total_logins = 0usize;
    let mut total_autofill = 0usize;
    let mut total_bookmarks = 0usize;
    let mut total_extensions = 0usize;
    let mut total_cache = 0usize;
    let mut total_sessions = 0usize;
    let mut browsers: Vec<String> = Vec::new();
    let mut has_brave_wallet = false;
    let mut has_brave_tor = false;
    let mut total_wal_recovered = 0usize;
    let mut total_cache_extracted = 0usize;
    let mut total_extension_files = 0usize;

    for coll in &input.artifacts {
        total_history += coll.history.len();
        total_downloads += coll.downloads.len();
        total_cookies += coll.cookies.len();
        total_logins += coll.logins.len();
        total_autofill += coll.autofill.len() + coll.form_history.len();
        total_bookmarks += coll.bookmarks.len();
        total_extensions += coll.extensions.len();
        total_cache += coll.cache.len();
        total_sessions += coll.sessions.len();
        total_wal_recovered += coll.wal_recovered.len();
        total_cache_extracted += coll.cache_extracted.len();
        total_extension_files += coll.extension_files.len();

        let bname = coll.browser.to_string();
        if !browsers.contains(&bname) {
            browsers.push(bname);
        }

        if !coll.brave_wallet.is_empty() {
            has_brave_wallet = true;
        }
        if coll.brave_tor.is_some() {
            has_brave_tor = true;
        }
    }

    ReportSummary {
        total_browsers: browsers.len(),
        total_history_entries: total_history,
        total_downloads,
        total_cookies,
        total_logins,
        total_autofill,
        total_bookmarks,
        total_extensions,
        total_cache_entries: total_cache,
        total_sessions,
        browsers_found: browsers,
        has_brave_wallet,
        has_brave_tor,
        has_dns_cache: !input.dns_cache.is_empty(),
        has_prefetch: !input.prefetch.is_empty(),
        has_jump_lists: !input.jump_lists.is_empty(),
        has_zone_identifiers: !input.zone_identifiers.is_empty(),
        total_timeline_events: 0, // set after timeline is built
        total_wal_recovered,
        total_cache_extracted,
        total_extension_files,
        total_privacy_indicators: 0, // set after detection
    }
}
