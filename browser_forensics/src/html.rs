// =============================================================================
// Browser Forensics — HTML Report Generator
// =============================================================================
// Produces a self-contained, styled HTML forensic report from ForensicReport.
// =============================================================================

use crate::models::*;
use std::fmt::Write as FmtWrite;

/// Generate a full HTML report as a String.
pub fn render_html(report: &ForensicReport) -> String {
    let mut h = String::with_capacity(128 * 1024);

    write_head(&mut h, report);
    write_navbar(&mut h, report);
    write_case_info(&mut h, report);
    write_dashboard(&mut h, report);
    write_summary(&mut h, report);

    for (idx, coll) in report.artifacts.iter().enumerate() {
        write_artifact_collection(&mut h, coll, idx);
    }

    // URL / Domain analysis
    write_domain_analysis(&mut h, report);

    // Timeline
    write_timeline(&mut h, report);

    // Behavioral analysis
    write_behavioral_analysis(&mut h, report);

    // Privacy indicators
    write_privacy_indicators(&mut h, report);

    // System-wide artifacts
    write_system_artifacts(&mut h, report);

    // Inline JS data + chart init
    write_inline_scripts(&mut h, report);

    write_footer(&mut h, report);
    h
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn opt(s: &Option<String>) -> String {
    match s {
        Some(v) => esc(v),
        None => String::from("—"),
    }
}

fn opt_bool(b: &Option<bool>) -> &str {
    match b {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "—",
    }
}

fn opt_u64(n: &Option<u64>) -> String {
    match n {
        Some(v) => v.to_string(),
        None => String::from("—"),
    }
}

// ---------------------------------------------------------------------------
// HTML Sections
// ---------------------------------------------------------------------------

fn write_head(h: &mut String, report: &ForensicReport) {
    let title = match &report.case_info {
        Some(ci) => ci
            .case_name
            .clone()
            .unwrap_or_else(|| "Browser Forensics Report".into()),
        None => "Browser Forensics Report".into(),
    };

    let _ = write!(
        h,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
:root {{
  --bg: #0d1117;
  --bg-primary: #0d1117;
  --surface: #161b22;
  --bg-secondary: #161b22;
  --bg-tertiary: #1f2428;
  --border: #30363d;
  --border-color: #30363d;
  --text: #c9d1d9;
  --text-primary: #c9d1d9;
  --text-muted: #8b949e;
  --text-secondary: #8b949e;
  --accent: #238636;
  --accent-light: #2ea043;
  --accent2: #f0883e;
  --red: #f85149;
  --alert-bg: #da3633;
  --green: #3fb950;
  --yellow: #d29922;
  --warning-bg: #9e6a03;
  --purple: #bc8cff;
  --notice-bg: #238636;
  --info-bg: #388bfd;
  --font-mono: 'SF Mono','Fira Code','Consolas','Liberation Mono',monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* Navbar */
.navbar {{
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  gap: 24px;
}}
.navbar .brand {{
  font-weight: 700;
  font-size: 1.1rem;
  color: var(--accent);
}}
.navbar .nav-links a {{
  color: var(--text-muted);
  font-size: 0.85rem;
  margin-right: 16px;
}}
.navbar .nav-links a:hover {{ color: var(--text); }}

/* Container */
.container {{
  max-width: 1280px;
  margin: 0 auto;
  padding: 24px;
}}

/* Cards */
.card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 24px;
}}
.card h2 {{
  font-size: 1.25rem;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
  color: var(--accent);
}}
.card h3 {{
  font-size: 1.05rem;
  margin: 16px 0 8px;
  color: var(--accent2);
}}

/* Stat grid */
.stats {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}}
.stat-box {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 16px;
  text-align: center;
}}
.stat-box .number {{
  font-size: 1.8rem;
  font-weight: 700;
  color: var(--accent);
}}
.stat-box .label {{
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-top: 4px;
}}

/* Tables */
.table-wrap {{
  overflow-x: auto;
  margin-top: 8px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}}
thead th {{
  background: var(--bg);
  color: var(--accent);
  text-align: left;
  padding: 10px 12px;
  border-bottom: 2px solid var(--border);
  white-space: nowrap;
}}
tbody td {{
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  word-break: break-all;
  max-width: 400px;
}}
tbody tr:hover {{ background: rgba(35,134,54,0.06); }}

/* Badges */
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.badge-blue {{ background: rgba(56,139,253,0.15); color: #388bfd; }}
.badge-green {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.badge-red {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.badge-yellow {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
.badge-purple {{ background: rgba(188,140,255,0.15); color: var(--purple); }}

/* Browser header */
.browser-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}}
.browser-header h2 {{
  border: none;
  margin: 0;
  padding: 0;
}}

/* Collapsible */
details {{ margin-bottom: 12px; }}
details summary {{
  cursor: pointer;
  padding: 8px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-weight: 600;
  color: var(--text);
}}
details summary:hover {{ background: rgba(35,134,54,0.06); }}
details[open] summary {{ border-radius: 6px 6px 0 0; }}
details .detail-content {{
  border: 1px solid var(--border);
  border-top: none;
  border-radius: 0 0 6px 6px;
  padding: 12px;
}}

/* Timeline graph */
.timeline-graph-wrap {{
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    background: var(--bg);
}}
.timeline-legend {{
    margin-top: 10px;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}
.timeline-meta {{
    margin-top: 8px;
    color: var(--text-muted);
    font-size: 0.82rem;
}}

footer {{
  text-align: center;
  padding: 24px;
  color: var(--text-muted);
  font-size: 0.8rem;
  border-top: 1px solid var(--border);
  margin-top: 48px;
}}
/* ── Dashboard / stat-cards ────────────────────────── */
.dash-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}}
.stat-card {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 16px;
  text-align: center;
  transition: border-color .2s;
}}
.stat-card:hover {{ border-color: var(--accent); }}
.stat-card.c-red    {{ border-left: 4px solid var(--red); }}
.stat-card.c-yellow {{ border-left: 4px solid var(--yellow); }}
.stat-card.c-blue   {{ border-left: 4px solid var(--accent); }}
.stat-card.c-green  {{ border-left: 4px solid var(--green); }}
.sc-val {{ font-size: 2rem; font-weight: 700; color: var(--accent); margin-bottom: 4px; }}
.sc-lbl {{ font-size: 0.82rem; color: var(--text-muted); }}
/* ── Findings list ─────────────────────────────────── */
.findings {{ display: flex; flex-direction: column; gap: 9px; margin: 12px 0; }}
.finding {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
}}
.finding.f-high {{ border-left: 4px solid var(--red); }}
.finding.f-med  {{ border-left: 4px solid var(--yellow); }}
.finding.f-low  {{ border-left: 4px solid var(--accent); }}
.fbadge {{ padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: 700; white-space: nowrap; }}
.finding.f-high .fbadge {{ background: rgba(248,81,73,.2);  color: var(--red); }}
.finding.f-med  .fbadge {{ background: rgba(210,153,34,.2); color: var(--yellow); }}
.finding.f-low  .fbadge {{ background: rgba(35,134,54,.2); color: var(--accent); }}
.ftext {{ flex: 1; font-size: .88rem; }}
.flink {{ font-size: .82rem; color: var(--accent); white-space: nowrap; }}
/* ── Alerts ────────────────────────────────────────── */
.alert {{ padding: 10px 14px; border-radius: 6px; margin-bottom: 12px; font-size: .88rem; }}
.alert-info {{ background: rgba(35,134,54,.1);  border-left: 4px solid var(--accent); }}
.alert-warn {{ background: rgba(210,153,34,.1);  border-left: 4px solid var(--yellow); }}
.alert-danger {{background: rgba(248,81,73,.1);  border-left: 4px solid var(--red); }}
/* ── Chart wrappers ────────────────────────────────── */
.chart-wrap {{ position: relative; width: 100%; }}
.chart-sm  {{ height: 180px; }}
.chart-md  {{ height: 260px; }}
.chart-lg  {{ height: 360px; }}
/* ── Interactive timeline controls ─────────────────── */
.tl-controls {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  margin-bottom: 14px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
  gap: 14px;
}}
.fg {{ display: flex; flex-direction: column; gap: 5px; }}
.fg-lbl {{
  font-size: .78rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: .04em;
  margin-bottom: 3px;
}}
.fg label {{ font-size: .84rem; display: flex; align-items: center; gap: 5px; cursor: pointer; }}
.fg input[type=checkbox] {{ accent-color: var(--accent); width: 14px; height: 14px; }}
.fg select, .fg input[type=text] {{
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 5px 9px;
  border-radius: 4px;
  font-size: .84rem;
}}
.tl-btn-row {{ display: flex; gap: 8px; align-items: flex-end; }}
/* ── Buttons ───────────────────────────────────────── */
.btn {{ padding: 6px 14px; border-radius: 6px; border: none; font-weight: 600; cursor: pointer; font-size: .82rem; transition: opacity .2s; }}
.btn:hover {{ opacity: .85; }}
.btn-pri {{ background: var(--accent); color: #000; }}
.btn-sec {{ background: var(--surface); color: var(--text); border: 1px solid var(--border); }}
/* ── Domain bars ───────────────────────────────────── */
.domain-bars {{ display: flex; flex-direction: column; gap: 9px; margin-top: 12px; }}
.domain-bar-item {{ display: flex; align-items: center; gap: 10px; }}
.db-label {{
  min-width: 200px;
  max-width: 200px;
  font-size: .82rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.db-track {{
  flex: 1;
  background: rgba(35,134,54,.08);
  border-radius: 4px;
  height: 20px;
  overflow: hidden;
}}
.db-fill {{
  height: 100%;
  background: linear-gradient(90deg, rgba(46,160,67,.9), rgba(46,160,67,.6));
  border-radius: 4px;
  display: flex;
  align-items: center;
  padding-left: 7px;
  font-size: .77rem;
  color: #fff;
  font-weight: 700;
  min-width: 2px;
  transition: width 0.7s ease;
}}
.db-count {{ min-width: 36px; text-align: right; font-size: .82rem; color: var(--text-muted); }}
/* ── Risk row highlights ───────────────────────────── */
tr.risk-h > td:first-child {{ border-left: 3px solid var(--red); }}
tr.risk-m > td:first-child {{ border-left: 3px solid var(--yellow); }}
/* ── Hour heatmap ──────────────────────────────────── */
.hour-grid {{
  display: grid;
  grid-template-columns: repeat(24, 1fr);
  gap: 3px;
  margin-top: 10px;
}}
.hour-cell {{
  aspect-ratio: 1;
  border-radius: 3px;
  background: rgba(35,134,54,.1);
  position: relative;
  cursor: default;
}}
.hour-cell:hover::after {{
  content: attr(data-label);
  position: absolute;
  bottom: 110%;
  left: 50%;
  transform: translateX(-50%);
  background: #161b22;
  border: 1px solid #30363d;
  color: #c9d1d9;
  padding: 3px 7px;
  border-radius: 4px;
  font-size: .75rem;
  white-space: nowrap;
  z-index: 10;
}}
.hour-labels {{
  display: grid;
  grid-template-columns: repeat(24, 1fr);
  gap: 3px;
  margin-top: 3px;
  font-size: .7rem;
  color: var(--text-muted);
  text-align: center;
}}
/* ── KaliHeker-style branded header ────────────────── */
.header {{
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  padding: 24px 32px;
}}
.header-content {{
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 20px;
}}
.logo {{ display: flex; align-items: center; gap: 14px; }}
.logo-text {{
  font-size: 1.5rem;
  font-weight: 800;
  letter-spacing: 2px;
  color: var(--text);
}}
.logo-text span {{ color: var(--accent); }}
.version {{
  background: var(--accent);
  color: #fff;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: .75rem;
  font-weight: 700;
}}
.scan-info {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  flex: 1;
  max-width: 600px;
}}
.info-card {{
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
}}
.info-card h3 {{
  font-size: .65rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--text-muted);
  margin-bottom: 4px;
  font-weight: 600;
  border: none;
}}
.info-card p {{
  font-size: .88rem;
  color: var(--text);
  font-family: var(--font-mono);
}}
/* ── KaliHeker-style filter nav ────────────────────── */
.filter-buttons {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  flex: 1;
}}
.filter-btn {{
  background: var(--bg-tertiary);
  color: var(--text-muted);
  border: 1px solid var(--border);
  padding: 5px 14px;
  border-radius: 20px;
  font-size: .82rem;
  cursor: pointer;
  font-weight: 600;
  transition: all .2s;
  font-family: inherit;
}}
.filter-btn:hover {{ border-color: var(--accent); color: var(--text); }}
.filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.filter-btn .count {{
  background: rgba(255,255,255,.15);
  padding: 1px 6px;
  border-radius: 10px;
  font-size: .72rem;
  margin-left: 5px;
}}
.search-box {{ flex-shrink: 0; }}
.search-box input {{
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 14px;
  border-radius: 20px;
  font-size: .82rem;
  width: 220px;
  transition: border-color .2s;
  font-family: inherit;
}}
.search-box input:focus {{ outline: none; border-color: var(--accent); }}
/* ── Stats bar with dots ───────────────────────────── */
.stats-bar {{
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: center;
  margin: 16px 0;
  font-size: .84rem;
  color: var(--text-muted);
}}
.stat-dot {{
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
  margin-right: 4px;
}}
.stat-dot.critical {{ background: var(--red); }}
.stat-dot.high {{ background: #f0883e; }}
.stat-dot.medium {{ background: var(--yellow); }}
.stat-dot.low {{ background: var(--green); }}
.stat-dot.info {{ background: #388bfd; }}
/* ── Summary grid ──────────────────────────────────── */
.summary-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 14px;
  margin: 16px 0;
}}
.summary-card {{
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 14px;
  text-align: center;
  transition: border-color .2s;
}}
.summary-card:hover {{ border-color: var(--accent); }}
.summary-card .number {{
  font-size: 2rem;
  font-weight: 800;
  font-family: var(--font-mono);
  margin-bottom: 4px;
}}
.summary-card .number.c-green {{ color: var(--green); }}
.summary-card .number.c-red {{ color: var(--red); }}
.summary-card .number.c-yellow {{ color: var(--yellow); }}
.summary-card .number.c-blue {{ color: #388bfd; }}
.summary-card .number.c-accent {{ color: var(--accent); }}
.summary-card .label {{
  font-size: .75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: .06em;
}}
/* ── Finding cards (KaliHeker style) ───────────────── */
.finding-card {{
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 14px;
  overflow: hidden;
}}
.finding-card.severity-critical {{ border-left: 4px solid var(--red); }}
.finding-card.severity-high {{ border-left: 4px solid #f0883e; }}
.finding-card.severity-medium {{ border-left: 4px solid var(--yellow); }}
.finding-card.severity-low {{ border-left: 4px solid var(--green); }}
.finding-card.severity-info {{ border-left: 4px solid #388bfd; }}
.finding-header {{
  background: var(--bg-tertiary);
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}}
.severity-badge {{
  padding: 3px 10px;
  border-radius: 4px;
  font-size: .72rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: .05em;
}}
.severity-badge.critical {{ background: rgba(248,81,73,.2); color: var(--red); }}
.severity-badge.high {{ background: rgba(240,136,62,.2); color: #f0883e; }}
.severity-badge.medium {{ background: rgba(210,153,34,.2); color: var(--yellow); }}
.severity-badge.low {{ background: rgba(63,185,80,.2); color: var(--green); }}
.severity-badge.info {{ background: rgba(56,139,253,.2); color: #388bfd; }}
.finding-title {{
  font-family: var(--font-mono);
  font-size: .9rem;
  font-weight: 600;
  color: var(--text);
}}
.finding-body {{ padding: 14px 16px; }}
.finding-description {{ font-size: .88rem; line-height: 1.6; color: var(--text-muted); margin-bottom: 10px; }}
.evidence-box {{
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: .82rem;
  color: var(--text);
  margin: 8px 0;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}}
.metadata-tags {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}}
.meta-tag {{
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: .75rem;
  color: var(--text-muted);
}}
.meta-tag a {{ color: var(--accent); }}
/* ── Category headers (collapsible) ────────────────── */
.category-header {{
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 8px;
  padding: 14px 18px;
  margin: 20px 0 12px;
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  transition: border-color .2s;
}}
.category-header:hover {{ border-color: var(--accent-light); }}
.category-header .cat-dot {{
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--accent);
  flex-shrink: 0;
}}
.category-header h3 {{
  flex: 1;
  font-size: 1rem;
  color: var(--text);
  border: none;
  margin: 0;
  padding: 0;
}}
.category-header .cat-count {{
  background: var(--accent);
  color: #fff;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: .75rem;
  font-weight: 700;
}}
/* ── Vertical timeline (KaliHeker style) ───────────── */
.tl-list {{
  position: relative;
  margin: 16px 0;
  padding-left: 28px;
  border-left: 2px solid var(--border);
}}
.tl-event {{
  position: relative;
  padding: 8px 0 16px 16px;
}}
.tl-dot {{
  position: absolute;
  left: -35px;
  top: 10px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--accent);
  border: 2px solid var(--bg);
}}
.tl-dot.critical {{ background: var(--red); }}
.tl-dot.high {{ background: #f0883e; }}
.tl-dot.medium {{ background: var(--yellow); }}
.tl-dot.low {{ background: var(--green); }}
.tl-dot.info {{ background: #388bfd; }}
.tl-time {{
  font-family: var(--font-mono);
  font-size: .78rem;
  color: var(--text-muted);
  margin-bottom: 2px;
}}
.tl-content {{ font-size: .88rem; }}
.tl-evtitle {{ color: var(--text); font-weight: 600; }}
.tl-cat {{
  display: inline-block;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  padding: 1px 7px;
  border-radius: 4px;
  font-size: .72rem;
  color: var(--text-muted);
  margin-left: 6px;
}}
/* ── Quick reference box ───────────────────────────── */
.quick-ref {{
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  margin: 16px 0;
}}
.quick-ref h3 {{
  color: var(--accent);
  font-size: .9rem;
  margin-bottom: 10px;
  border: none;
  padding: 0;
}}
.quick-ref-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px;
  font-size: .84rem;
}}
.quick-ref-grid span {{ color: var(--text-muted); }}
.quick-ref-grid strong {{ color: var(--text); }}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
"#
    );
}

fn write_navbar(h: &mut String, report: &ForensicReport) {
    let s = &report.summary;
    let total_artifacts: usize = s.total_history_entries as usize
        + s.total_downloads as usize
        + s.total_cookies as usize
        + s.total_logins as usize;

    let _ = write!(
        h,
        r##"<header class="header">
  <div class="header-content">
    <div class="logo">
      <div class="logo-text">BROWSER<span>FORENSICS</span></div>
      <span class="version">v{ver}</span>
    </div>
    <div class="scan-info">
      <div class="info-card"><h3>Report Generated</h3><p>{date}</p></div>
      <div class="info-card"><h3>Tool Version</h3><p>v{ver}</p></div>
      <div class="info-card"><h3>Browsers Found</h3><p>{browsers}</p></div>
      <div class="info-card"><h3>Total Artifacts</h3><p>{total}</p></div>
    </div>
  </div>
</header>
<nav class="navbar" id="mainNav">
  <div class="filter-buttons">
    <button class="filter-btn active" onclick="scrollToSection('dashboard')">Dashboard</button>
    <button class="filter-btn" onclick="scrollToSection('summary')">Summary</button>
    <button class="filter-btn" onclick="scrollToSection('artifacts-0')">Artifacts</button>
    <button class="filter-btn" onclick="scrollToSection('domain-analysis')">URLs</button>
    <button class="filter-btn" onclick="scrollToSection('timeline')">Timeline</button>
    <button class="filter-btn" onclick="scrollToSection('behavioral')">Behavioral</button>
    <button class="filter-btn" onclick="scrollToSection('privacy')">Privacy</button>
    <button class="filter-btn" onclick="scrollToSection('system')">System</button>
  </div>
  <div class="search-box">
    <input type="text" id="globalSearch" placeholder="Search report..." onkeyup="searchReport(this.value)">
  </div>
</nav>
<div class="container">
"##,
        ver = esc(&report.tool_version),
        date = esc(&report.report_generated),
        browsers = s.total_browsers,
        total = total_artifacts,
    );
}

fn write_case_info(h: &mut String, report: &ForensicReport) {
    let _ = write!(h, r#"<div class="card" id="case-info"><h2>Case Information</h2>"#);
    if let Some(ci) = &report.case_info {
        let _ = write!(
            h,
            r#"<div class="scan-info" style="max-width:100%;">
  <div class="info-card"><h3>Case ID</h3><p>{}</p></div>
  <div class="info-card"><h3>Case Name</h3><p>{}</p></div>
  <div class="info-card"><h3>Examiner</h3><p>{}</p></div>
  <div class="info-card"><h3>Date</h3><p>{}</p></div>
  <div class="info-card"><h3>Computer</h3><p>{}</p></div>
  <div class="info-card"><h3>OS Version</h3><p>{}</p></div>
  <div class="info-card"><h3>Timezone</h3><p>{}</p></div>
</div>"#,
            opt(&ci.case_id),
            opt(&ci.case_name),
            opt(&ci.examiner),
            opt(&ci.date),
            opt(&ci.computer_name),
            opt(&ci.os_version),
            opt(&ci.system_timezone),
        );
        if ci.notes.is_some() {
            let _ = write!(
                h,
                r#"<div class="evidence-box" style="margin-top:12px;"><strong>Notes:</strong> {}</div>"#,
                opt(&ci.notes),
            );
        }
    } else {
        let _ = write!(h, "<p>No case information provided.</p>");
    }
    let _ = write!(
        h,
        r#"<div class="stats-bar"><span class="stat-dot info"></span> Report generated: <strong>{}</strong> &nbsp;|&nbsp; Tool v{}</div></div>"#,
        esc(&report.report_generated),
        esc(&report.tool_version),
    );
}

fn write_summary(h: &mut String, report: &ForensicReport) {
    let s = &report.summary;
    let _ = write!(
        h,
        r#"<div class="card" id="summary"><h2>Summary</h2>
<div class="summary-grid">
  <div class="summary-card"><div class="number c-accent">{}</div><div class="label">Browsers</div></div>
  <div class="summary-card"><div class="number c-blue">{}</div><div class="label">History</div></div>
  <div class="summary-card"><div class="number c-green">{}</div><div class="label">Downloads</div></div>
  <div class="summary-card"><div class="number c-yellow">{}</div><div class="label">Cookies</div></div>
  <div class="summary-card"><div class="number c-red">{}</div><div class="label">Logins</div></div>
  <div class="summary-card"><div class="number c-blue">{}</div><div class="label">Autofill</div></div>
  <div class="summary-card"><div class="number c-accent">{}</div><div class="label">Bookmarks</div></div>
  <div class="summary-card"><div class="number c-blue">{}</div><div class="label">Extensions</div></div>
  <div class="summary-card"><div class="number c-green">{}</div><div class="label">Cache</div></div>
  <div class="summary-card"><div class="number c-yellow">{}</div><div class="label">Sessions</div></div>
</div>
<div class="stats-bar">
  <span><span class="stat-dot" style="background:var(--accent)"></span> Browsers: <strong>{blist}</strong></span>
</div>
"#,
        s.total_browsers,
        s.total_history_entries,
        s.total_downloads,
        s.total_cookies,
        s.total_logins,
        s.total_autofill,
        s.total_bookmarks,
        s.total_extensions,
        s.total_cache_entries,
        s.total_sessions,
        blist = s.browsers_found.join(", "),
    );

    // Indicators
    let mut badges = Vec::new();
    if s.has_brave_wallet {
        badges.push(r#"<span class="meta-tag">Brave Wallet</span>"#);
    }
    if s.has_brave_tor {
        badges.push(r#"<span class="meta-tag" style="border-color:var(--red);color:var(--red);">Brave Tor</span>"#);
    }
    if s.has_dns_cache {
        badges.push(r#"<span class="meta-tag">DNS Cache</span>"#);
    }
    if s.has_prefetch {
        badges.push(r#"<span class="meta-tag">Prefetch</span>"#);
    }
    if s.has_jump_lists {
        badges.push(r#"<span class="meta-tag">Jump Lists</span>"#);
    }
    if s.has_zone_identifiers {
        badges.push(r#"<span class="meta-tag" style="border-color:var(--red);color:var(--red);">Zone.Identifier</span>"#);
    }
    if s.total_wal_recovered > 0 {
        badges.push(r#"<span class="meta-tag" style="border-color:var(--yellow);color:var(--yellow);">WAL Recovery</span>"#);
    }
    if s.total_cache_extracted > 0 {
        badges.push(r#"<span class="meta-tag">Cache Extracted</span>"#);
    }
    if s.total_privacy_indicators > 0 {
        badges.push(r#"<span class="meta-tag" style="border-color:var(--red);color:var(--red);">Privacy Indicators</span>"#);
    }
    if s.total_timeline_events > 0 {
        let _ = write!(
            h,
            r#"<div class="stats-bar"><span class="stat-dot info"></span> Timeline: <strong>{} events</strong></div>"#,
            s.total_timeline_events
        );
    }
    if !badges.is_empty() {
        let _ = write!(h, "<div class=\"metadata-tags\" style=\"margin-top:8px;\">{}</div>", badges.join(" "));
    }
    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// Executive dashboard
// ---------------------------------------------------------------------------

fn write_dashboard(h: &mut String, report: &ForensicReport) {
    let s = &report.summary;

    // Compute analysis period from timeline
    let (first_ts, last_ts) = if !report.timeline.is_empty() {
        let f = report.timeline.first().unwrap().timestamp.get(..10).unwrap_or("—");
        let l = report.timeline.last().unwrap().timestamp.get(..10).unwrap_or("—");
        (f.to_string(), l.to_string())
    } else {
        ("—".into(), "—".into())
    };

    let _ = write!(
        h,
        r#"<div class="card" id="dashboard"><h2>Investigation Dashboard</h2>
<div class="summary-grid">
  <div class="summary-card"><div class="number c-accent">{}</div><div class="label">Timeline Events</div></div>
  <div class="summary-card"><div class="number c-blue">{}</div><div class="label">History Entries</div></div>
  <div class="summary-card"><div class="number c-green">{}</div><div class="label">Downloads</div></div>
  <div class="summary-card"><div class="number c-red">{}</div><div class="label">Privacy Indicators</div></div>
  <div class="summary-card"><div class="number c-yellow">{}</div><div class="label">Sessions Recovered</div></div>
  <div class="summary-card"><div class="number c-accent">{}</div><div class="label">Browsers Analysed</div></div>
</div>
<div class="stats-bar">
  <span><span class="stat-dot info"></span> Analysis period: <strong>{}</strong> → <strong>{}</strong></span>
</div>
"#,
        s.total_timeline_events,
        s.total_history_entries,
        s.total_downloads,
        s.total_privacy_indicators,
        s.total_sessions,
        s.total_browsers,
        first_ts,
        last_ts,
    );

    // Key findings — (severity_cls, badge_cls, badge_text, title, description, href)
    let mut findings: Vec<(&str, &str, &str, String, String)> = Vec::new();

    if s.total_privacy_indicators > 0 {
        findings.push(("severity-critical", "critical", "CRITICAL", "Privacy / Tor / Incognito indicators detected".into(), "#privacy".into()));
    }
    if s.total_downloads > 0 {
        findings.push(("severity-medium", "medium", "MEDIUM", "Downloaded files present — verify sources and hashes".into(), "#artifacts-0".into()));
    }
    if s.total_wal_recovered > 0 {
        findings.push(("severity-medium", "medium", "MEDIUM", "Deleted SQLite rows recovered from WAL/journal files".into(), "#artifacts-0".into()));
    }
    if s.total_sessions > 0 {
        findings.push(("severity-low", "low", "LOW", "Browser session data recovered — tab/URL details available".into(), "#timeline".into()));
    }
    if s.total_browsers > 1 {
        findings.push(("severity-info", "info", "INFO", format!("{} browsers found — compare activity across profiles", s.total_browsers), "#summary".into()));
    }
    if findings.is_empty() {
        findings.push(("severity-info", "info", "INFO", "No high-risk indicators automatically detected — manual review recommended".into(), "#artifacts-0".into()));
    }

    let _ = write!(h, r#"<h3 style="margin-bottom:10px;color:var(--accent);">Key Findings</h3>"#);
    for (card_cls, badge_cls, badge_text, title, href) in &findings {
        let _ = write!(
            h,
            r#"<div class="finding-card {}">
  <div class="finding-header">
    <span class="severity-badge {}">{}</span>
    <span class="finding-title">{}</span>
  </div>
  <div class="finding-body">
    <div class="finding-description">{}</div>
    <div class="metadata-tags"><a class="meta-tag" href="{}">View Details →</a></div>
  </div>
</div>"#,
            card_cls, badge_cls, badge_text, title, title, href
        );
    }

    // Activity overview chart placeholder (filled by JS)
    let _ = write!(
        h,
        r#"<h3 style="margin:16px 0 10px;">Activity by Event Type</h3>
<div class="chart-wrap chart-sm"><canvas id="dashTypeChart"></canvas></div>
</div>"#
    );
}

// ---------------------------------------------------------------------------
// URL / Domain analysis (canvas driven by inline JS data)
// ---------------------------------------------------------------------------

fn write_domain_analysis(h: &mut String, report: &ForensicReport) {
    let total_history: usize = report.artifacts.iter().map(|c| c.history.len()).sum();
    if total_history == 0 {
        return;
    }

    let _ = write!(
        h,
        r#"<div class="card" id="domain-analysis"><h2>URL &amp; Domain Analysis</h2>"#
    );

    // Top domains — computed by JS, injected into #domainBarsContainer
    let _ = write!(
        h,
        r#"<details open><summary>Top Visited Domains (computed from {total_history} history entries)</summary>
<div class="detail-content">
<div class="domain-bars" id="domainBarsContainer">
  <p style="color:var(--text-muted)">Loading…</p>
</div>
</div></details>"#
    );

    // Search queries — table body filled by JS
    let _ = write!(
        h,
        r#"<details open><summary>Search Queries Extracted from URLs (<span id="sqCount">…</span>)</summary>
<div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Query</th><th>Engine</th><th>Timestamp</th><th>Browser</th></tr></thead>
<tbody id="searchQueriesBody"><tr><td colspan="5" style="text-align:center;color:var(--text-muted)">Loading…</td></tr></tbody>
</table></div></div></details>"#
    );

    // Top domains chart
    let _ = write!(
        h,
        r#"<details><summary>Domain Distribution Chart</summary>
<div class="detail-content">
<div class="chart-wrap chart-md"><canvas id="domainChart"></canvas></div>
</div></details>"#
    );

    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// Behavioral analysis
// ---------------------------------------------------------------------------

fn write_behavioral_analysis(h: &mut String, report: &ForensicReport) {
    if report.timeline.is_empty() {
        return;
    }

    let _ = write!(
        h,
        r#"<div class="card" id="behavioral"><h2>Behavioral Analysis &amp; Usage Patterns</h2>"#
    );

    // Hourly activity chart
    let _ = write!(
        h,
        r#"<details open><summary>Hourly Activity Distribution</summary>
<div class="detail-content">
<div class="chart-wrap chart-sm"><canvas id="hourlyChart"></canvas></div>
</div></details>"#
    );

    // Browser activity chart
    let _ = write!(
        h,
        r#"<details open><summary>Activity by Browser</summary>
<div class="detail-content">
<div class="chart-wrap chart-sm"><canvas id="browserActivityChart"></canvas></div>
</div></details>"#
    );

    // Browsing sessions table (events grouped into sessions by >30-min gaps)
    let _ = write!(
        h,
        r#"<details><summary>Inferred Browsing Sessions (events grouped by 30-min idle gaps)</summary>
<div class="detail-content">
<div class="table-wrap"><table>
<thead><tr><th>#</th><th>Start</th><th>End</th><th>Events</th><th>Browsers</th></tr></thead>
<tbody id="sessionsBody"><tr><td colspan="5" style="text-align:center;color:var(--text-muted)">Loading…</td></tr></tbody>
</table></div></div></details>"#
    );

    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// Inline scripts — embeds JSON data + initialises Chart.js charts
// ---------------------------------------------------------------------------

fn write_inline_scripts(h: &mut String, report: &ForensicReport) {
    // Serialize timeline events for Chart.js
    let tl_json: String = {
        let parts: Vec<String> = report
            .timeline
            .iter()
            .map(|e| {
                format!(
                    r#"{{"ts":"{ts}","type":"{ty}","browser":"{br}","profile":"{pr}","url":"{ur}","title":"{ti}"}}"#,
                    ts = js_esc(&e.timestamp),
                    ty = js_esc(&e.event_type),
                    br = js_esc(&e.source_browser),
                    pr = js_esc(e.profile.as_deref().unwrap_or("")),
                    ur = js_esc(e.url.as_deref().unwrap_or("")),
                    ti = js_esc(
                        e.title
                            .as_deref()
                            .or(e.details.as_deref())
                            .unwrap_or("")
                    ),
                )
            })
            .collect();
        format!("[{}]", parts.join(","))
    };

    // Serialize history entries for domain analysis
    let hist_json: String = {
        let parts: Vec<String> = report
            .artifacts
            .iter()
            .flat_map(|coll| {
                let br = coll.browser.to_string();
                coll.history.iter().map(move |h| {
                    format!(
                        r#"{{"url":"{ur}","title":"{ti}","ts":"{ts}","browser":"{br}","vc":{vc}}}"#,
                        ur = js_esc(&h.url),
                        ti = js_esc(h.title.as_deref().unwrap_or("")),
                        ts = js_esc(h.last_visit_time.as_deref().unwrap_or("")),
                        br = js_esc(&br),
                        vc = h.visit_count.unwrap_or(0),
                    )
                })
            })
            .collect();
        format!("[{}]", parts.join(","))
    };

    let _ = write!(
        h,
        r##"<script>
/* ─── Embedded forensic data ──────────────────────────── */
const TIMELINE_EVENTS = {tl};
const HISTORY_ENTRIES = {hi};

/* ─── Helpers ──────────────────────────────────────────── */
function escHtml(s) {{
  if (!s) return '—';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
function tsMs(s) {{ return s ? new Date(s).getTime() : 0; }}
function eventY(type) {{
  if (type==='visit') return 0;
  if (type.includes('download')) return 1;
  if (type.includes('autofill')||type.includes('form')) return 2;
  if (type.includes('session')||type.includes('tab')) return 3;
  if (type.includes('bookmark')) return 4;
  if (type.includes('login')||type.includes('credential')) return 5;
  return 6;
}}
const YLABELS = ['Visits','Downloads','Autofill','Sessions','Bookmarks','Logins','Other'];
const BROWSER_COLORS = {{
  'Microsoft Edge':'#0078D4','Brave Browser':'#FB542B',
  'Firefox':'#FF7139','Chrome':'#4285F4','Unknown':'#8b949e'
}};
function browserColor(br) {{ return BROWSER_COLORS[br] || '#8b949e'; }}

/* ─── Chart: Dashboard event-type breakdown ────────────── */
function initDashChart() {{
  const cvs = document.getElementById('dashTypeChart');
  if (!cvs || !TIMELINE_EVENTS.length) return;
  const counts = {{}};
  TIMELINE_EVENTS.forEach(e => {{ counts[e.type] = (counts[e.type]||0)+1; }});
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const palette = ['#238636','#3fb950','#d29922','#f85149','#bc8cff','#f0883e','#58d5e5'];
  new Chart(cvs, {{
    type: 'bar',
    data: {{
      labels: sorted.map(x=>x[0]),
      datasets: [{{ data: sorted.map(x=>x[1]), backgroundColor: sorted.map((_,i)=>palette[i%palette.length]), borderRadius: 4, borderSkipped: false }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      scales: {{
        x: {{ ticks: {{ color:'#8b949e' }}, grid: {{ color:'rgba(48,54,61,0.5)' }}, beginAtZero:true }},
        y: {{ ticks: {{ color:'#c9d1d9', font:{{size:11}} }}, grid: {{ display:false }} }}
      }},
      plugins: {{ legend:{{display:false}}, tooltip:{{ backgroundColor:'#161b22', titleColor:'#238636', bodyColor:'#c9d1d9', borderColor:'#30363d', borderWidth:1 }} }}
    }}
  }});
}}

/* ─── Chart: Interactive timeline (scatter / swim-lane) ── */
function buildTimelineDatasets(events) {{
  const byBrowser = {{}};
  events.forEach(e => {{
    if (!byBrowser[e.browser]) byBrowser[e.browser] = [];
    byBrowser[e.browser].push({{ x: tsMs(e.ts), y: eventY(e.type), meta: e }});
  }});
  return Object.entries(byBrowser).map(([br,pts]) => ({{
    label: br,
    data: pts,
    backgroundColor: browserColor(br),
    borderColor: browserColor(br),
    pointRadius: 4,
    pointHoverRadius: 8
  }}));
}}

let tlChart;
function initTimelineChart() {{
  const cvs = document.getElementById('tlChart');
  if (!cvs || !TIMELINE_EVENTS.length) return;
  const minTs = Math.min(...TIMELINE_EVENTS.map(e=>tsMs(e.ts)));
  const maxTs = Math.max(...TIMELINE_EVENTS.map(e=>tsMs(e.ts)));
  tlChart = new Chart(cvs, {{
    type: 'scatter',
    data: {{ datasets: buildTimelineDatasets(TIMELINE_EVENTS) }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      scales: {{
        x: {{
          type: 'linear', min: minTs, max: maxTs,
          ticks: {{
            color:'#8b949e',
            maxTicksLimit: 10,
            callback: v => {{ const d=new Date(v); return d.toLocaleDateString('en-GB',{{day:'2-digit',month:'short',year:'2-digit'}}); }}
          }},
          grid: {{ color:'rgba(48,54,61,0.5)' }}
        }},
        y: {{
          type: 'linear', min:-0.5, max:6.5,
          ticks: {{
            color:'#c9d1d9',
            stepSize: 1,
            callback: v => YLABELS[Math.round(v)] || ''
          }},
          grid: {{ color:'rgba(48,54,61,0.4)' }}
        }}
      }},
      plugins: {{
        legend: {{ display:true, position:'top', labels:{{ color:'#c9d1d9', usePointStyle:true, boxWidth:10 }} }},
        tooltip: {{
          backgroundColor:'#161b22', titleColor:'#238636', bodyColor:'#c9d1d9',
          borderColor:'#30363d', borderWidth:1,
          callbacks: {{
            title: items => new Date(items[0].parsed.x).toUTCString(),
            label: item => {{
              const m=item.raw.meta;
              const lines=[`[${{m.browser}}] ${{m.type}}`];
              if (m.url) lines.push((m.url.length>70 ? m.url.slice(0,70)+'…' : m.url));
              if (m.title) lines.push((m.title.length>60 ? m.title.slice(0,60)+'…' : m.title));
              return lines;
            }}
          }}
        }}
      }}
    }}
  }});
}}

function filterTimeline() {{
  if (!tlChart) return;
  const typeChecks = Array.from(document.querySelectorAll('.tl-type-chk')).filter(c=>c.checked).map(c=>c.value);
  const brChecks   = Array.from(document.querySelectorAll('.tl-br-chk')).filter(c=>c.checked).map(c=>c.value);
  const search     = (document.getElementById('tlSearch')||{{}}).value?.toLowerCase()||'';
  const filtered   = TIMELINE_EVENTS.filter(e => {{
    const typeOk = typeChecks.length===0 || typeChecks.some(t=>e.type.includes(t));
    const brOk   = brChecks.length===0   || brChecks.some(b=>e.browser===b);
    const srOk   = !search || e.url.toLowerCase().includes(search) || e.title.toLowerCase().includes(search);
    return typeOk && brOk && srOk;
  }});
  tlChart.data.datasets = buildTimelineDatasets(filtered);
  tlChart.update();
  document.getElementById('tlCount').textContent = `${{filtered.length}} / ${{TIMELINE_EVENTS.length}} events`;
}}

function resetTimeline() {{
  document.querySelectorAll('.tl-type-chk,.tl-br-chk').forEach(c=>{{c.checked=true;}});
  const s=document.getElementById('tlSearch'); if(s) s.value='';
  filterTimeline();
}}

/* ─── Chart: Hourly activity ─────────────────────────── */
function initHourlyChart() {{
  const cvs = document.getElementById('hourlyChart');
  if (!cvs || !TIMELINE_EVENTS.length) return;
  const hours = new Array(24).fill(0);
  TIMELINE_EVENTS.forEach(e => {{ const d=new Date(e.ts); if(!isNaN(d)) hours[d.getUTCHours()]++; }});
  new Chart(cvs, {{
    type: 'bar',
    data: {{
      labels: Array.from({{length:24}},(_,i)=>`${{String(i).padStart(2,'0')}}:00`),
      datasets: [{{ label:'Events', data:hours, backgroundColor:'rgba(35,134,54,0.55)', borderColor:'rgba(46,160,67,0.9)', borderWidth:1, borderRadius:3 }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      scales: {{
        x: {{ ticks:{{ color:'#8b949e', font:{{size:10}} }}, grid:{{ color:'rgba(48,54,61,0.5)' }} }},
        y: {{ ticks:{{ color:'#8b949e' }}, grid:{{ color:'rgba(48,54,61,0.5)' }}, beginAtZero:true }}
      }},
      plugins: {{ legend:{{display:false}}, tooltip:{{ backgroundColor:'#161b22',titleColor:'#238636',bodyColor:'#c9d1d9',borderColor:'#30363d',borderWidth:1,callbacks:{{title:i=>`Hour ${{i[0].label}}: ${{i[0].parsed.y}} events`}} }} }}
    }}
  }});
}}

/* ─── Chart: Browser activity breakdown ─────────────── */
function initBrowserActivityChart() {{
  const cvs = document.getElementById('browserActivityChart');
  if (!cvs || !TIMELINE_EVENTS.length) return;
  const counts = {{}};
  TIMELINE_EVENTS.forEach(e => {{ counts[e.browser]=(counts[e.browser]||0)+1; }});
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  new Chart(cvs, {{
    type: 'doughnut',
    data: {{
      labels: sorted.map(x=>x[0]),
      datasets: [{{ data:sorted.map(x=>x[1]), backgroundColor:sorted.map(x=>browserColor(x[0])), borderColor:'#161b22', borderWidth:2 }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{
        legend: {{ position:'right', labels:{{ color:'#c9d1d9', usePointStyle:true }} }},
        tooltip: {{ backgroundColor:'#161b22',titleColor:'#238636',bodyColor:'#c9d1d9',borderColor:'#30363d',borderWidth:1 }}
      }}
    }}
  }});
}}

/* ─── Domain analysis (bars + search queries) ─────────── */
function initDomainAnalysis() {{
  if (!HISTORY_ENTRIES.length) return;
  // Count by domain
  const dc = {{}};
  HISTORY_ENTRIES.forEach(h => {{
    try {{
      const dom = new URL(h.url).hostname.replace(/^www\./,'');
      dc[dom] = (dc[dom]||0) + (h.vc||1);
    }} catch(e) {{}}
  }});
  const sorted = Object.entries(dc).sort((a,b)=>b[1]-a[1]).slice(0,20);
  const container = document.getElementById('domainBarsContainer');
  if (container && sorted.length>0) {{
    const maxV = sorted[0][1];
    container.innerHTML = sorted.map(([d,c]) =>
      `<div class="domain-bar-item">
        <div class="db-label" title="${{escHtml(d)}}">${{escHtml(d)}}</div>
        <div class="db-track"><div class="db-fill" style="width:${{(c/maxV*100).toFixed(1)}}%">${{c>3?c:''}}</div></div>
        <div class="db-count">${{c}}</div>
      </div>`
    ).join('');
  }}
  // Domain chart
  const dCvs = document.getElementById('domainChart');
  if (dCvs && sorted.length>0) {{
    const palette=['#238636','#3fb950','#d29922','#f85149','#bc8cff','#f0883e','#58d5e5','#6b7280'];
    new Chart(dCvs, {{
      type: 'bar',
      data: {{
        labels: sorted.slice(0,15).map(x=>x[0]),
        datasets: [{{ data:sorted.slice(0,15).map(x=>x[1]), backgroundColor:sorted.slice(0,15).map((_,i)=>palette[i%palette.length]), borderRadius:4, borderSkipped:false }}]
      }},
      options: {{
        indexAxis:'y', responsive:true, maintainAspectRatio:false,
        scales:{{
          x:{{ ticks:{{color:'#8b949e'}}, grid:{{color:'rgba(48,54,61,0.5)'}}, beginAtZero:true }},
          y:{{ ticks:{{color:'#c9d1d9',font:{{size:11}}}}, grid:{{display:false}} }}
        }},
        plugins:{{ legend:{{display:false}}, tooltip:{{ backgroundColor:'#161b22',titleColor:'#238636',bodyColor:'#c9d1d9',borderColor:'#30363d',borderWidth:1 }} }}
      }}
    }});
  }}
  // Search queries
  const SE = {{'www.google.com':'q','www.bing.com':'q','search.brave.com':'q','duckduckgo.com':'q','search.yahoo.com':'p','www.google.co.uk':'q'}};
  const queries=[];
  HISTORY_ENTRIES.forEach(h=>{{
    try {{
      const u=new URL(h.url);
      const qp=SE[u.hostname];
      if (qp) {{ const q=u.searchParams.get(qp); if(q&&q.trim().length>1) queries.push({{query:q.trim(),engine:u.hostname,ts:h.ts,browser:h.browser}}); }}
    }} catch(e) {{}}
  }});
  const sqCnt = document.getElementById('sqCount');
  if (sqCnt) sqCnt.textContent = queries.length;
  const sqBody = document.getElementById('searchQueriesBody');
  if (sqBody) {{
    if (!queries.length) {{
      sqBody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No search queries found</td></tr>';
    }} else {{
      sqBody.innerHTML = queries.map((q,i)=>`<tr><td>${{i+1}}</td><td>${{escHtml(q.query)}}</td><td>${{escHtml(q.engine)}}</td><td>${{escHtml(q.ts)}}</td><td>${{escHtml(q.browser)}}</td></tr>`).join('');
    }}
  }}
}}

/* ─── Inferred browsing sessions ────────────────────── */
function inferSessions() {{
  if (!TIMELINE_EVENTS.length) return;
  const GAP_MS = 30*60*1000; // 30 min
  const events = [...TIMELINE_EVENTS].sort((a,b)=>tsMs(a.ts)-tsMs(b.ts));
  const sessions=[];
  let cur=null;
  events.forEach(e => {{
    const t=tsMs(e.ts);
    if (!cur || t-cur.lastTs>GAP_MS) {{
      if(cur) sessions.push(cur);
      cur={{start:e.ts,end:e.ts,lastTs:t,count:1,browsers:new Set([e.browser])}};
    }} else {{
      cur.end=e.ts; cur.lastTs=t; cur.count++; cur.browsers.add(e.browser);
    }}
  }});
  if(cur) sessions.push(cur);
  const body=document.getElementById('sessionsBody');
  if(!body) return;
  if(!sessions.length) {{
    body.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No sessions</td></tr>';
    return;
  }}
  body.innerHTML=sessions.map((s,i)=>`<tr>
    <td>${{i+1}}</td>
    <td>${{escHtml(s.start)}}</td>
    <td>${{escHtml(s.end)}}</td>
    <td>${{s.count}}</td>
    <td>${{escHtml([...s.browsers].join(', '))}}</td>
  </tr>`).join('');
}}

/* ─── KaliHeker-style navigation & search ───────────── */
function scrollToSection(id) {{
  const el = document.getElementById(id);
  if (el) {{
    el.scrollIntoView({{ behavior:'smooth', block:'start' }});
    // Update active filter button
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
  }}
}}
function searchReport(query) {{
  const q = query.toLowerCase().trim();
  document.querySelectorAll('.card').forEach(card => {{
    if (!q) {{ card.style.display = ''; return; }}
    const text = card.textContent.toLowerCase();
    card.style.display = text.includes(q) ? '' : 'none';
  }});
}}

/* ─── Init all charts on load ───────────────────────── */
document.addEventListener('DOMContentLoaded', () => {{
  initDashChart();
  initTimelineChart();
  initHourlyChart();
  initBrowserActivityChart();
  initDomainAnalysis();
  inferSessions();
  // Attach filter listeners
  document.querySelectorAll('.tl-type-chk,.tl-br-chk').forEach(c=>c.addEventListener('change', filterTimeline));
  const s=document.getElementById('tlSearch'); if(s) s.addEventListener('input', filterTimeline);
  // Highlight active nav section on scroll
  const sections = ['dashboard','summary','artifacts-0','domain-analysis','timeline','behavioral','privacy','system'];
  const observer = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
      if (e.isIntersecting) {{
        const id = e.target.id;
        document.querySelectorAll('.filter-btn').forEach(b => {{
          const onclick = b.getAttribute('onclick') || '';
          b.classList.toggle('active', onclick.includes("'"+id+"'"));
        }});
      }}
    }});
  }}, {{ rootMargin:'-100px 0px -60% 0px' }});
  sections.forEach(id => {{ const el=document.getElementById(id); if(el) observer.observe(el); }});
}});
</script>
"##,
        tl = tl_json,
        hi = hist_json,
    );
}

fn js_esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
        .replace('\r', "")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}

// ---------------------------------------------------------------------------
// Per-browser artifact collection
// ---------------------------------------------------------------------------

fn write_artifact_collection(h: &mut String, coll: &ArtifactCollection, idx: usize) {
    let artifact_count = coll.history.len() + coll.downloads.len() + coll.cookies.len()
        + coll.logins.len() + coll.autofill.len() + coll.bookmarks.len()
        + coll.extensions.len() + coll.cache.len() + coll.sessions.len();

    let _ = write!(
        h,
        r#"<div class="card" id="artifacts-{}">
<div class="category-header" style="margin-top:0;">
  <span class="cat-dot"></span>
  <h3>{}</h3>
  <span class="cat-count">{} artifacts</span>
</div>"#,
        idx,
        esc(&coll.browser.to_string()),
        artifact_count,
    );

    if let Some(pn) = &coll.profile_name {
        let _ = write!(
            h,
            r#"<div class="stats-bar" style="margin-top:8px;"><span class="stat-dot info"></span> Profile: <strong>{}</strong></div>"#,
            esc(pn)
        );
    }
    if let Some(pp) = &coll.profile_path {
        let _ = write!(
            h,
            r#"<div class="evidence-box" style="margin:8px 0;font-size:.8rem;">{}</div>"#,
            esc(pp)
        );
    }

    // Each artifact type as a collapsible detail
    if !coll.history.is_empty() {
        write_history_table(h, &coll.history);
    }
    if !coll.downloads.is_empty() {
        write_downloads_table(h, &coll.downloads);
    }
    if !coll.cookies.is_empty() {
        write_cookies_table(h, &coll.cookies);
    }
    if !coll.logins.is_empty() {
        write_logins_table(h, &coll.logins);
    }
    if !coll.autofill.is_empty() {
        write_autofill_table(h, &coll.autofill, "Autofill");
    }
    if !coll.form_history.is_empty() {
        write_autofill_table(h, &coll.form_history, "Form History (Firefox)");
    }
    if !coll.bookmarks.is_empty() {
        write_bookmarks_table(h, &coll.bookmarks);
    }
    if !coll.extensions.is_empty() {
        write_extensions_table(h, &coll.extensions);
    }
    if !coll.cache.is_empty() {
        write_cache_table(h, &coll.cache);
    }
    if !coll.sessions.is_empty() {
        write_sessions_table(h, &coll.sessions);
    }
    if !coll.preferences.is_empty() {
        write_preferences_table(h, &coll.preferences);
    }
    if !coll.top_sites.is_empty() {
        write_top_sites_table(h, &coll.top_sites);
    }
    // Brave-specific
    if !coll.brave_shields.is_empty() {
        write_brave_shields_table(h, &coll.brave_shields);
    }
    if let Some(ref rewards) = coll.brave_rewards {
        write_brave_rewards(h, rewards);
    }
    if !coll.brave_wallet.is_empty() {
        write_brave_wallet_table(h, &coll.brave_wallet);
    }
    if let Some(ref tor) = coll.brave_tor {
        write_brave_tor(h, tor);
    }
    if !coll.permissions.is_empty() {
        write_permissions_table(h, &coll.permissions);
    }
    if !coll.typed_urls.is_empty() {
        write_typed_urls_table(h, &coll.typed_urls);
    }

    // New forensic sections
    if !coll.wal_recovered.is_empty() {
        write_wal_recovered_table(h, &coll.wal_recovered);
    }
    if !coll.cache_extracted.is_empty() {
        write_cache_extracted_table(h, &coll.cache_extracted);
    }
    if !coll.extension_files.is_empty() {
        write_extension_files_table(h, &coll.extension_files);
    }

    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

fn write_history_table(h: &mut String, entries: &[HistoryEntry]) {
    let _ = write!(
        h,
        r#"<details id="artifacts"><summary>Browsing History ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Title</th><th>Visit Count</th><th>Last Visit</th><th>Type</th><th>Referrer</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.title),
            opt_u64(&e.visit_count),
            opt(&e.last_visit_time),
            opt(&e.visit_type),
            opt(&e.referrer),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_downloads_table(h: &mut String, entries: &[DownloadEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Downloads ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Target Path</th><th>Start</th><th>End</th><th>Size</th><th>State</th><th>MIME</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let size = match (e.received_bytes, e.total_bytes) {
            (Some(r), Some(t)) => format!("{}/{}", r, t),
            (Some(r), None) => r.to_string(),
            _ => "—".into(),
        };
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.target_path),
            opt(&e.start_time),
            opt(&e.end_time),
            size,
            opt(&e.state),
            opt(&e.mime_type),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_cookies_table(h: &mut String, entries: &[CookieEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Cookies ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Host</th><th>Name</th><th>Path</th><th>Created</th><th>Expires</th><th>Secure</th><th>HttpOnly</th><th>Encrypted</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.host),
            esc(&e.name),
            opt(&e.path),
            opt(&e.creation_time),
            opt(&e.expiry_time),
            opt_bool(&e.is_secure),
            opt_bool(&e.is_httponly),
            opt_bool(&e.encrypted),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_logins_table(h: &mut String, entries: &[LoginEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Login Data ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Origin URL</th><th>Username</th><th>Password Present</th><th>Created</th><th>Last Used</th><th>Times Used</th><th>Encryption</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.origin_url),
            opt(&e.username),
            opt_bool(&e.password_present),
            opt(&e.date_created),
            opt(&e.date_last_used),
            opt_u64(&e.times_used),
            opt(&e.encrypted_with),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_autofill_table(h: &mut String, entries: &[AutofillEntry], label: &str) {
    let _ = write!(
        h,
        r#"<details><summary>{} ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Field Name</th><th>Value</th><th>Times Used</th><th>First Used</th><th>Last Used</th></tr></thead><tbody>"#,
        label,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.field_name),
            esc(&e.value),
            opt_u64(&e.times_used),
            opt(&e.first_used),
            opt(&e.last_used),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_bookmarks_table(h: &mut String, entries: &[BookmarkEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Bookmarks ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Title</th><th>Folder</th><th>Date Added</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.title),
            opt(&e.folder),
            opt(&e.date_added),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_extensions_table(h: &mut String, entries: &[ExtensionEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Extensions / Add-ons ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>ID</th><th>Name</th><th>Version</th><th>Permissions</th><th>Enabled</th><th>Source</th><th>Installed</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let perms = match &e.permissions {
            Some(p) => esc(&p.join(", ")),
            None => "—".into(),
        };
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.id),
            opt(&e.name),
            opt(&e.version),
            perms,
            opt_bool(&e.enabled),
            opt(&e.source),
            opt(&e.install_date),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_cache_table(h: &mut String, entries: &[CacheEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Cache Metadata ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Content Type</th><th>Size</th><th>Created</th><th>Last Access</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.content_type),
            opt_u64(&e.content_length),
            opt(&e.creation_time),
            opt(&e.last_access_time),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_sessions_table(h: &mut String, entries: &[SessionEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Sessions ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Title</th><th>Window</th><th>Tab</th><th>Last Active</th><th>Pinned</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let win = e.window_id.map_or("—".into(), |v| v.to_string());
        let tab = e.tab_index.map_or("—".into(), |v| v.to_string());
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.title),
            win,
            tab,
            opt(&e.last_active_time),
            opt_bool(&e.pinned),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_preferences_table(h: &mut String, entries: &[PreferenceEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Preferences ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Key</th><th>Value</th><th>Note</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let val = serde_json::to_string(&e.value).unwrap_or_default();
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.key),
            esc(&val),
            opt(&e.note),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_top_sites_table(h: &mut String, entries: &[TopSiteEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Top Sites ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>Rank</th><th>URL</th><th>Title</th></tr></thead><tbody>"#,
        entries.len()
    );
    for e in entries {
        let rank = e.rank.map_or("—".into(), |v| v.to_string());
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            rank,
            esc(&e.url),
            opt(&e.title),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

// -- Brave-specific ----------------------------------------------------------

fn write_brave_shields_table(h: &mut String, entries: &[BraveShieldsEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Brave Shields Config ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>Site</th><th>Shields ON</th><th>Ad Block</th><th>Fingerprint Block</th><th>Cookie Block</th><th>HTTPS Upgrade</th></tr></thead><tbody>"#,
        entries.len()
    );
    for e in entries {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&e.site),
            opt_bool(&e.shields_enabled),
            opt(&e.ad_block),
            opt(&e.fingerprint_block),
            opt(&e.cookie_block),
            opt_bool(&e.https_upgrade),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_brave_rewards(h: &mut String, r: &BraveRewardsEntry) {
    let _ = write!(
        h,
        r#"<details><summary>Brave Rewards / BAT</summary><div class="detail-content"><table>
<tbody>
  <tr><td><b>Wallet Connected</b></td><td>{}</td></tr>
  <tr><td><b>Custodial Partner</b></td><td>{}</td></tr>
  <tr><td><b>BAT Balance</b></td><td>{}</td></tr>
  <tr><td><b>Payment Month</b></td><td>{}</td></tr>
  <tr><td><b>Ad Notifications</b></td><td>{}</td></tr>
</tbody></table>"#,
        opt_bool(&r.wallet_connected),
        opt(&r.custodial_partner),
        r.bat_balance.map_or("—".into(), |v| format!("{:.4}", v)),
        opt(&r.payment_month),
        opt_u64(&r.ad_notifications_received),
    );
    if let Some(tips) = &r.tips {
        if !tips.is_empty() {
            let _ = write!(
                h,
                r#"<h3>Tips</h3><div class="table-wrap"><table>
<thead><tr><th>Publisher</th><th>Amount (BAT)</th><th>Date</th></tr></thead><tbody>"#
            );
            for t in tips {
                let _ = write!(
                    h,
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&t.publisher),
                    t.amount_bat.map_or("—".into(), |v| format!("{:.4}", v)),
                    opt(&t.date),
                );
            }
            let _ = write!(h, "</tbody></table></div>");
        }
    }
    let _ = write!(h, "</div></details>");
}

fn write_brave_wallet_table(h: &mut String, entries: &[BraveWalletEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Brave Wallet ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Address</th><th>Chain</th><th>TX Hash</th><th>TX Time</th><th>TX Value</th><th>Connected dApps</th><th>Encrypted</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let dapps = match &e.connected_dapps {
            Some(d) => esc(&d.join(", ")),
            None => "—".into(),
        };
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            opt(&e.address),
            opt(&e.chain),
            opt(&e.tx_hash),
            opt(&e.tx_time),
            opt(&e.tx_value),
            dapps,
            opt_bool(&e.encrypted),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_brave_tor(h: &mut String, t: &BraveTorEntry) {
    let _ = write!(
        h,
        r#"<details><summary><span class="badge badge-red" style="margin-right:8px;">TOR</span> Brave Tor Indicators</summary><div class="detail-content"><table>
<tbody>
  <tr><td><b>Tor Enabled</b></td><td>{}</td></tr>
  <tr><td><b>Config Path</b></td><td>{}</td></tr>
  <tr><td><b>Notes</b></td><td>{}</td></tr>
</tbody></table>"#,
        opt_bool(&t.tor_enabled),
        opt(&t.tor_config_path),
        opt(&t.notes),
    );
    if let Some(urls) = &t.onion_urls_found {
        if !urls.is_empty() {
            let _ = write!(h, "<h3>.onion URLs Found</h3><ul>");
            for u in urls {
                let _ = write!(h, "<li>{}</li>", esc(u));
            }
            let _ = write!(h, "</ul>");
        }
    }
    let _ = write!(h, "</div></details>");
}

fn write_permissions_table(h: &mut String, entries: &[PermissionEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Permissions ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Origin</th><th>Type</th><th>Capability</th><th>Expiry</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.origin),
            esc(&e.permission_type),
            opt(&e.capability),
            opt(&e.expiry_time),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_typed_urls_table(h: &mut String, entries: &[TypedUrlEntry]) {
    let _ = write!(
        h,
        r#"<details><summary>Typed URLs ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Timestamp</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.timestamp),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

// ---------------------------------------------------------------------------
// New forensic section tables
// ---------------------------------------------------------------------------

fn write_wal_recovered_table(h: &mut String, entries: &[WalRecoveredRow]) {
    let _ = write!(
        h,
        r#"<details><summary><span class="badge badge-yellow" style="margin-right:8px;">RECOVERED</span> WAL/Journal Recovery ({} items)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Source File</th><th>Frame</th><th>Type</th><th>Recovered Data</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let frame = e.frame_number.map_or("—".into(), |f| f.to_string());
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.source_file),
            frame,
            opt(&e.data_type),
            esc(&e.recovered_text),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_cache_extracted_table(h: &mut String, entries: &[CacheExtractedItem]) {
    let _ = write!(
        h,
        r#"<details><summary>Cache Extracted ({} items)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>URL</th><th>Content Type</th><th>Size</th><th>Cache File</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.url),
            opt(&e.content_type),
            opt_u64(&e.content_length),
            opt(&e.cache_file),
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

fn write_extension_files_table(h: &mut String, entries: &[ExtensionCodeFile]) {
    let _ = write!(
        h,
        r#"<details><summary>Extension Code Files ({} files)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Extension ID</th><th>Name</th><th>File Path</th><th>Type</th><th>Size</th></tr></thead><tbody>"#,
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            i + 1,
            esc(&e.extension_id),
            opt(&e.extension_name),
            esc(&e.file_path),
            esc(&e.file_type),
            e.file_size,
        );
    }
    let _ = write!(h, "</tbody></table></div></div></details>");
}

// ---------------------------------------------------------------------------
// Timeline section
// ---------------------------------------------------------------------------

fn write_timeline(h: &mut String, report: &ForensicReport) {
    if report.timeline.is_empty() {
        return;
    }

    let _ = write!(
        h,
        r#"<div class="card" id="timeline"><h2>Automated Timeline ({} events)</h2>"#,
        report.timeline.len()
    );

    // ── Collect unique browsers for filter UI
    let uniq_browsers: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        report.timeline.iter()
            .map(|e| e.source_browser.clone())
            .filter(|b| seen.insert(b.clone()))
            .collect()
    };

    // ── Interactive Chart.js scatter timeline
    let _ = write!(
        h,
        r#"<details open><summary>Interactive Timeline Chart (<span id="tlCount">{n} events</span>)</summary>
<div class="detail-content">
<div class="tl-controls">
  <div class="fg">
    <span class="fg-lbl">Event Types</span>
    <label><input type="checkbox" class="tl-type-chk" value="visit" checked> Visits</label>
    <label><input type="checkbox" class="tl-type-chk" value="download" checked> Downloads</label>
    <label><input type="checkbox" class="tl-type-chk" value="autofill" checked> Autofill</label>
    <label><input type="checkbox" class="tl-type-chk" value="session" checked> Sessions</label>
    <label><input type="checkbox" class="tl-type-chk" value="bookmark" checked> Bookmarks</label>
    <label><input type="checkbox" class="tl-type-chk" value="login" checked> Logins</label>
  </div>
  <div class="fg">
    <span class="fg-lbl">Browsers</span>
"#,
        n = report.timeline.len()
    );
    for br in &uniq_browsers {
        let _ = write!(
            h,
            r#"    <label><input type="checkbox" class="tl-br-chk" value="{v}" checked> {l}</label>"#,
            v = esc(br),
            l = esc(br)
        );
    }
    let _ = write!(
        h,
        r#"
  </div>
  <div class="fg">
    <span class="fg-lbl">Search</span>
    <input type="text" id="tlSearch" placeholder="URL or title…">
    <div class="tl-btn-row" style="margin-top:6px;">
      <button class="btn btn-sec btn-sm" onclick="resetTimeline()">Reset</button>
    </div>
  </div>
</div>
<div class="chart-wrap chart-lg"><canvas id="tlChart"></canvas></div>
<p style="font-size:.8rem;color:var(--text-muted);margin-top:8px;">
  Y-axis lanes: Visits · Downloads · Autofill · Sessions · Bookmarks · Logins · Other &nbsp;|&nbsp;
  Hover a point for details. Use checkboxes to filter.
</p>
</div></details>"#
    );

    let _ = write!(
        h,
        r#"<details open><summary>Timeline Events</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Timestamp</th><th>Event</th><th>Browser</th><th>Profile</th><th>URL</th><th>Title/Details</th></tr></thead><tbody>"#
    );

    // Show up to 5000 events to avoid massive HTML
    let max_display = std::cmp::min(report.timeline.len(), 5000);
    for (i, e) in report.timeline.iter().take(max_display).enumerate() {
        let event_class = match e.event_type.as_str() {
            "visit" => "badge-blue",
            "download_start" | "download_end" => "badge-green",
            "cookie_created" | "cookie_accessed" => "badge-yellow",
            "login_created" | "login_used" => "badge-red",
            "bookmark_added" => "badge-purple",
            _ => "badge-blue",
        };
        let _ = write!(
            h,
            r#"<tr><td>{}</td><td>{}</td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            i + 1,
            esc(&e.timestamp),
            event_class,
            esc(&e.event_type),
            esc(&e.source_browser),
            opt(&e.profile),
            opt(&e.url),
            e.title.as_deref().or(e.details.as_deref()).map(|s| esc(s)).unwrap_or_else(|| "—".into()),
        );
    }

    if report.timeline.len() > max_display {
        let _ = write!(
            h,
            r#"<tr><td colspan="7" style="text-align:center;color:var(--text-muted);">… {} more events (see JSON report for full data) …</td></tr>"#,
            report.timeline.len() - max_display
        );
    }

    let _ = write!(h, "</tbody></table></div></div></details></div>");
}

// ---------------------------------------------------------------------------
// Privacy indicators section
// ---------------------------------------------------------------------------

fn write_privacy_indicators(h: &mut String, report: &ForensicReport) {
    if report.privacy_indicators.is_empty() {
        return;
    }

    let _ = write!(
        h,
        r#"<div class="card" id="privacy"><h2><span class="severity-badge critical" style="margin-right:8px;">!</span> Privacy / Incognito / Tor Indicators ({} found)</h2>"#,
        report.privacy_indicators.len()
    );

    for (i, ind) in report.privacy_indicators.iter().enumerate() {
        let (card_cls, badge_cls) = match ind.severity.as_str() {
            "critical" => ("severity-critical", "critical"),
            "high" => ("severity-high", "high"),
            "medium" => ("severity-medium", "medium"),
            _ => ("severity-info", "info"),
        };
        let _ = write!(
            h,
            r#"<div class="finding-card {}">
  <div class="finding-header">
    <span class="severity-badge {}">{}</span>
    <span class="finding-title">{}  — {}</span>
  </div>
  <div class="finding-body">
    <div class="evidence-box">{}</div>
    <div class="metadata-tags">
      <span class="meta-tag">Browser: {}</span>
      <span class="meta-tag">Profile: {}</span>
      <span class="meta-tag">#{}</span>
    </div>
  </div>
</div>"#,
            card_cls,
            badge_cls,
            esc(&ind.severity).to_uppercase(),
            esc(&ind.indicator_type),
            esc(&ind.browser),
            esc(&ind.evidence),
            esc(&ind.browser),
            opt(&ind.profile),
            i + 1,
        );
    }

    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// System-wide artifacts
// ---------------------------------------------------------------------------

fn write_system_artifacts(h: &mut String, report: &ForensicReport) {
    if report.dns_cache.is_empty()
        && report.prefetch.is_empty()
        && report.jump_lists.is_empty()
        && report.zone_identifiers.is_empty()
    {
        return;
    }

    let _ = write!(
        h,
        r#"<div class="card" id="system"><h2>System-Wide / Cross-Browser Artifacts</h2>"#
    );

    if !report.dns_cache.is_empty() {
        let _ = write!(
            h,
            r#"<details><summary>DNS Cache ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Record Name</th><th>Type</th><th>TTL</th><th>Data</th></tr></thead><tbody>"#,
            report.dns_cache.len()
        );
        for (i, e) in report.dns_cache.iter().enumerate() {
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                esc(&e.record_name),
                opt(&e.record_type),
                opt_u64(&e.ttl),
                opt(&e.data),
            );
        }
        let _ = write!(h, "</tbody></table></div></div></details>");
    }

    if !report.prefetch.is_empty() {
        let _ = write!(
            h,
            r#"<details><summary>Prefetch ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Executable</th><th>Run Count</th><th>Last Run</th><th>Hash</th></tr></thead><tbody>"#,
            report.prefetch.len()
        );
        for (i, e) in report.prefetch.iter().enumerate() {
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                esc(&e.executable),
                opt_u64(&e.run_count),
                opt(&e.last_run_time),
                opt(&e.hash),
            );
        }
        let _ = write!(h, "</tbody></table></div></div></details>");
    }

    if !report.jump_lists.is_empty() {
        let _ = write!(
            h,
            r#"<details><summary>Jump Lists ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>App ID</th><th>Target</th><th>Arguments</th><th>Timestamp</th></tr></thead><tbody>"#,
            report.jump_lists.len()
        );
        for (i, e) in report.jump_lists.iter().enumerate() {
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                opt(&e.app_id),
                esc(&e.target_path),
                opt(&e.arguments),
                opt(&e.timestamp),
            );
        }
        let _ = write!(h, "</tbody></table></div></div></details>");
    }

    if !report.zone_identifiers.is_empty() {
        let _ = write!(
            h,
            r#"<details><summary>Zone.Identifier ADS ({} entries)</summary><div class="detail-content"><div class="table-wrap"><table>
<thead><tr><th>#</th><th>File</th><th>Zone ID</th><th>Host URL</th><th>Referrer URL</th></tr></thead><tbody>"#,
            report.zone_identifiers.len()
        );
        for (i, e) in report.zone_identifiers.iter().enumerate() {
            let zone = e.zone_id.map_or("—".into(), |v| v.to_string());
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                esc(&e.file_path),
                zone,
                opt(&e.host_url),
                opt(&e.referrer_url),
            );
        }
        let _ = write!(h, "</tbody></table></div></div></details>");
    }

    let _ = write!(h, "</div>");
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn write_footer(h: &mut String, report: &ForensicReport) {
    let _ = write!(
        h,
        r#"</div><!-- /container -->
<footer>
  <p style="margin-bottom:6px;"><strong style="color:var(--accent);">BROWSER</strong><strong>FORENSICS</strong> &mdash; Automated Browser Artifact Analysis</p>
  <p>Report generated {} &mdash; Tool v{}</p>
  <p>This report is generated from parsed artifact data. All findings should be verified with original evidence.</p>
</footer>
</body>
</html>"#,
        esc(&report.report_generated),
        esc(&report.tool_version),
    );
}
