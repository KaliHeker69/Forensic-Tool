use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::collections::BTreeMap;

use crate::models::timeline::TimelineEvent;
use crate::models::{AnalysisContext, CorrelatedFinding, Severity, UsbDevice, format_bytes};

pub fn generate_html_report(
    path: &Path,
    devices: &[UsbDevice],
    findings: &[CorrelatedFinding],
    timeline: &[TimelineEvent],
    context: &AnalysisContext,
) -> Result<()> {
    let mut file = std::fs::File::create(path)?;

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();
    let generated_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    write!(file, "{}", html_head())?;
    write!(file, "{}", html_css())?;

    // Banner
    write!(file, r#"</style></head><body>
<div class="report-banner">
    <h1><span class="icon">&#x1F50D;</span> Forensic Analysis Report</h1>
    <div class="subtitle">USB Data Theft &amp; Exfiltration Investigation</div>
    <div class="meta">
        <span>Generated: {gen}</span>
        <span>Tool: forensic_analyzer v1.0.0</span>
        <span>Devices: {nd}</span>
        <span>Findings: {nf}</span>
        <span>Timeline: {nt}</span>
    </div>
</div>
"#, gen=generated_at, nd=devices.len(), nf=findings.len(), nt=timeline.len())?;

    // Nav
    write!(file, r##"
<div class="nav-bar">
    <a href="#summary">Dashboard</a>
    <a href="#devices">USB Devices</a>
    <a href="#findings">Findings</a>
    <a href="#timeline">Timeline</a>
    <a href="#events-table">Event Log</a>
    <a href="#integrity">Evidence</a>
    <a href="#artifacts-status">Artifacts</a>
</div>
<div class="container">
"##)?;

    // Risk score
    let risk_score = compute_risk_score(findings, context);
    let (risk_color, risk_label) = match risk_score {
        90..=100 => ("var(--severity-critical)", "CRITICAL RISK"),
        70..=89 => ("var(--severity-high)", "HIGH RISK"),
        40..=69 => ("var(--severity-medium)", "MEDIUM RISK"),
        10..=39 => ("var(--severity-low)", "LOW RISK"),
        _ => ("var(--severity-info)", "MINIMAL RISK"),
    };
    let sev_class = match risk_score { 90..=100 => "critical", 70..=89 => "high", 40..=69 => "medium", 10..=39 => "low", _ => "info" };

    write!(file, r#"
<div class="risk-meter">
    <div class="risk-label">Overall Risk Assessment</div>
    <div class="risk-bar"><div class="risk-fill" style="width:{score}%;background:linear-gradient(90deg,var(--severity-low),{color});"></div></div>
    <div class="risk-score" style="color:{color}">{score}/100</div>
    <span class="severity {sc}">{rl}</span>
</div>
"#, score=risk_score, color=risk_color, rl=risk_label, sc=sev_class)?;

    // === EXECUTIVE DASHBOARD ===
    write!(file, r#"
<div id="summary" class="section">
    <div class="section-header"><h2>&#x1F4CA; Executive Dashboard</h2></div>
    <div class="stat-grid">
        <div class="stat-card"><div class="label">USB Devices</div><div class="value purple">{nd}</div></div>
        <div class="stat-card"><div class="label">Timeline Events</div><div class="value accent">{nt}</div></div>
        <div class="stat-card"><div class="label">Total Findings</div><div class="value">{nf}</div></div>
        <div class="stat-card"><div class="label">Critical</div><div class="value critical">{cr}</div></div>
        <div class="stat-card"><div class="label">High</div><div class="value high">{hi}</div></div>
        <div class="stat-card"><div class="label">Medium</div><div class="value medium">{me}</div></div>
        <div class="stat-card"><div class="label">Low</div><div class="value low">{lo}</div></div>
        <div class="stat-card"><div class="label">Info</div><div class="value" style="color:var(--severity-info)">{inf}</div></div>
    </div>
"#, nd=devices.len(), nt=timeline.len(), nf=findings.len(), cr=critical, hi=high, me=medium, lo=low, inf=info)?;

    // Executive detail cards
    let suspect = context.suspect_users.first().cloned().unwrap_or_else(|| "Unknown / Not Determined".to_string());
    write!(file, r#"
    <div class="exec-grid">
        <div class="exec-card">
            <div class="exec-label">&#x1F464; Suspect User Account</div>
            <div class="exec-value">{suspect}</div>
        </div>
        <div class="exec-card">
            <div class="exec-label">&#x1F4BE; Data Volume Estimate</div>
            <div class="exec-value">{vol} ({uf} unique files / {te} events)</div>
        </div>
        <div class="exec-card">
            <div class="exec-label">&#x1F3AF; Investigation Confidence</div>
            <div class="exec-value">{conf:.0}%</div>
            <div class="exec-detail">
"#, suspect=html_escape(&suspect), vol=format_bytes(context.data_volume_estimate), uf=context.unique_files_accessed, te=context.total_file_events, conf=context.investigation_confidence)?;
    for driver in &context.confidence_drivers {
        write!(file, r#"<div class="exec-driver">{}</div>"#, html_escape(driver))?;
    }
    write!(file, r#"</div></div></div>
    <div class="narrative-box">
        <div class="narrative-label">&#x1F4DD; Key Finding Summary</div>
        <div class="narrative-text">{}</div>
    </div>
"#, html_escape(&context.executive_narrative))?;

    // Recommended Next Steps
    if !context.recommended_next_steps.is_empty() {
        write!(file, r#"<div class="next-steps-box"><div class="narrative-label">&#x2705; Recommended Next Steps</div><ol class="next-steps">"#)?;
        for step in &context.recommended_next_steps {
            write!(file, r#"<li>{}</li>"#, html_escape(step))?;
        }
        write!(file, r#"</ol></div>"#)?;
    }
    write!(file, r#"</div>"#)?;

    // === USB DEVICES ===
    write!(file, r#"
<div id="devices" class="section">
    <div class="section-header"><h2>&#x1F4BE; USB Devices Detected</h2><span class="badge">{} device(s)</span></div>
"#, devices.len())?;

    if devices.is_empty() {
        write!(file, r#"<p style="color:var(--text-muted);font-style:italic;">No USB storage devices found.</p>"#)?;
    } else {
        write!(file, r#"<div class="usb-grid">"#)?;
        for device in devices {
            let fc = device.first_connected.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("N/A".into());
            let lc = device.last_connected.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("N/A".into());
            let ld = device.last_disconnected.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("N/A".into());
            let serial_class = if device.suspicious_serial { " suspicious" } else { "" };

            write!(file, r#"
    <div class="usb-card{sc}">
        <div class="usb-name">{v} {p}</div>
        <div class="usb-serial">S/N: {sn}{ss}</div>
        <div class="usb-detail">
            <span class="lbl">Drive Letter</span><span class="val">{dl}</span>
            <span class="lbl">Volume GUID</span><span class="val">{guid}</span>
            <span class="lbl">Volume Label</span><span class="val">{vl}</span>
            <span class="lbl">Friendly Name</span><span class="val">{fn_}</span>
            <span class="lbl">User Account</span><span class="val">{user}</span>
            <span class="lbl">Vendor ID (VID)</span><span class="val">{vid}</span>
            <span class="lbl">Product ID (PID)</span><span class="val">{pid}</span>
            <span class="lbl">First Connected</span><span class="val">{fc}</span>
            <span class="lbl">Last Connected</span><span class="val">{lc}</span>
            <span class="lbl">Last Removed</span><span class="val">{ld}</span>
            <span class="lbl">Connection Count</span><span class="val">{cc}</span>
        </div>{flags}
    </div>
"#,
                sc=serial_class,
                v=html_escape(&device.vendor), p=html_escape(&device.product),
                sn=html_escape(&device.serial_number),
                ss=if device.suspicious_serial { " ⚠ SUSPICIOUS" } else { "" },
                dl=device.drive_letter.as_deref().unwrap_or("N/A"),
                guid=device.volume_guid.as_deref().unwrap_or("N/A"),
                vl=device.volume_label.as_deref().unwrap_or("N/A"),
                fn_=device.friendly_name.as_deref().map(|s| html_escape(s)).unwrap_or("N/A".into()),
                user=device.associated_user.as_deref().unwrap_or("N/A"),
                vid=device.vendor_id.as_deref().unwrap_or("N/A"),
                pid=device.product_id.as_deref().unwrap_or("N/A"),
                fc=fc, lc=lc, ld=ld, cc=device.connection_count,
                flags=if device.suspicious_serial {
                    format!(r#"<div class="serial-flags">⚠ {}</div>"#, html_escape(&device.serial_flags.join(", ")))
                } else { String::new() },
            )?;
        }
        write!(file, r#"</div>"#)?;
    }
    write!(file, r#"</div>"#)?;

    // === FINDINGS ===
    write!(file, r#"
<div id="findings" class="section">
    <div class="section-header"><h2>&#x26A0;&#xFE0F; Correlated Findings</h2><span class="badge">{} finding(s)</span></div>
    <div class="findings-tools"><input id="findings-search" type="text" placeholder="Search findings..." /></div>
"#, findings.len())?;

    if findings.is_empty() {
        write!(file, r#"<p style="color:var(--text-muted);font-style:italic;">No significant findings.</p>"#)?;
    } else {
        for (i, finding) in findings.iter().enumerate() {
            let sc = match finding.severity { Severity::Critical => "critical", Severity::High => "high", Severity::Medium => "medium", Severity::Low => "low", Severity::Info => "info" };
            let unique_files: std::collections::HashSet<_> = finding.file_events.iter().map(|e| &e.file_path).collect();

            write!(file, r#"
    <div class="finding-card{open}" id="finding-{i}">
        <div class="fc-header" onclick="this.parentElement.classList.toggle('open')">
            <span class="severity {sc}">{sev}</span>
            <span class="fc-title">{title}</span>
            <div class="fc-meta">
                <span class="conf-bar">{conf:.0}%<span class="bar"><span class="fill" style="width:{conf:.0}%"></span></span></span>
                <span>{uf} file(s)</span>
                <span title="Cross-artifact corroboration">&#x1F517; {corr} source(s)</span>
            </div>
            <span class="fc-chevron">&#x25B6;</span>
        </div>
        <div class="fc-body">
            <div class="fc-desc">{desc}</div>
            <div class="fc-type-badge">{ft}</div>
"#,
                i=i, open=if i==0 { " open" } else { "" }, sc=sc,
                sev=finding.severity, title=html_escape(&finding.title),
                conf=finding.confidence * 100.0,
                uf=unique_files.len(), corr=finding.corroboration_count,
                desc=html_escape(&finding.description), ft=finding.finding_type,
            )?;

            if !finding.supporting_artifacts.is_empty() {
                write!(file, r#"<div class="fc-artifacts">"#)?;
                for a in &finding.supporting_artifacts { write!(file, r#"<span class="fc-artifact-tag">{}</span>"#, html_escape(a))?; }
                write!(file, r#"</div>"#)?;
            }

            if let Some(ref dev) = finding.usb_device {
                write!(file, r#"<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">
                    <strong style="color:var(--accent-purple);">Device:</strong> {} {} (S/N: {})</div>"#,
                    html_escape(&dev.vendor), html_escape(&dev.product), html_escape(&dev.serial_number))?;
            }

            if !finding.file_events.is_empty() {
                write!(file, r#"<div class="fc-file-list">"#)?;
                let mut grouped: BTreeMap<(String, String), (usize, Option<chrono::DateTime<chrono::Utc>>)> = BTreeMap::new();
                for event in &finding.file_events {
                    let key = (event.access_type.to_string(), event.file_path.clone());
                    let entry = grouped.entry(key).or_insert((0, event.timestamp));
                    entry.0 += 1;
                    if entry.1.is_none() && event.timestamp.is_some() { entry.1 = event.timestamp; }
                }
                let show = std::cmp::min(grouped.len(), 100);
                for ((access, path), (count, ts_opt)) in grouped.iter().take(show) {
                    let ts = ts_opt.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("—".into());
                    write!(file, r#"<div class="fc-file-item"><span class="tag">{a}</span> <span style="color:var(--text-muted)">{ts}</span> &nbsp; {p}{ch}</div>"#,
                        a=access, ts=ts, p=html_escape(path),
                        ch=if *count > 1 { format!("<span class=\"count\">x{}</span>", count) } else { String::new() })?;
                }
                if grouped.len() > show { write!(file, r#"<div class="fc-file-item" style="color:var(--accent-blue);font-weight:600;">... +{} more</div>"#, grouped.len() - show)?; }
                write!(file, r#"</div>"#)?;
            }

            write!(file, r#"</div></div>"#)?;
        }
    }
    write!(file, r#"</div>"#)?;

    // === TIMELINE ===
    let svg = generate_timeline_overview_svg(timeline);
    write!(file, r#"
<div id="timeline" class="section">
    <div class="section-header"><h2>&#x1F552; Visual Timeline</h2><span class="badge">{ne} event(s)</span></div>
    <div class="timeline-overview">{svg}</div>
    <div class="timeline-controls">
        <button class="tl-filter-btn active" onclick="filterTimeline('all',this)">All</button>
        <button class="tl-filter-btn" onclick="filterTimeline('usb',this)"><span class="dot" style="background:var(--tl-usb)"></span>USB</button>
        <button class="tl-filter-btn" onclick="filterTimeline('file',this)"><span class="dot" style="background:var(--tl-file)"></span>File</button>
        <button class="tl-filter-btn" onclick="filterTimeline('exec',this)"><span class="dot" style="background:var(--tl-exec)"></span>Execution</button>
        <button class="tl-filter-btn" onclick="filterTimeline('user',this)"><span class="dot" style="background:var(--tl-user)"></span>User</button>
        <button class="tl-filter-btn" onclick="filterTimeline('driver',this)"><span class="dot" style="background:var(--tl-driver)"></span>Driver</button>
    </div>
    <div class="timeline-container"><div class="timeline-track" id="timeline-track">
"#, ne=timeline.len(), svg=svg)?;

    let mut current_date = String::new();
    let initial_display = 200;
    for (i, event) in timeline.iter().enumerate() {
        let edate = event.timestamp.format("%Y-%m-%d").to_string();
        let etime = event.timestamp.format("%H:%M:%S%.3f").to_string();
        let cat = timeline_event_category(&event.event_type.to_string());
        let hc = if i >= initial_display { " tl-hidden tl-extra" } else { "" };
        // Severity color based on if this event appears in high-severity findings
        let sev_attr = if crate::models::is_off_hours(&event.timestamp) { " data-offhours=\"1\"" } else { "" };
        if edate != current_date {
            current_date = edate.clone();
            write!(file, r#"<div class="tl-date-group{hc}">{d}</div>"#, d=edate, hc=hc)?;
        }
        write!(file, r#"<div class="tl-event cat-{cat}{hc}" data-cat="{cat}"{sa}>
    <div class="tl-time">{t}</div><div class="tl-type">{et}</div><div class="tl-desc">{desc}</div>
"#, cat=cat, hc=hc, sa=sev_attr, t=etime, et=html_escape(&event.event_type.to_string()), desc=html_escape(&event.description))?;
        if let Some(ref fp) = event.file_path { write!(file, r#"<div class="tl-detail">{}</div>"#, html_escape(fp))?; }
        else if let Some(ref dt) = event.details { write!(file, r#"<div class="tl-detail">{}</div>"#, html_escape(dt))?; }
        write!(file, r#"<div class="tl-source">Source: {} &middot; Reliability: {}{}</div></div>
"#, html_escape(&event.source_artifact), event.reliability, if crate::models::is_off_hours(&event.timestamp) { " &middot; <span style=\"color:var(--severity-high)\">OFF-HOURS</span>" } else { "" })?;
    }
    if timeline.len() > initial_display {
        write!(file, r#"<button class="tl-load-more" id="tl-load-more" onclick="showAllTimeline()">Show all {} ({} more)</button>"#, timeline.len(), timeline.len() - initial_display)?;
    }
    write!(file, r#"</div></div></div>"#)?;

    // === EVENT LOG TABLE ===
    write!(file, r#"
<div id="events-table" class="section">
    <div class="section-header"><h2>&#x1F4CB; Full Event Log</h2><span class="badge">{ne} event(s)</span>
        <span class="badge">{uf} unique files / {te} total events</span>
    </div>
    <div class="table-tools">
        <input id="table-search" type="text" placeholder="Filter events..." />
        <button class="export-btn" onclick="exportTableCSV()">&#x1F4E5; CSV</button>
        <button class="export-btn" onclick="exportTableJSON()">&#x1F4E5; JSON</button>
    </div>
    <div style="overflow-x:auto;">
    <table class="data-table" id="event-table">
        <thead><tr>
            <th onclick="sortTable(0)">#</th>
            <th onclick="sortTable(1)">Timestamp</th>
            <th onclick="sortTable(2)">Type</th>
            <th onclick="sortTable(3)">Description</th>
            <th onclick="sortTable(4)">File/Device</th>
            <th onclick="sortTable(5)">User / SID</th>
            <th onclick="sortTable(6)">Source</th>
            <th onclick="sortTable(7)">Reliability</th>
        </tr></thead><tbody>
"#, ne=timeline.len(), uf=context.unique_files_accessed, te=context.total_file_events)?;

    // Deduplicate events for table
    let mut event_dedup: BTreeMap<String, (usize, &TimelineEvent)> = BTreeMap::new();
    for event in timeline.iter() {
        let key = format!("{}|{}|{}|{}", event.timestamp.format("%Y-%m-%d %H:%M:%S"), event.event_type, event.description, event.source_artifact);
        let entry = event_dedup.entry(key).or_insert((0, event));
        entry.0 += 1;
    }

    let table_limit = 500;
    for (i, (_, (count, event))) in event_dedup.iter().take(table_limit).enumerate() {
        let detail = event.file_path.as_deref().or(event.device_serial.as_deref()).unwrap_or("—");
        let user = event.user.as_deref().unwrap_or("—");
        let count_badge = if *count > 1 { format!(" <span class=\"count\">x{}</span>", count) } else { String::new() };
        write!(file, r#"<tr><td>{i}</td><td class="mono">{ts}</td><td>{et}{cb}</td><td>{desc}</td><td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">{det}</td><td>{user}</td><td>{src}</td><td>{rel}</td></tr>
"#, i=i+1, ts=event.timestamp.format("%Y-%m-%d %H:%M:%S"), et=html_escape(&event.event_type.to_string()), cb=count_badge, desc=html_escape(&event.description), det=html_escape(detail), user=html_escape(user), src=html_escape(&event.source_artifact), rel=event.reliability)?;
    }

    if event_dedup.len() > table_limit {
        write!(file, r#"<tr><td colspan="8" style="text-align:center;color:var(--text-muted);font-style:italic;">Showing {s} of {t} unique events. See timeline.csv for full data.</td></tr>"#, s=table_limit, t=event_dedup.len())?;
    }
    write!(file, r#"</tbody></table></div></div>"#)?;

    // === EVIDENCE INTEGRITY ===
    write!(file, r#"
<div id="integrity" class="section">
    <div class="section-header"><h2>&#x1F512; Evidence Integrity</h2><span class="badge">{} file(s) hashed</span></div>
    <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px;">SHA-256 hashes of all parsed artifact files. These hashes can be used to verify evidence integrity and chain of custody.</p>
    <table class="data-table"><thead><tr><th>Artifact Type</th><th>File Name</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>
"#, context.artifact_hashes.len())?;

    for h in &context.artifact_hashes {
        write!(file, r#"<tr><td>{at}</td><td class="mono">{fn_}</td><td>{sz}</td><td class="mono" style="font-size:10px;word-break:break-all;">{hash}</td></tr>
"#, at=html_escape(&h.artifact_type), fn_=html_escape(&h.file_name), sz=format_bytes(h.file_size), hash=html_escape(&h.sha256))?;
    }
    if context.artifact_hashes.is_empty() {
        write!(file, r#"<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No artifact files were parsed.</td></tr>"#)?;
    }
    write!(file, r#"</tbody></table></div>"#)?;

    // === ARTIFACTS NOT FOUND ===
    write!(file, r#"
<div id="artifacts-status" class="section">
    <div class="section-header"><h2>&#x1F50E; Artifact Coverage</h2></div>
    <p style="color:var(--text-secondary);font-size:13px;margin-bottom:16px;">Showing which artifact categories were searched and whether data was found. Missing artifacts may represent collection gaps or deliberate evidence destruction.</p>
    <div class="artifact-coverage-grid">
"#)?;

    for status in &context.artifact_statuses {
        let (icon, cls) = if status.found { ("&#x2705;", "found") } else { ("&#x274C;", "not-found") };
        write!(file, r#"<div class="artifact-coverage-card {cls}">
    <div class="artifact-icon">{icon}</div>
    <div class="artifact-info">
        <div class="artifact-name">{name}</div>
        <div class="artifact-detail">{files} file(s) found</div>
        <div class="artifact-patterns">Searched: {pats}</div>
    </div>
</div>"#,
            cls=cls, icon=icon, name=html_escape(&status.category),
            files=status.files_found, pats=html_escape(&status.searched_patterns.join(", ")))?;
    }
    write!(file, r#"</div>"#)?;

    let missing: Vec<_> = context.artifact_statuses.iter().filter(|s| !s.found).collect();
    if !missing.is_empty() {
        write!(file, r#"<div class="missing-warning"><strong>⚠ Missing Artifacts:</strong> {} category(ies) had no files. Missing: {}. This may indicate incomplete evidence collection or deliberate evidence destruction.</div>"#,
            missing.len(), missing.iter().map(|m| m.category.as_str()).collect::<Vec<_>>().join(", "))?;
    }
    write!(file, r#"</div>"#)?;

    // Footer
    write!(file, r#"
<div class="report-footer">
    Forensic Analyzer v1.0.0 &middot; USB Data Theft Investigation Tool &middot; {gen}
    <br>This report is for authorized forensic investigation purposes only.
</div>
"#, gen=generated_at)?;

    // JavaScript
    write!(file, "{}", html_javascript())?;

    write!(file, r#"</div></body></html>"#)?;
    Ok(())
}

fn html_head() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Analysis Report - USB Data Theft Investigation</title>
<style>
"#
}

fn html_css() -> &'static str {
    r#"
:root {
    --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #1f2428;
    --bg-card: #1f2428; --bg-card-hover: #262c33;
    --bg-table-row: #161b22; --bg-table-row-alt: #1f2428;
    --border-color: #30363d; --text-primary: #c9d1d9; --text-secondary: #8b949e; --text-muted: #6e7681;
    --accent: #238636; --accent-light: #2ea043;
    --severity-critical: #da3633; --severity-critical-bg: rgba(218,54,51,0.16);
    --severity-high: #fd8c00; --severity-high-bg: rgba(253,140,0,0.16);
    --severity-medium: #9e6a03; --severity-medium-bg: rgba(158,106,3,0.16);
    --severity-low: #238636; --severity-low-bg: rgba(35,134,54,0.16);
    --severity-info: #1f6feb; --severity-info-bg: rgba(31,111,235,0.16);
    --accent-blue: #1f6feb; --accent-cyan: #2ea043; --accent-purple: #2ea043;
    --tl-usb: #da3633; --tl-file: #1f6feb; --tl-exec: #fd8c00; --tl-user: #2ea043; --tl-driver: #8b949e;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,sans-serif; background:var(--bg-primary); color:var(--text-primary); line-height:1.6; }
a { color:var(--accent-blue); text-decoration:none; } a:hover { text-decoration:underline; }
.report-banner { background:var(--bg-secondary); border-bottom:1px solid var(--border-color); padding:32px 48px; position:relative; overflow:hidden; }
.report-banner::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background:radial-gradient(circle at 20% 10%,rgba(46,160,67,0.10),transparent 45%); }
.report-banner h1 { font-size:26px; font-weight:700; position:relative; } .report-banner h1 .icon { margin-right:10px; }
.report-banner .subtitle { color:var(--text-secondary); font-size:14px; margin-top:6px; position:relative; }
.report-banner .meta { position:relative; margin-top:10px; font-size:12px; color:var(--text-muted); } .report-banner .meta span { margin-right:24px; }
.nav-bar { background:var(--bg-secondary); border-bottom:1px solid var(--border-color); padding:0 48px; display:flex; gap:4px; position:sticky; top:0; z-index:100; }
.nav-bar a { padding:12px 20px; font-size:13px; font-weight:600; color:var(--text-secondary); border-bottom:2px solid transparent; transition:all 0.2s; }
.nav-bar a:hover,.nav-bar a.active { color:var(--accent-light); border-bottom-color:var(--accent-light); text-decoration:none; background:rgba(46,160,67,0.08); }
.container { max-width:1320px; margin:0 auto; padding:32px 48px 80px; }
.section { margin-bottom:40px; }
.section-header { display:flex; align-items:center; gap:10px; margin-bottom:20px; padding-bottom:12px; border-bottom:1px solid var(--border-color); }
.section-header h2 { font-size:20px; font-weight:700; }
.section-header .badge { background:var(--bg-card); border:1px solid var(--border-color); border-radius:12px; padding:2px 10px; font-size:12px; color:var(--text-secondary); }
.stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:24px; }
.stat-card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; transition:transform 0.15s; }
.stat-card:hover { transform:translateY(-2px); border-color:var(--accent-blue); }
.stat-card .label { font-size:12px; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); margin-bottom:8px; }
.stat-card .value { font-size:32px; font-weight:700; }
.stat-card .value.critical { color:var(--severity-critical); } .stat-card .value.high { color:var(--severity-high); }
.stat-card .value.medium { color:var(--severity-medium); } .stat-card .value.low { color:var(--severity-low); }
.stat-card .value.accent { color:var(--accent-cyan); } .stat-card .value.purple { color:var(--accent-purple); }
.exec-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; margin-bottom:24px; }
.exec-card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; }
.exec-label { font-size:13px; font-weight:600; color:var(--text-muted); margin-bottom:8px; }
.exec-value { font-size:18px; font-weight:700; color:var(--text-primary); }
.exec-detail { margin-top:8px; }
.exec-driver { font-size:11px; color:var(--text-muted); padding:2px 0; }
.narrative-box { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; margin-bottom:16px; }
.narrative-label { font-size:14px; font-weight:700; color:var(--text-primary); margin-bottom:10px; }
.narrative-text { font-size:13px; color:var(--text-secondary); line-height:1.8; }
.next-steps-box { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; }
.next-steps { padding-left:20px; } .next-steps li { font-size:13px; color:var(--text-secondary); margin-bottom:6px; line-height:1.6; }
.severity { display:inline-block; padding:2px 10px; border-radius:4px; font-size:11px; font-weight:700; letter-spacing:0.5px; text-transform:uppercase; }
.severity.critical { background:var(--severity-critical-bg); color:var(--severity-critical); border:1px solid rgba(218,54,51,0.35); }
.severity.high { background:var(--severity-high-bg); color:var(--severity-high); border:1px solid rgba(253,140,0,0.35); }
.severity.medium { background:var(--severity-medium-bg); color:var(--severity-medium); border:1px solid rgba(158,106,3,0.35); }
.severity.low { background:var(--severity-low-bg); color:var(--severity-low); border:1px solid rgba(35,134,54,0.35); }
.severity.info { background:var(--severity-info-bg); color:var(--severity-info); border:1px solid rgba(31,111,235,0.35); }
.data-table { width:100%; border-collapse:separate; border-spacing:0; font-size:13px; border:1px solid var(--border-color); border-radius:8px; overflow:hidden; }
.data-table th { background:var(--bg-card); color:var(--text-secondary); font-weight:600; text-transform:uppercase; letter-spacing:0.5px; font-size:11px; padding:12px 16px; text-align:left; border-bottom:1px solid var(--border-color); cursor:pointer; user-select:none; }
.data-table th:hover { color:var(--accent-blue); }
.data-table td { padding:10px 16px; border-bottom:1px solid rgba(42,48,112,0.4); vertical-align:top; }
.data-table tr:nth-child(even) td { background:var(--bg-table-row-alt); } .data-table tr:nth-child(odd) td { background:var(--bg-table-row); }
.data-table tr:hover td { background:var(--bg-card-hover); } .data-table tr:last-child td { border-bottom:none; }
.data-table .mono { font-family:'Cascadia Code','Fira Code','Consolas',monospace; font-size:12px; }
.table-tools { display:flex; gap:8px; margin-bottom:14px; align-items:center; }
.table-tools input { flex:1; max-width:400px; padding:8px 12px; border-radius:6px; border:1px solid var(--border-color); background:var(--bg-card); color:var(--text-primary); font-size:13px; }
.table-tools input:focus { outline:none; border-color:var(--accent-light); }
.export-btn { padding:8px 16px; border-radius:6px; border:1px solid var(--border-color); background:var(--bg-card); color:var(--accent-blue); font-size:12px; font-weight:600; cursor:pointer; }
.export-btn:hover { border-color:var(--accent-blue); background:rgba(31,111,235,0.1); }
.count { display:inline-block; margin-left:6px; padding:0 6px; border-radius:10px; font-size:10px; color:var(--text-primary); background:var(--bg-card-hover); border:1px solid var(--border-color); }
.finding-card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; margin-bottom:16px; overflow:hidden; transition:border-color 0.2s; }
.finding-card:hover { border-color:var(--accent-blue); }
.finding-card .fc-header { display:flex; align-items:center; gap:12px; padding:16px 20px; cursor:pointer; user-select:none; }
.finding-card .fc-header:hover { background:var(--bg-card-hover); }
.finding-card .fc-title { flex:1; font-weight:600; font-size:14px; }
.finding-card .fc-meta { display:flex; gap:16px; font-size:12px; color:var(--text-muted); }
.finding-card .fc-body { padding:0 20px 16px; display:none; }
.finding-card.open .fc-body { display:block; }
.finding-card .fc-desc { color:var(--text-secondary); font-size:13px; line-height:1.7; margin-bottom:12px; }
.finding-card .fc-artifacts { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px; }
.finding-card .fc-artifact-tag { background:rgba(46,160,67,0.12); border:1px solid rgba(46,160,67,0.28); border-radius:4px; padding:2px 8px; font-size:11px; color:var(--accent-light); }
.finding-card .fc-file-list { max-height:250px; overflow-y:auto; font-size:12px; font-family:'Cascadia Code','Fira Code','Consolas',monospace; background:var(--bg-primary); border-radius:6px; padding:12px; }
.finding-card .fc-file-item { padding:3px 0; color:var(--text-secondary); border-bottom:1px solid rgba(42,48,112,0.3); }
.finding-card .fc-file-item:last-child { border-bottom:none; }
.finding-card .fc-file-item .tag { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:600; margin-right:6px; background:rgba(46,160,67,0.15); color:var(--accent-light); }
.fc-type-badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; background:rgba(31,111,235,0.12); color:var(--accent-blue); border:1px solid rgba(31,111,235,0.25); margin-bottom:10px; }
.fc-chevron { font-size:14px; color:var(--text-muted); transition:transform 0.2s; }
.finding-card.open .fc-chevron { transform:rotate(90deg); }
.findings-tools { display:flex; justify-content:flex-end; margin:0 0 14px; }
.findings-tools input { width:320px; max-width:100%; padding:8px 12px; border-radius:6px; border:1px solid var(--border-color); background:var(--bg-card); color:var(--text-primary); font-size:13px; }
.findings-tools input:focus { outline:none; border-color:var(--accent-light); box-shadow:0 0 0 2px rgba(46,160,67,0.2); }
.conf-bar { display:inline-flex; align-items:center; gap:6px; }
.conf-bar .bar { width:60px; height:6px; background:rgba(255,255,255,0.08); border-radius:3px; overflow:hidden; }
.conf-bar .bar .fill { height:100%; border-radius:3px; background:var(--accent-blue); }
.timeline-container { position:relative; padding:20px 0; }
.timeline-controls { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tl-filter-btn { padding:6px 14px; border-radius:6px; border:1px solid var(--border-color); background:var(--bg-card); color:var(--text-secondary); font-size:12px; font-weight:600; cursor:pointer; transition:all 0.15s; }
.tl-filter-btn:hover { border-color:var(--accent-blue); color:var(--accent-blue); }
.tl-filter-btn.active { background:var(--accent); border-color:var(--accent); color:#fff; }
.tl-filter-btn .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }
.timeline-track { position:relative; padding-left:40px; max-height:700px; overflow-y:auto; }
.timeline-track::before { content:''; position:absolute; left:18px; top:0; bottom:0; width:2px; background:linear-gradient(180deg,var(--accent-light),var(--accent),var(--accent-light)); opacity:0.4; }
.tl-event { position:relative; margin-bottom:6px; padding:10px 16px; background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; transition:all 0.15s; }
.tl-event:hover { border-color:var(--accent-blue); transform:translateX(4px); }
.tl-event::before { content:''; position:absolute; left:-28px; top:16px; width:12px; height:12px; border-radius:50%; border:2px solid; background:var(--bg-primary); }
.tl-event.cat-usb::before { border-color:var(--tl-usb); box-shadow:0 0 8px rgba(218,54,51,0.35); }
.tl-event.cat-file::before { border-color:var(--tl-file); box-shadow:0 0 8px rgba(31,111,235,0.35); }
.tl-event.cat-exec::before { border-color:var(--tl-exec); box-shadow:0 0 8px rgba(253,140,0,0.35); }
.tl-event.cat-user::before { border-color:var(--tl-user); box-shadow:0 0 8px rgba(46,160,67,0.35); }
.tl-event.cat-driver::before { border-color:var(--tl-driver); box-shadow:0 0 8px rgba(139,148,158,0.3); }
.tl-event .tl-time { font-size:11px; color:var(--text-muted); font-family:'Cascadia Code','Fira Code',monospace; }
.tl-event .tl-type { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; margin:2px 0; }
.tl-event.cat-usb .tl-type { color:var(--tl-usb); } .tl-event.cat-file .tl-type { color:var(--tl-file); }
.tl-event.cat-exec .tl-type { color:var(--tl-exec); } .tl-event.cat-user .tl-type { color:var(--tl-user); }
.tl-event.cat-driver .tl-type { color:var(--tl-driver); }
.tl-event .tl-desc { font-size:13px; color:var(--text-secondary); }
.tl-event .tl-detail { margin-top:4px; font-size:11px; color:var(--text-muted); font-family:'Cascadia Code','Fira Code',monospace; word-break:break-all; }
.tl-event .tl-source { font-size:10px; color:var(--text-muted); margin-top:4px; }
.tl-date-group { font-size:13px; font-weight:700; color:var(--accent-light); margin:16px 0 8px -10px; padding:4px 12px; background:rgba(46,160,67,0.08); border-radius:6px; display:inline-block; }
.tl-load-more { display:block; margin:16px auto; padding:8px 24px; background:var(--bg-card); border:1px solid var(--border-color); border-radius:6px; color:var(--accent-blue); font-size:13px; font-weight:600; cursor:pointer; }
.tl-load-more:hover { border-color:var(--accent-light); background:rgba(46,160,67,0.12); }
.tl-hidden { display:none; }
.timeline-overview { border:1px solid var(--border-color); border-radius:8px; background:var(--bg-secondary); padding:8px; margin-bottom:16px; overflow-x:auto; }
.timeline-overview svg { width:100%; min-width:980px; height:190px; display:block; }
.timeline-overview .label { fill:var(--text-secondary); font-size:11px; font-family:'SF Mono','Fira Code',monospace; }
.timeline-overview .axis { stroke:var(--border-color); stroke-width:1; }
.timeline-overview .guide { stroke:rgba(139,148,158,0.25); stroke-width:1; stroke-dasharray:3 3; }
.timeline-overview .density { fill:rgba(46,160,67,0.14); stroke:var(--accent-light); stroke-width:1.5; }
.timeline-overview .marker { stroke:var(--bg-primary); stroke-width:1; opacity:0.96; }
.usb-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(380px,1fr)); gap:16px; }
.usb-card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px; transition:border-color 0.2s; }
.usb-card:hover { border-color:var(--accent-purple); }
.usb-card.suspicious { border-color:var(--severity-high); border-width:2px; }
.usb-card .usb-name { font-size:16px; font-weight:700; margin-bottom:4px; }
.usb-card .usb-serial { font-size:12px; color:var(--text-muted); font-family:'Cascadia Code','Fira Code',monospace; margin-bottom:12px; }
.usb-card .usb-detail { display:grid; grid-template-columns:130px 1fr; gap:4px 12px; font-size:12px; }
.usb-card .usb-detail .lbl { color:var(--text-muted); font-weight:600; } .usb-card .usb-detail .val { color:var(--text-secondary); }
.serial-flags { margin-top:10px; padding:6px 10px; background:var(--severity-high-bg); border:1px solid rgba(253,140,0,0.3); border-radius:6px; font-size:11px; color:var(--severity-high); font-weight:600; }
.risk-meter { display:flex; align-items:center; gap:12px; padding:20px 24px; background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; margin-bottom:24px; }
.risk-meter .risk-label { font-size:13px; font-weight:600; color:var(--text-secondary); white-space:nowrap; }
.risk-meter .risk-bar { flex:1; height:12px; background:rgba(255,255,255,0.06); border-radius:6px; overflow:hidden; }
.risk-meter .risk-fill { height:100%; border-radius:6px; }
.risk-meter .risk-score { font-size:22px; font-weight:700; white-space:nowrap; }
.artifact-coverage-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:12px; margin-bottom:16px; }
.artifact-coverage-card { display:flex; align-items:center; gap:12px; background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:14px; }
.artifact-coverage-card.not-found { border-color:var(--severity-high); background:var(--severity-high-bg); }
.artifact-icon { font-size:24px; }
.artifact-info { flex:1; }
.artifact-name { font-size:13px; font-weight:700; color:var(--text-primary); }
.artifact-detail { font-size:11px; color:var(--text-secondary); }
.artifact-patterns { font-size:10px; color:var(--text-muted); font-family:monospace; }
.missing-warning { margin-top:16px; padding:14px 16px; background:var(--severity-high-bg); border:1px solid rgba(253,140,0,0.3); border-radius:8px; font-size:13px; color:var(--severity-high); }
::-webkit-scrollbar { width:6px; } ::-webkit-scrollbar-track { background:var(--bg-primary); }
::-webkit-scrollbar-thumb { background:var(--border-color); border-radius:3px; } ::-webkit-scrollbar-thumb:hover { background:var(--accent-blue); }
.report-footer { text-align:center; padding:24px; color:var(--text-muted); font-size:12px; border-top:1px solid var(--border-color); margin-top:40px; }
"#
}

fn html_javascript() -> &'static str {
    r#"
<script>
function filterTimeline(cat,btn){
    document.querySelectorAll('.tl-filter-btn').forEach(b=>b.classList.remove('active'));
    if(btn)btn.classList.add('active');
    const ev=document.querySelectorAll('.tl-event'),dg=document.querySelectorAll('.tl-date-group');
    const loaded=!document.getElementById('tl-load-more')||document.getElementById('tl-load-more').style.display==='none';
    if(cat==='all'){ev.forEach(el=>{if(!el.classList.contains('tl-extra')||loaded)el.style.display='';});dg.forEach(el=>el.style.display='');}
    else{ev.forEach(el=>{const ok=el.dataset.cat===cat&&(!el.classList.contains('tl-extra')||loaded);el.style.display=ok?'':'none';});
    dg.forEach(el=>{let n=el.nextElementSibling,v=false;while(n&&!n.classList.contains('tl-date-group')){if(n.classList.contains('tl-event')&&n.style.display!=='none'){v=true;break;}n=n.nextElementSibling;}el.style.display=v?'':'none';});}
}
function showAllTimeline(){document.querySelectorAll('.tl-extra').forEach(el=>{el.classList.remove('tl-hidden');el.style.display='';});const b=document.getElementById('tl-load-more');if(b)b.style.display='none';}
document.querySelectorAll('.nav-bar a').forEach(link=>{link.addEventListener('click',function(e){e.preventDefault();const t=document.querySelector(this.getAttribute('href'));if(t)t.scrollIntoView({behavior:'smooth',block:'start'});document.querySelectorAll('.nav-bar a').forEach(l=>l.classList.remove('active'));this.classList.add('active');});});
const secs=document.querySelectorAll('.section'),navs=document.querySelectorAll('.nav-bar a');
window.addEventListener('scroll',()=>{let c='';secs.forEach(s=>{if(window.scrollY>=s.offsetTop-80)c=s.getAttribute('id');});navs.forEach(l=>{l.classList.remove('active');if(l.getAttribute('href')==='#'+c)l.classList.add('active');});});
const fs=document.getElementById('findings-search');
if(fs)fs.addEventListener('input',function(){const q=this.value.toLowerCase().trim();document.querySelectorAll('#findings .finding-card').forEach(c=>{c.style.display=(!q||c.textContent.toLowerCase().includes(q))?'':'none';});});

// Table search
const ts=document.getElementById('table-search');
if(ts)ts.addEventListener('input',function(){const q=this.value.toLowerCase().trim();document.querySelectorAll('#event-table tbody tr').forEach(r=>{r.style.display=(!q||r.textContent.toLowerCase().includes(q))?'':'none';});});

// Table sorting
let sortDir={};
function sortTable(col){const tb=document.getElementById('event-table').querySelector('tbody');const rows=Array.from(tb.querySelectorAll('tr'));sortDir[col]=!sortDir[col];rows.sort((a,b)=>{const at=a.cells[col]?.textContent||'',bt=b.cells[col]?.textContent||'';return sortDir[col]?at.localeCompare(bt):bt.localeCompare(at);});rows.forEach(r=>tb.appendChild(r));}

// Export CSV
function exportTableCSV(){const t=document.getElementById('event-table');let csv='';const rows=t.querySelectorAll('tr');rows.forEach(r=>{const cols=r.querySelectorAll('td,th');const row=[];cols.forEach(c=>row.push('"'+c.textContent.replace(/"/g,'""').trim()+'"'));csv+=row.join(',')+'\n';});const b=new Blob([csv],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='event_log.csv';a.click();}

// Export JSON
function exportTableJSON(){const t=document.getElementById('event-table');const headers=[];t.querySelectorAll('th').forEach(h=>headers.push(h.textContent.trim()));const data=[];t.querySelectorAll('tbody tr').forEach(r=>{const obj={};r.querySelectorAll('td').forEach((c,i)=>obj[headers[i]||i]=c.textContent.trim());data.push(obj);});const b=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='event_log.json';a.click();}
</script>
"#
}

/// Compute risk score factoring in sensitivity, corroboration, volume, time-of-day
fn compute_risk_score(findings: &[CorrelatedFinding], context: &AnalysisContext) -> u32 {
    if findings.is_empty() { return 0; }
    let mut score = 0.0_f64;

    // Severity-weighted score
    for f in findings {
        let base = match f.severity { Severity::Critical => 25.0, Severity::High => 15.0, Severity::Medium => 8.0, Severity::Low => 3.0, Severity::Info => 1.0 };
        let corrob_mult = 1.0 + (f.corroboration_count as f64 * 0.1).min(0.5);
        score += base * f.confidence * corrob_mult;
    }

    // Volume factor
    if context.data_volume_estimate > 104_857_600 { score += 10.0; } // >100MB
    else if context.data_volume_estimate > 10_485_760 { score += 5.0; } // >10MB

    // Off-hours factor
    let has_off_hours = findings.iter().any(|f| f.finding_type == crate::models::FindingType::OffHoursActivity);
    if has_off_hours { score += 8.0; }

    // Anti-forensics escalation
    let has_af = findings.iter().any(|f| f.finding_type == crate::models::FindingType::AntiForensicTool || f.finding_type == crate::models::FindingType::Timestomping);
    if has_af { score += 12.0; }

    (score / 2.0).min(100.0) as u32
}

fn timeline_event_category(event_type: &str) -> &'static str {
    let lower = event_type.to_lowercase();
    if lower.contains("usb") { "usb" }
    else if lower.contains("file") || lower.contains("folder") || lower.contains("renamed") { "file" }
    else if lower.contains("executed") || lower.contains("application") { "exec" }
    else if lower.contains("user") || lower.contains("logon") || lower.contains("logoff") { "user" }
    else if lower.contains("driver") { "driver" }
    else { "file" }
}

fn timeline_category_color(category: &str) -> &'static str {
    match category { "usb"=>"#da3633", "file"=>"#1f6feb", "exec"=>"#fd8c00", "user"=>"#2ea043", "driver"=>"#8b949e", _=>"#1f6feb" }
}

fn generate_timeline_overview_svg(timeline: &[TimelineEvent]) -> String {
    if timeline.is_empty() {
        return "<svg viewBox=\"0 0 1100 190\" role=\"img\"><text x=\"24\" y=\"95\" class=\"label\">No timeline events</text></svg>".into();
    }
    let (w, left, right, base_y) = (1100.0_f64, 40.0_f64, 30.0_f64, 148.0_f64);
    let inner_w = w - left - right;
    let (mut min_ts, mut max_ts) = (timeline[0].timestamp, timeline[0].timestamp);
    for e in timeline { if e.timestamp < min_ts { min_ts = e.timestamp; } if e.timestamp > max_ts { max_ts = e.timestamp; } }
    let total_ms = (max_ts - min_ts).num_milliseconds().max(1) as f64;

    let bc = usize::min(48, usize::max(8, timeline.len() / 2));
    let mut buckets = vec![0usize; bc];
    for e in timeline {
        let mut idx = (((e.timestamp - min_ts).num_milliseconds().max(0) as f64 / total_ms) * ((bc - 1) as f64)).round() as usize;
        if idx >= bc { idx = bc - 1; }
        buckets[idx] += 1;
    }
    let mb = *buckets.iter().max().unwrap_or(&1) as f64;
    let mut dp = String::new();
    for (i, c) in buckets.iter().enumerate() {
        let x = left + (i as f64 / (bc.saturating_sub(1) as f64)) * inner_w;
        let y = base_y - ((*c as f64 / mb) * 62.0);
        dp.push_str(&format!("{:.1},{:.1} ", x, y));
    }

    let mut circles = String::new();
    let mut stacks: BTreeMap<(i32, &'static str), usize> = BTreeMap::new();
    let mut cat_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for e in timeline {
        let cat = timeline_event_category(&e.event_type.to_string());
        *cat_counts.entry(cat).or_insert(0) += 1;
        let x = left + ((e.timestamp - min_ts).num_milliseconds().max(0) as f64 / total_ms) * inner_w;
        let mut y = match cat { "usb"=>34.0, "file"=>56.0, "exec"=>78.0, "user"=>100.0, "driver"=>122.0, _=>56.0 };
        let bk = ((x / w) * 1600.0).round() as i32;
        let si = stacks.entry((bk, cat)).or_insert(0);
        y -= (*si as f64).min(4.0) * 4.0;
        *si += 1;
        let label = html_escape(&e.description);
        circles.push_str(&format!("<circle class=\"marker\" cx=\"{:.1}\" cy=\"{:.1}\" r=\"3.2\" fill=\"{}\"><title>{}</title></circle>", x, y, timeline_category_color(cat), label));
    }

    let mut ticks = String::new();
    for i in 0..=6 {
        let r = i as f64 / 6.0;
        let x = left + r * inner_w;
        let ts = min_ts + chrono::Duration::milliseconds((total_ms * r) as i64);
        ticks.push_str(&format!("<line x1=\"{:.1}\" y1=\"146\" x2=\"{:.1}\" y2=\"154\" class=\"axis\"/><text x=\"{:.1}\" y=\"170\" class=\"label\" text-anchor=\"middle\">{}</text>", x, x, x, ts.format("%m-%d %H:%M")));
    }

    let mut legend = String::new();
    for (i, (k, l)) in [("usb","USB"),("file","File"),("exec","Exec"),("user","User"),("driver","Driver")].iter().enumerate() {
        let x = 40 + i as i32 * 118;
        let c = cat_counts.get(k).copied().unwrap_or(0);
        legend.push_str(&format!("<circle cx=\"{}\" cy=\"16\" r=\"4\" fill=\"{}\"/><text x=\"{}\" y=\"20\" class=\"label\">{} ({})</text>", x, timeline_category_color(k), x + 10, l, c));
    }

    format!("<svg viewBox=\"0 0 1100 190\" role=\"img\"><line x1=\"40\" y1=\"148\" x2=\"1070\" y2=\"148\" class=\"axis\"/><line x1=\"40\" y1=\"86\" x2=\"1070\" y2=\"86\" class=\"guide\"/><polyline points=\"{}\" class=\"density\"/>{}{}<text x=\"40\" y=\"184\" class=\"label\">Events: {} &middot; {} to {}</text>{}</svg>",
        dp, circles, ticks, timeline.len(), min_ts.format("%Y-%m-%d %H:%M:%S"), max_ts.format("%Y-%m-%d %H:%M:%S"), legend)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
