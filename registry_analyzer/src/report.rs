use crate::models::*;

/// Generate a complete HTML report matching the KaliHeker dark theme.
pub fn generate_html(report: &AnalysisReport) -> String {
    let critical = report.count_severity(Severity::Critical);
    let high = report.count_severity(Severity::High);
    let medium = report.count_severity(Severity::Medium);
    let low = report.count_severity(Severity::Low);
    let info = report.count_severity(Severity::Info);
    let total = report.findings.len();

    let high_and_above: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.severity <= Severity::High)
        .collect();

    let mut html = String::with_capacity(64 * 1024);

    // ── Document head ──────────────────────────────────────
    html.push_str(&format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliHeker - Registry Analysis Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #238636;
            --accent-light: #2ea043;
            --alert-bg: #da3633;
            --alert-text: #ffebe9;
            --warning-bg: #9e6a03;
            --warning-text: #fff8c5;
            --notice-bg: #238636;
            --notice-text: #f0f6fc;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }}
        header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 24px;
        }}
        .header-content {{ max-width: 1400px; margin: 0 auto; }}
        .logo {{ display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }}
        .logo-text {{ font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }}
        .logo-text span {{ color: var(--accent-light); }}
        .version {{ font-size: 14px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 12px; border: 1px solid var(--border-color); }}
        .scan-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 16px; }}
        .info-card {{ background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px 16px; }}
        .info-card h3 {{ font-size: 12px; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px; letter-spacing: 0.5px; }}
        .info-card p {{ font-size: 14px; color: var(--text-primary); word-break: break-all; }}
        .score {{ font-size: 18px; font-weight: 700; color: var(--text-primary); }}
        nav {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }}
        .nav-content {{ max-width: 1400px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; }}
        .filter-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{
            padding: 6px 14px; border: 1px solid var(--border-color); border-radius: 20px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s;
        }}
        .filter-btn:hover {{ border-color: var(--accent); }}
        .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
        .filter-btn .count {{ margin-left: 6px; opacity: 0.8; font-size: 0.9em; }}
        .search-box {{ display: flex; align-items: center; gap: 8px; }}
        .search-box input {{
            padding: 8px 14px; border: 1px solid var(--border-color); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; width: 280px;
        }}
        .search-box input:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(46, 160, 67, 0.4); }}
        main {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
        .stats-bar {{
            display: flex; gap: 24px; margin-bottom: 20px; padding: 16px;
            background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }}
        .stat {{ display: flex; align-items: center; gap: 8px; }}
        .stat-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
        .stat-dot.alert {{ background: var(--alert-bg); }}
        .stat-dot.warning {{ background: var(--warning-bg); }}
        .stat-dot.notice {{ background: var(--notice-bg); }}
        .stat-dot.info-dot {{ background: #1f6feb; }}
        .stat-label {{ font-size: 14px; color: var(--text-secondary); }}
        .stat-value {{ font-size: 18px; font-weight: 600; }}
        .finding-card {{
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;
            margin-bottom: 16px; transition: transform 0.2s; border-left: 4px solid var(--border-color);
        }}
        .finding-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
        .finding-card.critical {{ border-left-color: var(--alert-bg); }}
        .finding-card.high {{ border-left-color: #fd8c00; }}
        .finding-card.medium {{ border-left-color: var(--warning-bg); }}
        .finding-card.low {{ border-left-color: var(--notice-bg); }}
        .finding-card.info {{ border-left-color: #1f6feb; }}
        .finding-header {{
            display: flex; align-items: center; gap: 12px; padding: 16px;
            background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); flex-wrap: wrap;
        }}
        .severity-badge {{ padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
        .severity-badge.critical {{ background: var(--alert-bg); color: var(--alert-text); }}
        .severity-badge.high {{ background: #fd8c00; color: #fff; }}
        .severity-badge.medium {{ background: var(--warning-bg); color: var(--warning-text); }}
        .severity-badge.low {{ background: var(--notice-bg); color: var(--notice-text); }}
        .severity-badge.info {{ background: #1f6feb; color: #fff; }}
        .finding-title {{
            flex: 1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; font-weight: 600;
            color: var(--accent-light); word-break: break-all;
        }}
        .finding-body {{ padding: 16px; }}
        .finding-description {{ margin-bottom: 16px; color: var(--text-primary); font-size: 14px; }}
        .evidence-box {{
            background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;
            margin-bottom: 12px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; overflow-x: auto;
        }}
        .evidence-line {{ margin-bottom: 4px; }}
        .evidence-label {{ color: var(--text-secondary); margin-right: 8px; }}
        .metadata-tags {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
        .meta-tag {{
            background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px;
            padding: 2px 10px; font-size: 11px; color: var(--text-secondary);
        }}
        .meta-tag strong {{ color: var(--text-primary); }}
        .mitre-link {{ color: var(--accent-light); text-decoration: none; }}
        .mitre-link:hover {{ text-decoration: underline; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: var(--bg-tertiary); color: var(--accent-light); font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: rgba(255,255,255,0.03); }}
        code {{
            background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px;
        }}
        footer {{
            text-align: center; padding: 40px 20px; color: var(--text-secondary); font-size: 13px;
            border-top: 1px solid var(--border-color); margin-top: 40px;
        }}
        .category-header {{
            display: flex; align-items: center; gap: 12px; padding: 16px 20px;
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; margin-bottom: 16px; border-left: 4px solid var(--accent);
            cursor: pointer;
        }}
        .category-header h3 {{ flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0; }}
        .category-count {{ color: var(--text-secondary); font-size: 13px; background: var(--bg-tertiary); padding: 4px 10px; border-radius: 12px; }}
        .icon {{
            width: 14px; height: 14px; border-radius: 50%; display: inline-block;
            background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), var(--accent-light));
            box-shadow: 0 0 8px rgba(46, 160, 67, 0.4);
        }}
        .summary-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px; margin-bottom: 24px;
        }}
        .summary-card {{
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; padding: 16px; text-align: center;
        }}
        .summary-card .number {{ font-size: 32px; font-weight: 700; }}
        .summary-card .label {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }}
        .number.crit {{ color: var(--alert-bg); }}
        .number.high-c {{ color: #fd8c00; }}
        .number.med {{ color: var(--warning-bg); }}
        .number.low-c {{ color: var(--notice-bg); }}
        .number.info-c {{ color: #1f6feb; }}
        .quick-ref {{
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 10px; padding: 18px; margin-bottom: 20px;
        }}
        .quick-ref h3 {{ font-size: 16px; font-weight: 600; margin-bottom: 12px; }}
        .quick-ref-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px;
        }}
        .quick-ref-item {{
            background: var(--bg-tertiary); border: 1px solid var(--border-color);
            border-radius: 8px; padding: 12px;
        }}
        .quick-ref-title {{ font-size: 12px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }}
        .quick-ref-path {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; color: var(--accent-light); margin-top: 6px; }}
        .quick-ref-note {{ font-size: 12px; color: var(--text-secondary); margin-top: 8px; }}
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <div class="logo">
                <div class="logo-text">KALI<span>HEKER</span></div>
                <div class="version">Registry Analyzer v1.0</div>
            </div>
            <div class="scan-info">
                <div class="info-card"><h3>System Name</h3><p>{system_name}</p></div>
                <div class="info-card"><h3>Export Date</h3><p>{export_date}</p></div>
                <div class="info-card"><h3>Report Generated</h3><p>{report_date}</p></div>
                <div class="info-card"><h3>Registry Stats</h3><p>{total_hives} Hives &middot; {total_keys} Keys &middot; {total_values} Values</p></div>
                <div class="info-card"><h3>Total Findings</h3><p>Critical: {critical} | High: {high} | Medium: {medium} | Low: {low} | Info: {info}</p></div>
            </div>
        </div>
    </header>
"#,
        system_name = e(&report.system_name),
        export_date = e(&report.export_date),
        report_date = e(&report.report_date),
        total_hives = report.total_hives,
        total_keys = report.total_keys,
        total_values = report.total_values,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
    ));

    // ── Navigation / filters ──────────────────────────────
    html.push_str(&format!(r#"
    <nav>
        <div class="nav-content">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterAll(this)">All <span class="count">({total})</span></button>
                <button class="filter-btn" onclick="filterBy(this,'critical')">Critical <span class="count">({critical})</span></button>
                <button class="filter-btn" onclick="filterBy(this,'high')">High <span class="count">({high})</span></button>
                <button class="filter-btn" onclick="filterBy(this,'medium')">Medium <span class="count">({medium})</span></button>
                <button class="filter-btn" onclick="filterBy(this,'low')">Low <span class="count">({low})</span></button>
                <button class="filter-btn" onclick="filterBy(this,'info')">Info <span class="count">({info})</span></button>
            </div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search findings..." oninput="searchFindings(this.value)">
            </div>
        </div>
    </nav>
"#,
        total = total, critical = critical, high = high, medium = medium, low = low, info = info
    ));

    // ── Main content ──────────────────────────────────────
    html.push_str("    <main>\n");
    html.push_str(r#"
        <div class="quick-ref">
            <h3>Quick Reference: High-Value Registry Locations</h3>
            <div class="quick-ref-grid">
                <div class="quick-ref-item">
                    <div class="quick-ref-title">Autostart (Run / RunOnce)</div>
                    <div class="quick-ref-path">HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</div>
                    <div class="quick-ref-path">HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</div>
                    <div class="quick-ref-note">Common persistence locations for malware.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">Services</div>
                    <div class="quick-ref-path">SYSTEM\\CurrentControlSet\\Services\\*</div>
                    <div class="quick-ref-note">Service image paths and start types.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">Winlogon</div>
                    <div class="quick-ref-path">SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon</div>
                    <div class="quick-ref-note">Check Shell and Userinit hijacks.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">IFEO Debugger</div>
                    <div class="quick-ref-path">SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options</div>
                    <div class="quick-ref-note">Used for sticky-keys style backdoors.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">AppInit DLLs</div>
                    <div class="quick-ref-path">SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows</div>
                    <div class="quick-ref-note">DLLs injected into user processes.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">BAM / DAM Execution</div>
                    <div class="quick-ref-path">SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings</div>
                    <div class="quick-ref-note">Per-user execution timestamps.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">USB History</div>
                    <div class="quick-ref-path">SYSTEM\\CurrentControlSet\\Enum\\USBSTOR</div>
                    <div class="quick-ref-note">USB devices connected to the system.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">Network Profiles</div>
                    <div class="quick-ref-path">SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles</div>
                    <div class="quick-ref-note">Wireless and wired network history.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">RunMRU (Win+R)</div>
                    <div class="quick-ref-path">NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU</div>
                    <div class="quick-ref-note">User-typed commands.</div>
                </div>
                <div class="quick-ref-item">
                    <div class="quick-ref-title">Typed URLs</div>
                    <div class="quick-ref-path">NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs</div>
                    <div class="quick-ref-note">Directly typed browser URLs.</div>
                </div>
            </div>
        </div>
"#);

    // Stats bar
    html.push_str(&format!(r#"
        <div class="stats-bar">
            <div class="stat"><div class="stat-dot alert"></div> <span class="stat-label">Critical:</span> <span class="stat-value">{critical}</span></div>
            <div class="stat"><div class="stat-dot" style="background:#fd8c00"></div> <span class="stat-label">High:</span> <span class="stat-value">{high}</span></div>
            <div class="stat"><div class="stat-dot warning"></div> <span class="stat-label">Medium:</span> <span class="stat-value">{medium}</span></div>
            <div class="stat"><div class="stat-dot notice"></div> <span class="stat-label">Low:</span> <span class="stat-value">{low}</span></div>
            <div class="stat"><div class="stat-dot info-dot"></div> <span class="stat-label">Info:</span> <span class="stat-value">{info}</span></div>
        </div>
"#, critical = critical, high = high, medium = medium, low = low, info = info));

    // Summary cards
    html.push_str(&format!(r#"
        <div class="summary-grid">
            <div class="summary-card"><div class="number crit">{critical}</div><div class="label">Critical</div></div>
            <div class="summary-card"><div class="number high-c">{high}</div><div class="label">High</div></div>
            <div class="summary-card"><div class="number med">{medium}</div><div class="label">Medium</div></div>
            <div class="summary-card"><div class="number low-c">{low}</div><div class="label">Low</div></div>
            <div class="summary-card"><div class="number info-c">{info}</div><div class="label">Info</div></div>
        </div>
"#, critical = critical, high = high, medium = medium, low = low, info = info));

    // ── Critical & High finding cards ─────────────────────
    if !high_and_above.is_empty() {
        html.push_str(&format!(r#"
        <div class="category-header" style="border-left-color: var(--alert-bg);">
            <span class="icon"></span>
            <h3>&#x1F6A8; Critical &amp; High Severity Findings</h3>
            <span class="category-count">{} findings</span>
        </div>
"#, high_and_above.len()));

        for f in &high_and_above {
            html.push_str(&render_finding_card(f));
        }
    }

    // ── Medium findings cards ─────────────────────────────
    let medium_findings: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.severity == Severity::Medium)
        .collect();

    if !medium_findings.is_empty() {
        html.push_str(&format!(r#"
        <div class="category-header" style="border-left-color: var(--warning-bg);">
            <span class="icon"></span>
            <h3>&#x26A0;&#xFE0F; Medium Severity Findings</h3>
            <span class="category-count">{} findings</span>
        </div>
"#, medium_findings.len()));

        for f in &medium_findings {
            html.push_str(&render_finding_card(f));
        }
    }

    // ── Low findings ──────────────────────────────────────
    let low_findings: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.severity == Severity::Low)
        .collect();

    if !low_findings.is_empty() {
        html.push_str(&format!(r#"
        <div class="category-header" style="border-left-color: var(--notice-bg);">
            <span class="icon"></span>
            <h3>&#x2139;&#xFE0F; Low Severity Findings</h3>
            <span class="category-count">{} findings</span>
        </div>
"#, low_findings.len()));

        for f in &low_findings {
            html.push_str(&render_finding_card(f));
        }
    }

    // ── Info findings ─────────────────────────────────────
    let info_findings: Vec<&Finding> = report.findings.iter()
        .filter(|f| f.severity == Severity::Info)
        .collect();

    if !info_findings.is_empty() {
        html.push_str(&format!(r#"
        <div class="category-header" style="border-left-color: #1f6feb;">
            <span class="icon"></span>
            <h3>&#x1F4CB; Informational Findings</h3>
            <span class="category-count">{} findings</span>
        </div>
"#, info_findings.len()));

        for f in &info_findings {
            html.push_str(&render_finding_card(f));
        }
    }

    // ── Summary table ─────────────────────────────────────
    html.push_str(&format!(r#"
        <div class="category-header">
            <span class="icon"></span>
            <h3>&#x1F4CB; All Findings</h3>
            <span class="category-count">{total} total</span>
        </div>
        
        <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Category</th>
                        <th>Description</th>
                        <th>MITRE ATT&amp;CK</th>
                    </tr>
                </thead>
                <tbody>
"#, total = total));

    for f in &report.findings {
        let mitre_cell = if let (Some(id), Some(url)) = (&f.mitre_id, &f.mitre_url) {
            format!(r#"<a class="mitre-link" href="{}" target="_blank">{}</a>"#, e(url), e(id))
        } else {
            "-".into()
        };
        html.push_str(&format!(
            r#"                    <tr class="finding-row {sev_class}">
                        <td><span class="severity-badge {sev_class}">{sev}</span></td>
                        <td><code>{title}</code></td>
                        <td>{category}</td>
                        <td>{desc}</td>
                        <td>{mitre}</td>
                    </tr>
"#,
            sev_class = f.severity.css_class(),
            sev = f.severity,
            title = e(&f.title),
            category = e(&f.category),
            desc = e(&truncate_str(&f.description, 100)),
            mitre = mitre_cell,
        ));
    }

    html.push_str(r#"                </tbody>
            </table>
        </div>
"#);

    // ── Close main ────────────────────────────────────────
    html.push_str("    </main>\n");

    // ── Footer ────────────────────────────────────────────
    html.push_str(r#"
    <footer>
        <p>Generated by <strong>KaliHeker Registry Analyzer</strong></p>
        <p>Windows Registry forensic analysis tool</p>
    </footer>
"#);

    // ── JavaScript ────────────────────────────────────────
    html.push_str(r#"
    <script>
        let currentFilter = 'all';

        function filterAll(btn) {
            currentFilter = 'all';
            setActiveBtn(btn);
            applyFilters();
        }

        function filterBy(btn, level) {
            currentFilter = level;
            setActiveBtn(btn);
            applyFilters();
        }

        function setActiveBtn(btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        }

        function applyFilters() {
            document.querySelectorAll('.finding-card').forEach(card => {
                const level = ['critical','high','medium','low','info'].find(c => card.classList.contains(c)) || 'info';
                card.style.display = (currentFilter === 'all' || level === currentFilter) ? '' : 'none';
            });
            document.querySelectorAll('.finding-row').forEach(row => {
                const badge = row.querySelector('.severity-badge');
                if (!badge) return;
                const level = ['critical','high','medium','low','info'].find(c => badge.classList.contains(c)) || 'info';
                row.style.display = (currentFilter === 'all' || level === currentFilter) ? '' : 'none';
            });
        }

        function searchFindings(query) {
            const q = query.toLowerCase();
            document.querySelectorAll('.finding-card').forEach(card => {
                card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
            document.querySelectorAll('.finding-row').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        }

        // Collapsible category headers
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', function() {
                let sibling = this.nextElementSibling;
                while (sibling && !sibling.classList.contains('category-header')) {
                    if (sibling.style.display === 'none') {
                        sibling.style.display = '';
                    } else {
                        sibling.style.display = 'none';
                    }
                    sibling = sibling.nextElementSibling;
                }
            });
        });
    </script>
</body>
</html>
"#);

    html
}

// ─────────────────────────────────────────────────────────────
// Render a single finding card
// ─────────────────────────────────────────────────────────────

fn render_finding_card(f: &Finding) -> String {
    let mut card = String::new();

    card.push_str(&format!(
        r#"        <div class="finding-card {sev_class}">
            <div class="finding-header">
                <span class="severity-badge {sev_class}">{sev}</span>
                <span class="finding-title">{title}</span>
            </div>
            <div class="finding-body">
                <div class="finding-description">{desc}</div>
"#,
        sev_class = f.severity.css_class(),
        sev = f.severity,
        title = e(&f.title),
        desc = e(&f.description),
    ));

    // Evidence box
    if !f.evidence.is_empty() {
        card.push_str("                <div class=\"evidence-box\">\n");
        for ev in &f.evidence {
            card.push_str(&format!(
                "                    <div class=\"evidence-line\"><span class=\"evidence-label\">[{}]</span> {}</div>\n",
                e(&ev.label), e(&ev.value)
            ));
        }
        card.push_str("                </div>\n");
    }

    // Metadata tags
    card.push_str("<div class=\"metadata-tags\">");
    for (k, v) in &f.tags {
        card.push_str(&format!(
            "<div class=\"meta-tag\">{}: <strong>{}</strong></div>",
            e(k), e(v)
        ));
    }
    if let (Some(id), Some(url)) = (&f.mitre_id, &f.mitre_url) {
        card.push_str(&format!(
            "<div class=\"meta-tag\">MITRE: <a class=\"mitre-link\" href=\"{}\" target=\"_blank\"><strong>{}</strong></a></div>",
            e(url), e(id)
        ));
    }
    card.push_str("</div>\n");

    card.push_str("            </div>\n        </div>\n\n");
    card
}

// ─────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────

fn e(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
