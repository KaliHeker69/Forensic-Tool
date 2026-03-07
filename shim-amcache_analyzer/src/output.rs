//! Output formatters for analysis reports

use anyhow::Result;
use serde_json;

use crate::analysis::{AnalysisReport, RiskLevel};
use crate::OutputFormat;

/// Output formatter
pub struct OutputFormatter {
    format: OutputFormat,
    pretty: bool,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat, pretty: bool) -> Self {
        Self { format, pretty }
    }

    /// Format the full report
    pub fn format_full(&self, report: &AnalysisReport, min_risk: Option<RiskLevel>) -> Result<String> {
        match self.format {
            OutputFormat::Json => self.format_json(report),
            OutputFormat::Text => self.format_text(report, min_risk),
            OutputFormat::Csv => self.format_csv_full(report),
            OutputFormat::Html => self.format_html_full(report, min_risk),
        }
    }

    /// Format only suspicious entries
    pub fn format_suspicious(&self, report: &AnalysisReport) -> Result<String> {
        match self.format {
            OutputFormat::Json => self.format_suspicious_json(report),
            OutputFormat::Text => self.format_suspicious_text(report),
            OutputFormat::Csv => self.format_csv_suspicious(report),
            OutputFormat::Html => self.format_html_suspicious(report),
        }
    }

    fn generate_html_css() -> &'static str {
        r#"<style>
        :root {
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
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 24px;
        }
        .header-content { max-width: 1400px; margin: 0 auto; }
        .logo { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
        .logo-text { font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }
        .logo-text span { color: var(--accent-light); }
        .version { font-size: 14px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 12px; border: 1px solid var(--border-color); }
        .scan-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 16px; }
        .info-card { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px 16px; }
        .info-card h3 { font-size: 12px; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px; letter-spacing: 0.5px; }
        .info-card p { font-size: 14px; color: var(--text-primary); word-break: break-all; }
        .score { font-size: 18px; font-weight: 700; color: var(--text-primary); }
        nav {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .nav-content { max-width: 1400px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; }
        .filter-buttons { display: flex; gap: 8px; flex-wrap: wrap; }
        .filter-btn {
            padding: 6px 14px; border: 1px solid var(--border-color); border-radius: 20px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--accent); }
        .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
        .filter-btn .count { margin-left: 6px; opacity: 0.8; font-size: 0.9em; }
        .search-box { display: flex; align-items: center; gap: 8px; }
        .search-box input {
            padding: 8px 14px; border: 1px solid var(--border-color); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; width: 280px;
        }
        .search-box input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(46, 160, 67, 0.4); }
        main { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-bar {
            display: flex; gap: 24px; margin-bottom: 20px; padding: 16px; flex-wrap: wrap;
            background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);
        }
        .stat { display: flex; align-items: center; gap: 8px; }
        .stat-dot { width: 12px; height: 12px; border-radius: 50%; }
        .stat-dot.alert { background: var(--alert-bg); }
        .stat-dot.warning { background: #fd8c00; }
        .stat-dot.medium { background: var(--warning-bg); }
        .stat-dot.notice { background: var(--notice-bg); }
        .stat-dot.clean { background: #22c55e; }
        .stat-label { font-size: 14px; color: var(--text-secondary); }
        .stat-value { font-size: 18px; font-weight: 600; }
        .finding-card {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;
            margin-bottom: 16px; transition: transform 0.2s; border-left: 4px solid var(--border-color);
        }
        .finding-card:hover { transform: translateY(-2px); border-color: var(--accent); }
        .finding-card.critical { border-left-color: var(--alert-bg); }
        .finding-card.high { border-left-color: #fd8c00; }
        .finding-card.medium { border-left-color: var(--warning-bg); }
        .finding-card.low { border-left-color: var(--notice-bg); }
        .finding-card.clean { border-left-color: #22c55e; }
        .finding-header {
            display: flex; align-items: center; gap: 12px; padding: 16px;
            background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); flex-wrap: wrap;
        }
        .severity-badge { padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .severity-badge.critical { background: var(--alert-bg); color: var(--alert-text); }
        .severity-badge.high { background: #fd8c00; color: #fff; }
        .severity-badge.medium { background: var(--warning-bg); color: var(--warning-text); }
        .severity-badge.low { background: var(--notice-bg); color: var(--notice-text); }
        .severity-badge.clean { background: #22c55e; color: #fff; }
        .finding-title {
            flex: 1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; font-weight: 600;
            color: var(--accent-light); word-break: break-all;
        }
        .finding-body { padding: 16px; }
        .finding-description { margin-bottom: 16px; color: var(--text-primary); font-size: 14px; }
        .evidence-box {
            background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;
            margin-bottom: 12px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; overflow-x: auto;
        }
        .evidence-line { margin-bottom: 4px; }
        .evidence-label { color: var(--text-secondary); margin-right: 8px; }
        .metadata-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
        .meta-tag {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px;
            padding: 2px 10px; font-size: 11px; color: var(--text-secondary);
        }
        .meta-tag strong { color: var(--text-primary); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { background: var(--bg-tertiary); color: var(--accent-light); font-size: 12px; text-transform: uppercase; }
        tr:hover { background: rgba(255,255,255,0.03); }
        code {
            background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px;
        }
        footer {
            text-align: center; padding: 40px 20px; color: var(--text-secondary); font-size: 13px;
            border-top: 1px solid var(--border-color); margin-top: 40px;
        }
        .category-header {
            display: flex; align-items: center; gap: 12px; padding: 16px 20px;
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; margin-bottom: 16px; margin-top: 24px; border-left: 4px solid var(--accent); cursor: pointer;
        }
        .category-header h3 { flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0; }
        .category-count { color: var(--text-secondary); font-size: 13px; background: var(--bg-tertiary); padding: 4px 10px; border-radius: 12px; }
        .icon {
            width: 14px; height: 14px; border-radius: 50%; display: inline-block;
            background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), var(--accent-light));
            box-shadow: 0 0 8px rgba(46, 160, 67, 0.4);
        }
    </style>"#
    }

    fn generate_html_js() -> &'static str {
        r#"<script>
        let currentFilter = 'all';
        
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                const filterText = this.textContent.trim().toLowerCase();
                if (filterText.startsWith('all')) currentFilter = 'all';
                else if (filterText.startsWith('critical')) currentFilter = 'critical';
                else if (filterText.startsWith('high')) currentFilter = 'high';
                else if (filterText.startsWith('medium')) currentFilter = 'medium';
                else if (filterText.startsWith('low')) currentFilter = 'low';
                else if (filterText.startsWith('clean')) currentFilter = 'clean';
                
                applyFilters();
            });
        });
        
        function applyFilters() {
            document.querySelectorAll('.finding-card').forEach(card => {
                const level = card.classList.contains('critical') ? 'critical' :
                             card.classList.contains('high') ? 'high' :
                             card.classList.contains('medium') ? 'medium' :
                             card.classList.contains('low') ? 'low' : 'clean';
                
                if (currentFilter === 'all' || level === currentFilter) {
                    card.style.display = '';
                } else {
                    card.style.display = 'none';
                }
            });
            
            document.querySelectorAll('tbody tr').forEach(row => {
                const badge = row.querySelector('.severity-badge');
                if (!badge) return;
                
                const level = badge.classList.contains('critical') ? 'critical' :
                             badge.classList.contains('high') ? 'high' :
                             badge.classList.contains('medium') ? 'medium' :
                             badge.classList.contains('low') ? 'low' : 'clean';
                
                if (currentFilter === 'all' || level === currentFilter) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                const query = this.value.toLowerCase();
                
                document.querySelectorAll('.finding-card').forEach(card => {
                    const text = card.textContent.toLowerCase();
                    card.style.display = text.includes(query) ? '' : 'none';
                });
                
                document.querySelectorAll('tbody tr').forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            });
        }
        
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
    </script>"#
    }

    fn format_html_full(&self, report: &AnalysisReport, min_risk: Option<RiskLevel>) -> Result<String> {
        let mut output = String::new();

        // Count by risk level
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut clean_count = 0;

        for entry in &report.correlated_entries {
            match entry.risk_level {
                RiskLevel::Critical => critical_count += 1,
                RiskLevel::High => high_count += 1,
                RiskLevel::Medium => medium_count += 1,
                RiskLevel::Low => low_count += 1,
                RiskLevel::Clean => clean_count += 1,
            }
        }

        let total_findings = critical_count + high_count + medium_count + low_count;

        // HTML Head
        output.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        output.push_str("    <meta charset=\"UTF-8\">\n");
        output.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        output.push_str("    <title>KaliHeker - ShimCache & AmCache Analysis Report</title>\n");
        output.push_str(Self::generate_html_css());
        output.push_str("\n</head>\n<body>\n");

        // Header
        output.push_str("    <header>\n        <div class=\"header-content\">\n");
        output.push_str("            <div class=\"logo\">\n");
        output.push_str("                <div class=\"logo-text\">KALI<span>HEKER</span></div>\n");
        output.push_str("                <div class=\"version\">ShimCache & AmCache Analyzer v1.0</div>\n");
        output.push_str("            </div>\n");
        output.push_str("            <div class=\"scan-info\">\n");
        output.push_str(&format!("                <div class=\"info-card\"><h3>Report Generated</h3><p>{}</p></div>\n", report.analysis_time));
        output.push_str(&format!("                <div class=\"info-card\"><h3>ShimCache Entries</h3><div class=\"score\">{}</div></div>\n", report.statistics.total_shimcache));
        output.push_str(&format!("                <div class=\"info-card\"><h3>AmCache Entries</h3><div class=\"score\">{}</div></div>\n", report.statistics.total_amcache));
        output.push_str(&format!("                <div class=\"info-card\"><h3>Total Findings</h3><p>Critical: {} | High: {} | Medium: {} | Low: {}</p></div>\n", 
            critical_count, high_count, medium_count, low_count));
        output.push_str("            </div>\n        </div>\n    </header>\n\n");

        // Navigation
        output.push_str("    <nav>\n        <div class=\"nav-content\">\n            <div class=\"filter-buttons\">\n");
        output.push_str(&format!("                <button class=\"filter-btn active\">All <span class=\"count\">({})</span></button>\n", total_findings));
        output.push_str(&format!("                <button class=\"filter-btn\">Critical <span class=\"count\">({})</span></button>\n", critical_count));
        output.push_str(&format!("                <button class=\"filter-btn\">High <span class=\"count\">({})</span></button>\n", high_count));
        output.push_str(&format!("                <button class=\"filter-btn\">Medium <span class=\"count\">({})</span></button>\n", medium_count));
        output.push_str(&format!("                <button class=\"filter-btn\">Low <span class=\"count\">({})</span></button>\n", low_count));
        output.push_str("            </div>\n");
        output.push_str("            <div class=\"search-box\">\n");
        output.push_str("                <input type=\"text\" id=\"searchInput\" placeholder=\"Search findings...\">\n");
        output.push_str("            </div>\n        </div>\n    </nav>\n\n");

        // Main content
        output.push_str("    <main>\n");

        // Stats bar
        output.push_str("        <div class=\"stats-bar\">\n");
        output.push_str(&format!("            <div class=\"stat\"><div class=\"stat-dot alert\"></div> <span class=\"stat-label\">Critical:</span> <span class=\"stat-value\">{}</span></div>\n", critical_count));
        output.push_str(&format!("            <div class=\"stat\"><div class=\"stat-dot warning\"></div> <span class=\"stat-label\">High:</span> <span class=\"stat-value\">{}</span></div>\n", high_count));
        output.push_str(&format!("            <div class=\"stat\"><div class=\"stat-dot medium\"></div> <span class=\"stat-label\">Medium:</span> <span class=\"stat-value\">{}</span></div>\n", medium_count));
        output.push_str(&format!("            <div class=\"stat\"><div class=\"stat-dot notice\"></div> <span class=\"stat-label\">Low:</span> <span class=\"stat-value\">{}</span></div>\n", low_count));
        output.push_str(&format!("            <div class=\"stat\"><div class=\"stat-dot clean\"></div> <span class=\"stat-label\">Clean:</span> <span class=\"stat-value\">{}</span></div>\n", clean_count));
        output.push_str("        </div>\n\n");

        // Sort suspicious entries by risk level
        let mut sorted_suspicious = report.suspicious_entries.clone();
        sorted_suspicious.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
        
        let filtered: Vec<_> = if let Some(min) = min_risk {
            sorted_suspicious.into_iter().filter(|e| e.risk_level >= min).collect()
        } else {
            sorted_suspicious
        };

        // Critical & High Severity Section
        let critical_high: Vec<_> = filtered.iter()
            .filter(|e| e.risk_level == RiskLevel::Critical || e.risk_level == RiskLevel::High)
            .collect();
        
        if !critical_high.is_empty() {
            output.push_str("        <div class=\"category-header\" style=\"border-left-color: var(--alert-bg);\">\n");
            output.push_str("            <span class=\"icon\"></span>\n");
            output.push_str("            <h3>🚨 Critical & High Severity Findings</h3>\n");
            output.push_str(&format!("            <span class=\"category-count\">{} findings</span>\n", critical_high.len()));
            output.push_str("        </div>\n\n");

            for entry in critical_high.iter().take(50) {
                let level_class = Self::risk_class_name(&entry.risk_level);
                let level_str = entry.risk_level.to_string().to_uppercase();
                let filename = entry.path.split(['\\', '/']).last().unwrap_or(&entry.path);
                
                output.push_str(&format!("        <div class=\"finding-card {}\">\n", level_class));
                output.push_str("            <div class=\"finding-header\">\n");
                output.push_str(&format!("                <span class=\"severity-badge {}\">{}</span>\n", level_class, level_str));
                output.push_str(&format!("                <span class=\"finding-title\">{}</span>\n", Self::escape_html(filename)));
                output.push_str("            </div>\n");
                output.push_str("            <div class=\"finding-body\">\n");
                
                if !entry.risk_indicators.is_empty() {
                    output.push_str(&format!("                <div class=\"finding-description\">{}</div>\n", 
                        Self::escape_html(entry.risk_indicators.first().unwrap_or(&String::new()))));
                }
                
                output.push_str("                <div class=\"evidence-box\">\n");
                output.push_str(&format!("                    <div class=\"evidence-line\"><span class=\"evidence-label\">[path]</span> {}</div>\n", 
                    Self::escape_html(&entry.path)));
                if let Some(ref sha1) = entry.sha1 {
                    output.push_str(&format!("                    <div class=\"evidence-line\"><span class=\"evidence-label\">[sha1]</span> {}</div>\n", sha1));
                }
                output.push_str("                </div>\n");

                output.push_str("                <div class=\"metadata-tags\">\n");
                output.push_str(&format!("                    <div class=\"meta-tag\">ShimCache: <strong>{}</strong></div>\n", 
                    if entry.in_shimcache { "Yes" } else { "No" }));
                output.push_str(&format!("                    <div class=\"meta-tag\">AmCache: <strong>{}</strong></div>\n", 
                    if entry.in_amcache { "Yes" } else { "No" }));
                if let Some(ref company) = entry.company_name {
                    output.push_str(&format!("                    <div class=\"meta-tag\">Publisher: <strong>{}</strong></div>\n", 
                        Self::escape_html(company)));
                }
                if let Some(ref first_run) = entry.first_run_time {
                    output.push_str(&format!("                    <div class=\"meta-tag\">First Run: <strong>{}</strong></div>\n", first_run));
                }
                output.push_str("                </div>\n");
                output.push_str("            </div>\n        </div>\n\n");
            }
        }

        // Medium & Low Severity Section
        let medium_low: Vec<_> = filtered.iter()
            .filter(|e| e.risk_level == RiskLevel::Medium || e.risk_level == RiskLevel::Low)
            .collect();
        
        if !medium_low.is_empty() {
            output.push_str("        <div class=\"category-header\">\n");
            output.push_str("            <span class=\"icon\"></span>\n");
            output.push_str("            <h3>⚠️ Medium & Low Severity Findings</h3>\n");
            output.push_str(&format!("            <span class=\"category-count\">{} findings</span>\n", medium_low.len()));
            output.push_str("        </div>\n\n");

            for entry in medium_low.iter().take(100) {
                let level_class = Self::risk_class_name(&entry.risk_level);
                let level_str = entry.risk_level.to_string().to_uppercase();
                let filename = entry.path.split(['\\', '/']).last().unwrap_or(&entry.path);
                
                output.push_str(&format!("        <div class=\"finding-card {}\">\n", level_class));
                output.push_str("            <div class=\"finding-header\">\n");
                output.push_str(&format!("                <span class=\"severity-badge {}\">{}</span>\n", level_class, level_str));
                output.push_str(&format!("                <span class=\"finding-title\">{}</span>\n", Self::escape_html(filename)));
                output.push_str("            </div>\n");
                output.push_str("            <div class=\"finding-body\">\n");
                
                if !entry.risk_indicators.is_empty() {
                    output.push_str(&format!("                <div class=\"finding-description\">{}</div>\n", 
                        Self::escape_html(&entry.risk_indicators.join("; "))));
                }
                
                output.push_str("                <div class=\"evidence-box\">\n");
                output.push_str(&format!("                    <div class=\"evidence-line\"><span class=\"evidence-label\">[path]</span> {}</div>\n", 
                    Self::escape_html(&entry.path)));
                output.push_str("                </div>\n");

                output.push_str("                <div class=\"metadata-tags\">\n");
                output.push_str(&format!("                    <div class=\"meta-tag\">ShimCache: <strong>{}</strong></div>\n", 
                    if entry.in_shimcache { "Yes" } else { "No" }));
                output.push_str(&format!("                    <div class=\"meta-tag\">AmCache: <strong>{}</strong></div>\n", 
                    if entry.in_amcache { "Yes" } else { "No" }));
                output.push_str("                </div>\n");
                output.push_str("            </div>\n        </div>\n\n");
            }
        }

        // All Findings Table
        output.push_str("        <div class=\"category-header\">\n");
        output.push_str("            <span class=\"icon\"></span>\n");
        output.push_str("            <h3>📋 All Findings</h3>\n");
        output.push_str(&format!("            <span class=\"category-count\">{} total</span>\n", filtered.len()));
        output.push_str("        </div>\n\n");
        
        output.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;\">\n");
        output.push_str("            <table>\n                <thead>\n                    <tr>\n");
        output.push_str("                        <th>Severity</th>\n                        <th>Executable</th>\n");
        output.push_str("                        <th>Source</th>\n                        <th>Description</th>\n");
        output.push_str("                        <th>Publisher</th>\n                    </tr>\n                </thead>\n");
        output.push_str("                <tbody>\n");

        for entry in filtered.iter().take(200) {
            let level_class = Self::risk_class_name(&entry.risk_level);
            let level_str = entry.risk_level.to_string().to_uppercase();
            let filename = entry.path.split(['\\', '/']).last().unwrap_or(&entry.path);
            let source = match (entry.in_shimcache, entry.in_amcache) {
                (true, true) => "Both",
                (true, false) => "ShimCache",
                (false, true) => "AmCache",
                _ => "-",
            };
            let description = entry.risk_indicators.first()
                .map(|s| if s.len() > 50 { format!("{}...", &s[..50]) } else { s.clone() })
                .unwrap_or_else(|| "-".to_string());
            let publisher = entry.company_name.as_deref().unwrap_or("-");

            output.push_str("                    <tr>\n");
            output.push_str(&format!("                        <td><span class=\"severity-badge {}\">{}</span></td>\n", level_class, level_str));
            output.push_str(&format!("                        <td><code>{}</code></td>\n", Self::escape_html(filename)));
            output.push_str(&format!("                        <td>{}</td>\n", source));
            output.push_str(&format!("                        <td>{}</td>\n", Self::escape_html(&description)));
            output.push_str(&format!("                        <td>{}</td>\n", Self::escape_html(publisher)));
            output.push_str("                    </tr>\n");
        }

        output.push_str("                </tbody>\n            </table>\n        </div>\n\n");

        // Statistics Section
        output.push_str("        <div class=\"category-header\">\n");
        output.push_str("            <span class=\"icon\"></span>\n");
        output.push_str("            <h3>📊 Analysis Statistics</h3>\n");
        output.push_str("        </div>\n\n");

        output.push_str("        <div style=\"display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;\">\n");
        
        // Summary stats
        output.push_str("            <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;\">\n");
        output.push_str("                <h4 style=\"color: var(--accent-light); margin-bottom: 12px;\">Correlation Summary</h4>\n");
        output.push_str("                <table>\n");
        output.push_str(&format!("                    <tr><td>Total Correlated</td><td><strong>{}</strong></td></tr>\n", report.statistics.total_correlated));
        output.push_str(&format!("                    <tr><td>In Both Sources</td><td><strong>{}</strong></td></tr>\n", report.statistics.entries_in_both));
        output.push_str(&format!("                    <tr><td>ShimCache Only</td><td><strong>{}</strong></td></tr>\n", report.statistics.shimcache_only));
        output.push_str(&format!("                    <tr><td>AmCache Only</td><td><strong>{}</strong></td></tr>\n", report.statistics.amcache_only));
        output.push_str(&format!("                    <tr><td>Unique SHA1 Hashes</td><td><strong>{}</strong></td></tr>\n", report.hash_analysis.unique_hashes.len()));
        output.push_str(&format!("                    <tr><td>With Execution Flag</td><td><strong>{}</strong></td></tr>\n", report.statistics.executed_count));
        output.push_str("                </table>\n            </div>\n");

        // Top Extensions
        output.push_str("            <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;\">\n");
        output.push_str("                <h4 style=\"color: var(--accent-light); margin-bottom: 12px;\">Top File Extensions</h4>\n");
        output.push_str("                <table>\n");
        for (ext, count) in report.statistics.top_extensions.iter().take(8) {
            output.push_str(&format!("                    <tr><td><code>{}</code></td><td><strong>{}</strong></td></tr>\n", Self::escape_html(ext), count));
        }
        output.push_str("                </table>\n            </div>\n");
        output.push_str("        </div>\n\n");

        // Timeline Section
        if !report.timeline.is_empty() {
            output.push_str("        <div class=\"category-header\">\n");
            output.push_str("            <span class=\"icon\"></span>\n");
            output.push_str("            <h3>🕐 Recent Timeline Events</h3>\n");
            output.push_str(&format!("            <span class=\"category-count\">Last 20 of {}</span>\n", report.timeline.len()));
            output.push_str("        </div>\n\n");

            output.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;\">\n");
            output.push_str("            <table>\n                <thead>\n                    <tr>\n");
            output.push_str("                        <th>Timestamp</th>\n                        <th>Event Type</th>\n                        <th>Path</th>\n");
            output.push_str("                    </tr>\n                </thead>\n                <tbody>\n");

            for event in report.timeline.iter().rev().take(20) {
                output.push_str("                    <tr>\n");
                output.push_str(&format!("                        <td>{}</td>\n", event.timestamp));
                output.push_str(&format!("                        <td>{}</td>\n", Self::escape_html(&event.event_type)));
                output.push_str(&format!("                        <td><code>{}</code></td>\n", Self::escape_html(&event.path)));
                output.push_str("                    </tr>\n");
            }
            output.push_str("                </tbody>\n            </table>\n        </div>\n\n");
        }

        output.push_str("    </main>\n\n");

        // Footer
        output.push_str("    <footer>\n");
        output.push_str("        <p>Generated by <strong>KaliHeker ShimCache & AmCache Analyzer</strong></p>\n");
        output.push_str("        <p>A forensic analysis tool for Windows artifact correlation</p>\n");
        output.push_str("    </footer>\n\n");

        // JavaScript
        output.push_str(Self::generate_html_js());
        output.push_str("\n</body>\n</html>\n");

        Ok(output)
    }

    fn format_html_suspicious(&self, report: &AnalysisReport) -> Result<String> {
        self.format_html_full(report, Some(RiskLevel::Low))
    }

    fn risk_class_name(level: &RiskLevel) -> &'static str {
        match level {
            RiskLevel::Critical => "critical",
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
            RiskLevel::Clean => "clean",
        }
    }

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn format_json(&self, report: &AnalysisReport) -> Result<String> {
        if self.pretty {
            Ok(serde_json::to_string_pretty(report)?)
        } else {
            Ok(serde_json::to_string(report)?)
        }
    }

    fn format_suspicious_json(&self, report: &AnalysisReport) -> Result<String> {
        let suspicious_report = serde_json::json!({
            "analysis_time": report.analysis_time,
            "suspicious_count": report.suspicious_entries.len(),
            "suspicious_entries": report.suspicious_entries,
        });

        if self.pretty {
            Ok(serde_json::to_string_pretty(&suspicious_report)?)
        } else {
            Ok(serde_json::to_string(&suspicious_report)?)
        }
    }

    fn format_text(&self, report: &AnalysisReport, min_risk: Option<RiskLevel>) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&"=".repeat(80));
        output.push('\n');
        output.push_str("SHIMCACHE AND AMCACHE CORRELATION ANALYSIS REPORT\n");
        output.push_str(&"=".repeat(80));
        output.push('\n');
        output.push_str(&format!("Analysis Time: {}\n\n", report.analysis_time));

        // Summary
        output.push_str(&"-".repeat(40));
        output.push_str("\nSUMMARY\n");
        output.push_str(&"-".repeat(40));
        output.push('\n');
        output.push_str(&format!("ShimCache Entries:     {}\n", report.statistics.total_shimcache));
        output.push_str(&format!("AmCache Entries:       {}\n", report.statistics.total_amcache));
        output.push_str(&format!("Correlated Entries:    {}\n", report.statistics.total_correlated));
        output.push_str(&format!("  - In Both:           {}\n", report.statistics.entries_in_both));
        output.push_str(&format!("  - ShimCache Only:    {}\n", report.statistics.shimcache_only));
        output.push_str(&format!("  - AmCache Only:      {}\n", report.statistics.amcache_only));
        output.push_str(&format!("Suspicious Entries:    {}\n", report.suspicious_entries.len()));
        output.push_str(&format!("Unique SHA1 Hashes:    {}\n", report.hash_analysis.unique_hashes.len()));
        output.push_str(&format!("With Execution Flag:   {}\n", report.statistics.executed_count));
        output.push('\n');

        // Risk Distribution
        output.push_str(&"-".repeat(40));
        output.push_str("\nRISK DISTRIBUTION\n");
        output.push_str(&"-".repeat(40));
        output.push('\n');
        for (level, count) in &report.statistics.risk_distribution {
            output.push_str(&format!("  {:12}: {}\n", level.to_uppercase(), count));
        }
        output.push('\n');

        // Suspicious Entries
        if !report.suspicious_entries.is_empty() {
            output.push_str(&"-".repeat(40));
            output.push_str(&format!("\nSUSPICIOUS ENTRIES ({})\n", report.suspicious_entries.len()));
            output.push_str(&"-".repeat(40));
            output.push('\n');

            let mut sorted_suspicious = report.suspicious_entries.clone();
            sorted_suspicious.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

            let filtered: Vec<_> = if let Some(min) = min_risk {
                sorted_suspicious.into_iter().filter(|e| e.risk_level >= min).collect()
            } else {
                sorted_suspicious
            };

            for entry in filtered.iter().take(50) {
                output.push('\n');
                let risk_label = format!("[{}]", entry.risk_level.to_string().to_uppercase());
                output.push_str(&format!("{} {}\n", risk_label, entry.path));
                output.push_str(&format!("  In ShimCache: {}, In AmCache: {}\n", 
                    entry.in_shimcache, entry.in_amcache));

                if let Some(ref sha1) = entry.sha1 {
                    output.push_str(&format!("  SHA1: {}\n", sha1));
                }
                if let Some(ref company) = entry.company_name {
                    output.push_str(&format!("  Company: {}\n", company));
                }
                if let Some(ref product) = entry.product_name {
                    output.push_str(&format!("  Product: {}\n", product));
                }
                if let Some(ref first_run) = entry.first_run_time {
                    output.push_str(&format!("  First Run: {}\n", first_run));
                }
                if let Some(executed) = entry.shim_executed {
                    output.push_str(&format!("  Executed (ShimCache): {}\n", if executed { "Yes" } else { "No" }));
                }

                for indicator in &entry.risk_indicators {
                    output.push_str(&format!("  ! {}\n", indicator));
                }

                if let Some(ref vt) = entry.vt_result {
                    if vt.malicious > 0 {
                        output.push_str(&format!("  !! VirusTotal: {} malicious detections\n", vt.malicious));
                    }
                }
            }
        }
        output.push('\n');

        // Top Extensions
        output.push_str(&"-".repeat(40));
        output.push_str("\nTOP FILE EXTENSIONS\n");
        output.push_str(&"-".repeat(40));
        output.push('\n');
        for (ext, count) in report.statistics.top_extensions.iter().take(10) {
            output.push_str(&format!("  {:15}: {}\n", ext, count));
        }
        output.push('\n');

        // Recent Timeline
        if !report.timeline.is_empty() {
            output.push_str(&"-".repeat(40));
            output.push_str("\nRECENT TIMELINE EVENTS (Last 20)\n");
            output.push_str(&"-".repeat(40));
            output.push('\n');
            for event in report.timeline.iter().rev().take(20) {
                output.push_str(&format!("  [{}] {}: {}\n", 
                    event.timestamp, event.event_type, event.path));
            }
        }

        output.push('\n');
        output.push_str(&"=".repeat(80));
        output.push_str("\nEND OF REPORT\n");
        output.push_str(&"=".repeat(80));
        output.push('\n');

        Ok(output)
    }

    fn format_suspicious_text(&self, report: &AnalysisReport) -> Result<String> {
        let mut output = String::new();

        output.push_str(&"=".repeat(80));
        output.push('\n');
        output.push_str("SUSPICIOUS ENTRIES REPORT\n");
        output.push_str(&"=".repeat(80));
        output.push('\n');
        output.push_str(&format!("Analysis Time: {}\n", report.analysis_time));
        output.push_str(&format!("Total Suspicious: {}\n\n", report.suspicious_entries.len()));

        let mut sorted = report.suspicious_entries.clone();
        sorted.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

        for entry in &sorted {
            let risk_label = format!("[{}]", entry.risk_level.to_string().to_uppercase());
            output.push_str(&format!("{} {}\n", risk_label, entry.path));
            
            if let Some(ref sha1) = entry.sha1 {
                output.push_str(&format!("  SHA1: {}\n", sha1));
            }
            if let Some(ref first_run) = entry.first_run_time {
                output.push_str(&format!("  First Run: {}\n", first_run));
            }
            for indicator in &entry.risk_indicators {
                output.push_str(&format!("  ! {}\n", indicator));
            }
            output.push('\n');
        }

        Ok(output)
    }

    fn format_csv_full(&self, report: &AnalysisReport) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str("Path,Normalized_Path,In_ShimCache,In_AmCache,Risk_Level,SHA1,File_Size,");
        output.push_str("First_Run_Time,Shim_Modified_Time,Company_Name,Product_Name,");
        output.push_str("File_Version,Binary_Type,Shim_Executed,Risk_Indicators\n");

        for entry in &report.correlated_entries {
            output.push_str(&format!(
                "\"{}\",\"{}\",{},{},{},\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"\n",
                Self::escape_csv(&entry.path),
                Self::escape_csv(&entry.normalized_path),
                entry.in_shimcache,
                entry.in_amcache,
                entry.risk_level,
                entry.sha1.as_deref().unwrap_or(""),
                entry.file_size.map(|s| s.to_string()).unwrap_or_default(),
                entry.first_run_time.as_deref().unwrap_or(""),
                entry.shim_modified_time.as_deref().unwrap_or(""),
                Self::escape_csv(entry.company_name.as_deref().unwrap_or("")),
                Self::escape_csv(entry.product_name.as_deref().unwrap_or("")),
                Self::escape_csv(entry.file_version.as_deref().unwrap_or("")),
                Self::escape_csv(entry.binary_type.as_deref().unwrap_or("")),
                entry.shim_executed.map(|e| if e { "Yes" } else { "No" }).unwrap_or(""),
                Self::escape_csv(&entry.risk_indicators.join("; ")),
            ));
        }

        Ok(output)
    }

    fn format_csv_suspicious(&self, report: &AnalysisReport) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str("Path,Risk_Level,SHA1,First_Run_Time,Company_Name,Product_Name,");
        output.push_str("In_ShimCache,In_AmCache,Shim_Executed,VT_Malicious,Risk_Indicators\n");

        for entry in &report.suspicious_entries {
            let vt_mal = entry.vt_result.as_ref().map(|v| v.malicious.to_string()).unwrap_or_default();
            
            output.push_str(&format!(
                "\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",{},{},{},{},\"{}\"\n",
                Self::escape_csv(&entry.path),
                entry.risk_level,
                entry.sha1.as_deref().unwrap_or(""),
                entry.first_run_time.as_deref().unwrap_or(""),
                Self::escape_csv(entry.company_name.as_deref().unwrap_or("")),
                Self::escape_csv(entry.product_name.as_deref().unwrap_or("")),
                entry.in_shimcache,
                entry.in_amcache,
                entry.shim_executed.map(|e| if e { "Yes" } else { "No" }).unwrap_or(""),
                vt_mal,
                Self::escape_csv(&entry.risk_indicators.join("; ")),
            ));
        }

        Ok(output)
    }

    fn escape_csv(s: &str) -> String {
        s.replace('"', "\"\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_escape() {
        assert_eq!(OutputFormatter::escape_csv("test"), "test");
        assert_eq!(OutputFormatter::escape_csv("te\"st"), "te\"\"st");
    }
}
