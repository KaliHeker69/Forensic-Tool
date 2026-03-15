use axum::extract::State;
use axum::response::{Html, IntoResponse};

use crate::detection::types::Severity;
use crate::state::SharedState;

fn sev_color(sev: &str) -> &'static str {
    match sev {
        "critical" => "#E24B4A",
        "high" => "#BA7517",
        "medium" => "#378ADD",
        "low" => "#6b7280",
        _ => "#6b7280",
    }
}

fn severity_label(f: &crate::detection::types::Finding) -> &'static str {
    match f.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

pub async fn generate_report(State(state): State<SharedState>) -> impl IntoResponse {
    let state = state.read().await;
    let mut entries: Vec<_> = state.entries.values().collect();
    entries.sort_by(|a, b| b.analysis.score.cmp(&a.analysis.score));

    let total_files = entries.len();
    let flagged_files = entries.iter().filter(|e| e.analysis.score > 0).count();
    let critical_files = entries
        .iter()
        .filter(|e| {
            e.analysis
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical)
        })
        .count();
    let high_files = entries
        .iter()
        .filter(|e| {
            e.analysis
                .findings
                .iter()
                .any(|f| f.severity == Severity::High)
        })
        .count();

    let generated_at = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // ── Build table rows ──────────────────────────────────────────────────────
    let mut rows = String::new();
    for entry in &entries {
        let pf = &entry.parsed;
        let last_run = pf
            .header
            .last_run_times
            .first()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "–".to_string());

        let _top_sev_str = entry
            .analysis
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .map(|s| match s {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
            })
            .unwrap_or("clean");

        let row_style = if entry.analysis.score >= 30 {
            "background:#fff8f8"
        } else if entry.analysis.score > 0 {
            "background:#fffdf5"
        } else {
            ""
        };

        let score_color = if entry.analysis.score >= 30 {
            "#E24B4A"
        } else if entry.analysis.score >= 15 {
            "#BA7517"
        } else if entry.analysis.score > 0 {
            "#378ADD"
        } else {
            "#4b5563"
        };

        // Build findings list
        let mut findings_html = String::new();
        if entry.analysis.findings.is_empty() {
            findings_html.push_str(
                "<span style=\"font-size:11px;color:#9ca3af\">No indicators detected</span>",
            );
        } else {
            for f in &entry.analysis.findings {
                let sev_l = severity_label(f);
                let color = sev_color(sev_l);
                let techniques: String = f
                    .mitre_techniques
                    .iter()
                    .map(|t| {
                        format!(
                            "<span style=\"\
                                font-family:monospace;font-size:9px;padding:1px 5px;\
                                border-radius:3px;background:#eeedfe;color:#3c3489;\
                                margin-right:3px\">{t}</span>"
                        )
                    })
                    .collect();
                findings_html.push_str(&format!(
                    "<div style=\"\
                        display:flex;align-items:flex-start;gap:6px;padding:4px 0;\
                        border-bottom:0.5px solid #f0f0ee;font-size:11px\">\
                      <div style=\"\
                          width:6px;height:6px;border-radius:50%;background:{color};\
                          flex-shrink:0;margin-top:3px\"></div>\
                      <div style=\"flex:1;line-height:1.4\">{}</div>\
                      <div style=\"flex-shrink:0\">{techniques}</div>\
                    </div>",
                    f.description
                ));
            }
        }

        rows.push_str(&format!(
            "<tr style=\"{row_style}\">\
               <td style=\"padding:8px 10px;font-weight:500\">{}</td>\
               <td style=\"padding:8px 10px;font-family:monospace;font-size:11px;color:#6b7280\">{}</td>\
               <td style=\"padding:8px 10px;text-align:center\">{}</td>\
               <td style=\"padding:8px 10px;font-family:monospace;font-size:11px\">{}</td>\
               <td style=\"padding:8px 10px;text-align:center\">{}</td>\
               <td style=\"padding:8px 10px;text-align:center\">\
                 <span style=\"font-size:14px;font-weight:600;color:{score_color}\">{}</span>\
               </td>\
               <td style=\"padding:8px 10px\">{findings_html}</td>\
             </tr>",
            pf.header.exe_name,
            pf.header.prefetch_hash,
            pf.version,
            last_run,
            pf.header.run_count,
            entry.analysis.score,
        ));
    }

    // ── Build suspicious summary cards ────────────────────────────────────────
    let mut suspicious_cards = String::new();
    for entry in entries.iter().filter(|e| e.analysis.score >= 15) {
        let pf = &entry.parsed;
        let last_run = pf
            .header
            .last_run_times
            .first()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "–".to_string());
        let border_color = if entry.analysis.score >= 30 {
            "#E24B4A"
        } else {
            "#BA7517"
        };
        let mut finding_items = String::new();
        for f in &entry.analysis.findings {
            let sev_l = severity_label(f);
            let color = sev_color(sev_l);
            let tech = f.mitre_techniques.join(" · ");
            finding_items.push_str(&format!(
                "<li style=\"margin:3px 0;display:flex;gap:6px;align-items:baseline\">\
                   <span style=\"\
                       display:inline-block;width:7px;height:7px;border-radius:50%;\
                       background:{color};flex-shrink:0;margin-top:2px\"></span>\
                   <span>{}</span>\
                   {}\
                 </li>",
                f.description,
                if tech.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<code style=\"\
                            font-size:9px;padding:1px 5px;border-radius:3px;\
                            background:#eeedfe;color:#3c3489\">{tech}</code>"
                    )
                }
            ));
        }
        suspicious_cards.push_str(&format!(
            "<div style=\"\
                border-left:3px solid {border_color};padding:14px 16px;\
                background:#fff;border-radius:0 8px 8px 0;margin-bottom:10px;\
                box-shadow:0 1px 3px rgba(0,0,0,.06)\">\
              <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:8px\">\
                <span style=\"font-weight:600;font-size:13px\">{}</span>\
                <span style=\"font-family:monospace;font-size:11px;color:#6b7280\">\
                    Hash: {} · Runs: {} · Last: {}\
                </span>\
              </div>\
              <ul style=\"font-size:11px;list-style:none;padding:0\">{finding_items}</ul>\
            </div>",
            pf.header.exe_name,
            pf.header.prefetch_hash,
            pf.header.run_count,
            last_run,
        ));
    }

    if suspicious_cards.is_empty() {
        suspicious_cards = "<p style=\"color:#6b7280;font-size:13px\">No high/critical findings.</p>"
            .to_string();
    }

    // ── Assemble HTML ─────────────────────────────────────────────────────────
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str(&format!(
        "<title>Prefetch Forensic Report &mdash; {generated_at}</title>\n"
    ));
    html.push_str("<style>\n");
    html.push_str(
        "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n\
         body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; \
                background: #f8f8f6; color: #1a1a18; padding: 40px; max-width: 1200px; margin: 0 auto; }\n\
         h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }\n\
         h2 { font-size: 15px; font-weight: 600; margin: 28px 0 12px; \
              padding-bottom: 6px; border-bottom: 1px solid #e5e5e3; }\n\
         .meta { font-size: 12px; color: #9ca3af; margin-bottom: 28px; }\n\
         .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }\n\
         .stat { background: #fff; border: 0.5px solid rgba(0,0,0,.1); \
                 border-radius: 8px; padding: 14px 16px; }\n\
         .stat-val { font-size: 26px; font-weight: 600; line-height: 1; }\n\
         .stat-lbl { font-size: 11px; color: #6b7280; margin-top: 4px; \
                     text-transform: uppercase; letter-spacing: .04em; }\n\
         table { width: 100%; border-collapse: collapse; background: #fff; \
                 border-radius: 10px; overflow: hidden; border: 0.5px solid rgba(0,0,0,.08); \
                 font-size: 12px; }\n\
         th { padding: 10px; text-align: left; font-size: 10px; font-weight: 600; \
              text-transform: uppercase; letter-spacing: .06em; color: #6b7280; \
              background: #f5f5f3; border-bottom: 0.5px solid rgba(0,0,0,.08); }\n\
         tr { border-bottom: 0.5px solid rgba(0,0,0,.05); }\n\
         tr:last-child { border-bottom: none; }\n\
         tr:hover { background: #fafaf8 !important; }\n\
         code { font-family: 'SF Mono', 'Cascadia Code', monospace; }\n\
         @media print { body { background: white; padding: 20px; } \
                         .no-print { display: none; } }\n"
    );
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str(&format!(
        "<h1>Prefetch Forensic Report</h1>\
         <p class=\"meta\">Generated {generated_at} &nbsp;&bull;&nbsp; \
         {total_files} prefetch files analysed</p>\n"
    ));

    // Stats
    html.push_str("<div class=\"stat-grid\">\n");
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-val\">{total_files}</div>\
           <div class=\"stat-lbl\">Total files</div></div>\n"
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-val\" style=\"color:#E24B4A\">{flagged_files}</div>\
           <div class=\"stat-lbl\">Flagged files</div></div>\n"
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-val\" style=\"color:#E24B4A\">{critical_files}</div>\
           <div class=\"stat-lbl\">Critical findings</div></div>\n"
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-val\" style=\"color:#BA7517\">{high_files}</div>\
           <div class=\"stat-lbl\">High findings</div></div>\n"
    ));
    html.push_str("</div>\n");

    // Suspicious section
    html.push_str("<h2>High &amp; Critical Findings</h2>\n");
    html.push_str(&suspicious_cards);

    // Full table
    html.push_str("<h2>All Files</h2>\n");
    html.push_str(
        "<table>\n\
           <thead><tr>\
             <th>Executable</th>\
             <th>Hash</th>\
             <th>Ver</th>\
             <th>Last run (UTC)</th>\
             <th>Runs</th>\
             <th>Score</th>\
             <th>Findings</th>\
           </tr></thead>\n\
           <tbody>\n",
    );
    html.push_str(&rows);
    html.push_str("</tbody>\n</table>\n");
    html.push_str("</body>\n</html>");

    Html(html)
}
