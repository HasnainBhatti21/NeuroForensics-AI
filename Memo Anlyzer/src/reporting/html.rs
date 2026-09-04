//! HTML forensic report rendered as a professional document: navy
//! masthead, table of contents, numbered sections with accent bars,
//! key/value identity table, severity badges and severity-colored
//! lines. Self-contained single file; all text escaped before
//! embedding.

use super::{collect, html_escape, ReportInputs};

/// Render the canonical report content as a standalone HTML document.
pub fn generate(inputs: &ReportInputs) -> String {
    let content = collect(inputs);
    let meta = inputs.meta;

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<title>{}</title>\n",
        html_escape(&format!("Forensic Report — {}", meta.case_number))
    ));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n<div class=\"page\">\n");

    // ---------------- masthead ----------------
    html.push_str("<header class=\"masthead\">\n");
    html.push_str("  <div class=\"brand\">NEUROFORENSICS <span class=\"ai\">AI</span></div>\n");
    html.push_str("  <div class=\"doc-type\">FORENSIC CASE REPORT</div>\n");
    html.push_str(&format!(
        "  <h1>{} <span class=\"case-no\">{}</span></h1>\n",
        html_escape(&meta.case_name),
        html_escape(&meta.case_number)
    ));
    html.push_str("  <div class=\"masthead-meta\">\n");
    html.push_str(&format!(
        "    <span>Examiner: <b>{}</b></span>\n",
        html_escape(if meta.examiner.is_empty() { "—" } else { &meta.examiner })
    ));
    html.push_str(&format!(
        "    <span>Organization: <b>{}</b></span>\n",
        html_escape(if meta.organization.is_empty() { "—" } else { &meta.organization })
    ));
    html.push_str(&format!(
        "    <span>Generated: <b>{}</b></span>\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    html.push_str(&format!("    <span>{}</span>\n", html_escape(&super::tool_version())));
    html.push_str("  </div>\n");
    html.push_str("</header>\n");

    if content.demo_mode {
        html.push_str("<div class=\"demo\">DEMO / SYNTHETIC EVIDENCE — NOT A REAL CASE</div>\n");
    }

    // ---------------- table of contents ----------------
    html.push_str("<nav class=\"toc\">\n  <div class=\"toc-title\">CONTENTS</div>\n  <ol>\n");
    for (i, (section, _)) in content.sections.iter().enumerate() {
        html.push_str(&format!(
            "    <li><a href=\"#s{}\">{}</a></li>\n",
            i + 1,
            html_escape(section)
        ));
    }
    html.push_str("  </ol>\n</nav>\n");

    // ---------------- body sections ----------------
    for (i, (section, lines)) in content.sections.iter().enumerate() {
        html.push_str(&format!(
            "<section id=\"s{}\">\n<h2><span class=\"no\">{}.</span> {}</h2>\n",
            i + 1,
            i + 1,
            html_escape(section)
        ));
        html.push_str("<div class=\"sec-body\">\n");
        for line in lines {
            html.push_str(&render_line(line));
        }
        html.push_str("</div>\n</section>\n");
    }

    // ---------------- footer ----------------
    html.push_str("<footer>\n");
    html.push_str(&format!(
        "  <span>{} · generated {}</span>\n",
        html_escape(&super::tool_version()),
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z")
    ));
    html.push_str("  <span>Findings are POTENTIAL indicators, not confirmations. The original AIF case file was never modified.</span>\n");
    html.push_str("</footer>\n");

    html.push_str("</div>\n</body>\n</html>\n");
    html
}

/// One content line → styled HTML. Indented lines become detail rows,
/// `[TAG] …` prefixes become severity badges, `Key: value` lines
/// become definition rows, `--- … ---` lines become card headers.
fn render_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let indented = line.len() != trimmed.len();

    if trimmed.is_empty() {
        return "<div class=\"ln\">&nbsp;</div>\n".to_string();
    }

    // Card header inside EXPLAINABILITY.
    if trimmed.starts_with("--- ") && trimmed.ends_with(" ---") {
        return format!(
            "<div class=\"card-h\">{}</div>\n",
            html_escape(&trimmed[4..trimmed.len() - 4])
        );
    }

    // Bracketed tag prefix → badge + rest of the line.
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            let tag = &trimmed[1..end];
            let rest = trimmed[end + 1..].trim_start();
            let cls = match tag {
                "HIGH" | "CRITICAL" | "MISMATCH" => "b-high",
                "MEDIUM" => "b-med",
                "LOW" | "CLEAN" | "VERIFIED" | "EVALUATED" => "b-low",
                "NOT EVALUATED" => "b-med",
                _ => "b-tag",
            };
            if indented {
                return format!(
                    "<div class=\"sub\"><span class=\"badge {cls}\">{}</span>{}</div>\n",
                    html_escape(tag),
                    html_escape(rest)
                );
            }
            return format!(
                "<div class=\"ln\"><span class=\"badge {cls}\">{}</span>{}</div>\n",
                html_escape(tag),
                html_escape(rest)
            );
        }
    }

    if indented {
        return format!("<div class=\"sub\">{}</div>\n", html_escape(trimmed));
    }

    // `Key: value` definition row (case identity, stream facts…).
    if let Some(colon) = trimmed.find(": ") {
        let key = &trimmed[..colon];
        let chars: usize = key.chars().count();
        if chars >= 3 && chars <= 34 && key.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false) {
            return format!(
                "<div class=\"kv\"><span class=\"k\">{}</span><span class=\"v\">{}</span></div>\n",
                html_escape(key),
                html_escape(&trimmed[colon + 2..])
            );
        }
    }

    let cls = if trimmed.contains("MISMATCH") || trimmed.starts_with("CONTAINER HASH") {
        " ln-danger"
    } else if trimmed.starts_with("WARNING") || trimmed.contains("WARNING:") {
        " ln-warn"
    } else {
        ""
    };
    format!("<div class=\"ln{cls}\">{}</div>\n", html_escape(trimmed))
}

/// Document stylesheet (design tokens mirror the workstation theme).
const STYLE: &str = r#"<style>
:root{
  --navy:#1c2b3a; --navy-deep:#121d29; --accent:#1f5fa8; --accent-soft:#e8ecf4;
  --text:#1b232e; --dim:#57626f; --muted:#8993a1; --border:#d7dbe1;
  --hairline:#eef0f3; --stripe:#f7f9fb; --danger:#c0392b; --warn:#b3720b; --good:#1f7a45;
}
*{box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#eef1f5;color:var(--text);
     margin:0;padding:28px 16px;font-size:13.5px;line-height:1.5;}
.page{max-width:920px;margin:0 auto;background:#fff;border:1px solid var(--border);
      box-shadow:0 10px 34px rgba(18,29,41,.14);}
/* masthead */
.masthead{background:linear-gradient(135deg,var(--navy) 0%,var(--navy-deep) 100%);
          color:#dfe6ee;padding:30px 40px 26px;border-bottom:4px solid var(--accent);}
.brand{font-size:13px;letter-spacing:3px;font-weight:600;color:#dfe6ee;}
.brand .ai{color:#7fb2e8;}
.doc-type{font-size:10px;letter-spacing:2.5px;color:#a9b7c4;margin:2px 0 14px;}
.masthead h1{margin:0 0 14px;font-size:25px;font-weight:600;color:#fff;}
.masthead h1 .case-no{color:#7fb2e8;font-weight:500;}
.masthead-meta{display:flex;flex-wrap:wrap;gap:8px 26px;font-size:11.5px;color:#a9b7c4;}
.masthead-meta b{color:#dfe6ee;font-weight:600;}
.demo{background:#fdf1de;border:2px solid var(--warn);color:var(--warn);font-weight:700;
      padding:10px 40px;letter-spacing:1px;}
/* table of contents */
.toc{padding:20px 40px;border-bottom:1px solid var(--hairline);background:var(--stripe);}
.toc-title{font-size:10.5px;letter-spacing:2px;color:var(--muted);font-weight:700;margin-bottom:8px;}
.toc ol{margin:0;padding-left:22px;columns:2;column-gap:40px;font-size:12.5px;}
.toc li{margin:2.5px 0;break-inside:avoid;}
.toc a{color:var(--accent);text-decoration:none;}
.toc a:hover{text-decoration:underline;}
/* sections */
section{padding:22px 40px 6px;}
h2{font-size:15px;color:var(--navy-deep);margin:0 0 12px;padding-left:12px;
   border-left:4px solid var(--accent);line-height:1.3;}
h2 .no{color:var(--accent);margin-right:6px;}
.sec-body{margin-bottom:14px;}
/* lines */
.ln{padding:2px 0;}
.sub{padding:1px 0 1px 22px;color:var(--dim);font-size:12.5px;
     border-left:2px solid var(--hairline);margin-left:6px;}
.kv{display:flex;gap:10px;padding:4px 8px;border-bottom:1px solid var(--hairline);}
.kv:nth-child(odd){background:var(--stripe);}
.kv .k{flex:0 0 220px;color:var(--dim);font-weight:600;font-size:12px;
       text-transform:uppercase;letter-spacing:.4px;padding-top:1px;}
.kv .v{flex:1;font-family:'Cascadia Mono',Consolas,monospace;font-size:12px;word-break:break-word;}
.card-h{margin:12px 0 4px;font-weight:700;color:var(--navy-deep);font-size:12.5px;
        background:var(--accent-soft);border:1px solid #b7d3f2;border-radius:5px;
        padding:5px 10px;font-family:'Cascadia Mono',Consolas,monospace;}
.ln-danger{color:var(--danger);font-weight:600;}
.ln-warn{color:var(--warn);}
/* badges */
.badge{display:inline-block;font-family:'Cascadia Mono',Consolas,monospace;font-size:9.5px;
       font-weight:700;letter-spacing:.6px;border-radius:3px;padding:1px 7px;margin-right:9px;
       vertical-align:1px;white-space:nowrap;}
.b-high{background:#fbe9e7;color:var(--danger);border:1px solid #f0c4bd;}
.b-med{background:#fdf1de;color:var(--warn);border:1px solid #f0d69f;}
.b-low{background:#e7f5ec;color:var(--good);border:1px solid #bfe3cd;}
.b-tag{background:var(--accent-soft);color:var(--accent);border:1px solid #b7d3f2;}
/* footer */
footer{margin-top:26px;border-top:1px solid var(--border);background:var(--stripe);
       padding:16px 40px;display:flex;flex-wrap:wrap;gap:6px 28px;
       color:var(--muted);font-size:11px;}
@media print{
  body{background:#fff;padding:0;}
  .page{border:none;box-shadow:none;max-width:none;}
  section{break-inside:avoid-page;}
}
</style>
"#;

#[cfg(test)]
mod tests {
    use crate::casemgmt::db::CaseMeta;

    #[test]
    fn report_contains_all_evidence_classes() {
        let meta = CaseMeta {
            case_number: "CASE-TEST-001".into(),
            case_name: "Unit test case".into(),
            ..Default::default()
        };
        let inputs = crate::reporting::ReportInputs {
            meta: &meta,
            exam: None,
            report: None,
            correlations: None,
            ai: None,
            finding_workflow: &[],
            timeline: &[],
            custody: &[],
            notes: &[],
        };
        let html = super::generate(&inputs);
        for section in [
            "CASE IDENTITY",
            "OBSERVED FACT",
            "INTEGRITY VERIFICATION",
            "TIMELINE",
            "ANALYTICAL INDICATOR",
            "CORRELATION",
            "ML ANOMALY",
            "AI ANALYSIS LAYER",
            "EXPLAINABILITY",
            "FINDING WORKFLOW",
            "INVESTIGATOR INTERPRETATION",
            "NOTICE",
        ] {
            assert!(html.contains(section), "missing section {section}");
        }
        assert!(html.contains("No evidence image ingested"));
        // Document chrome: masthead, TOC and styled footer.
        assert!(html.contains("FORENSIC CASE REPORT"));
        assert!(html.contains("CONTENTS"));
        assert!(html.contains("POTENTIAL indicators"));
    }

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(super::html_escape("<b>&\""), "&lt;b&gt;&amp;&quot;");
    }

    #[test]
    fn render_line_classifies_severity_and_kv() {
        assert!(super::render_line("[HIGH] NET-001 — x").contains("b-high"));
        assert!(super::render_line("[MEDIUM] a").contains("b-med"));
        assert!(super::render_line("[LOW] a").contains("b-low"));
        assert!(super::render_line("Case number: CASE-1").contains("class=\"kv\""));
        assert!(super::render_line("    supporting artifacts: ART-1").contains("class=\"sub\""));
        assert!(super::render_line("--- NET-001 ---").contains("card-h"));
        assert!(super::render_line("CONTAINER HASH MISMATCH — x").contains("ln-danger"));
    }
}
