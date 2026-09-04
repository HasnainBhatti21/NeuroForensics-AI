//! HTML acquisition report generator.
//!
//! The report is strictly factual. It makes NO forensic conclusions: it
//! never labels processes as malware, never accuses anyone and never
//! interprets evidence.

use crate::evidence::custody::ChainOfCustody;
use crate::evidence::manifest::Manifest;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn bytes_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// Render the acquisition report. `container_sha256` is `None` for the copy
/// stored inside the AIF (the container hash is computed after packaging
/// and is recorded in the sidecar / external custody record).
pub fn render(manifest: &Manifest, custody: &ChainOfCustody, container_sha256: Option<&str>) -> String {
    let mut html = String::with_capacity(32 * 1024);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<title>Acquisition Report - {}</title>\n",
        escape(&manifest.case_id)
    ));
    html.push_str(
        "<style>
:root { color-scheme: dark; }
body { background:#0b0f14; color:#d7e0ea; font-family:'Segoe UI',Arial,sans-serif; margin:0; }
header { background:linear-gradient(120deg,#0e1622,#131b2b); padding:28px 40px; border-bottom:1px solid #1f2a3a; }
header h1 { margin:0; font-size:22px; color:#67e8f9; letter-spacing:1px; }
header .sub { color:#8b98a9; margin-top:6px; font-size:13px; }
main { padding:24px 40px 60px; max-width:1100px; }
h2 { color:#a5b4fc; border-bottom:1px solid #243044; padding-bottom:6px; margin-top:36px; font-size:16px; text-transform:uppercase; letter-spacing:1px; }
table { border-collapse:collapse; width:100%; margin:12px 0; font-size:13px; }
th, td { border:1px solid #243044; padding:6px 10px; text-align:left; vertical-align:top; word-break:break-word; }
th { background:#111827; color:#7dd3fc; font-weight:600; }
tr:nth-child(even) td { background:#0e1420; }
.pill { display:inline-block; padding:2px 10px; border-radius:10px; font-size:11px; font-weight:700; }
.ok { background:#052e1f; color:#34d399; border:1px solid #14532d; }
.warn { background:#2e2405; color:#facc15; border:1px solid #713f12; }
.err { background:#2e0505; color:#f87171; border:1px solid #7f1d1d; }
.skip { background:#1e293b; color:#94a3b8; border:1px solid #334155; }
.mono { font-family:Consolas,monospace; font-size:12px; }
footer { padding:20px 40px; color:#5b6675; font-size:12px; border-top:1px solid #1f2a3a; }
</style>\n</head>\n<body>\n",
    );

    html.push_str(&format!(
        "<header><h1>MEMO COLLECTOR &mdash; ACQUISITION REPORT</h1>\
         <div class=\"sub\">NEUROFORENSICS AI &middot; Case {} &middot; Generated {}</div></header>\n",
        escape(&manifest.case_id),
        escape(&chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    ));
    html.push_str("<main>\n");

    html.push_str("<h2>Case Information</h2>\n<table>");
    for (k, v) in [
        ("Case ID", manifest.case_id.clone()),
        ("Case Name", manifest.case_name.clone()),
        ("Operator", manifest.acquisition.operator.clone()),
        ("Acquisition Method", manifest.acquisition.method.clone()),
        ("Acquisition Status", manifest.acquisition.status.clone()),
        ("Start Time", manifest.acquisition.start_time.clone()),
        ("End Time", manifest.acquisition.end_time.clone()),
        (
            "Container SHA-256",
            container_sha256
                .map(|s| s.to_string())
                .unwrap_or_else(|| "recorded in the .sha256 sidecar and custody record".into()),
        ),
    ] {
        html.push_str(&format!(
            "<tr><th>{}</th><td class=\"mono\">{}</td></tr>",
            escape(k),
            escape(&v)
        ));
    }
    html.push_str("</table>\n");

    html.push_str("<h2>Host Information</h2>\n<table>");
    for (k, v) in [
        ("Hostname", manifest.host.hostname.clone()),
        ("OS", format!("{} {}", manifest.host.os, manifest.host.os_version)),
        ("Architecture", manifest.host.architecture.clone()),
        ("Kernel", manifest.host.kernel_version.clone()),
        (
            "Elevated Session",
            if manifest.host.elevated { "YES" } else { "NO" }.to_string(),
        ),
    ] {
        html.push_str(&format!(
            "<tr><th>{}</th><td class=\"mono\">{}</td></tr>",
            escape(k),
            escape(&v)
        ));
    }
    html.push_str("</table>\n");

    html.push_str("<h2>Collectors Used</h2>\n<table><tr><th>Module</th><th>Status</th><th>Artifacts</th><th>Bytes</th><th>Notes</th></tr>");
    for module in &manifest.modules {
        let pill = match module.status.as_str() {
            "COMPLETED" => "ok",
            "SKIPPED" => "skip",
            "FAILED" => "err",
            _ => "warn",
        };
        html.push_str(&format!(
            "<tr><td>{}</td><td><span class=\"pill {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&module.module_name),
            pill,
            escape(&module.status),
            module.artifacts,
            bytes_human(module.bytes),
            escape(module.reason.as_deref().unwrap_or(""))
        ));
    }
    html.push_str("</table>\n");

    let total_bytes: u64 = manifest.artifacts.iter().map(|a| a.size).sum();
    html.push_str(&format!(
        "<h2>Artifacts Collected</h2>\n<p>{} artifacts, {} of evidence.</p>\n",
        manifest.artifacts.len(),
        bytes_human(total_bytes)
    ));
    html.push_str("<table><tr><th>Artifact ID</th><th>Path</th><th>Collector</th><th>Size</th><th>SHA-256</th><th>Status</th></tr>");
    for artifact in manifest.artifacts.iter().take(500) {
        html.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            escape(&artifact.artifact_id),
            escape(&artifact.relative_path),
            escape(&artifact.collector),
            bytes_human(artifact.size),
            escape(&artifact.sha256),
            escape(&format!("{:?}", artifact.status)),
        ));
    }
    if manifest.artifacts.len() > 500 {
        html.push_str(&format!(
            "<tr><td colspan=\"6\">&hellip; {} more artifacts listed in manifest.json</td></tr>",
            manifest.artifacts.len() - 500
        ));
    }
    html.push_str("</table>\n");

    if !manifest.warnings.is_empty() {
        html.push_str(&format!(
            "<h2>Warnings ({})</h2>\n<ul>",
            manifest.warnings.len()
        ));
        for warning in &manifest.warnings {
            html.push_str(&format!("<li>{}</li>", escape(warning)));
        }
        html.push_str("</ul>\n");
    }
    if !manifest.errors.is_empty() {
        html.push_str(&format!("<h2>Errors ({})</h2>\n<ul>", manifest.errors.len()));
        for error in &manifest.errors {
            html.push_str(&format!("<li>{}</li>", escape(error)));
        }
        html.push_str("</ul>\n");
    }

    html.push_str("<h2>Acquisition Summary</h2>\n<table>");
    for (k, v) in [
        ("Modules Requested", custody.modules_requested.join(", ")),
        ("Modules Successful", custody.modules_successful.join(", ")),
        ("Modules Skipped", custody.modules_skipped.join(", ")),
        ("Modules Failed", custody.modules_failed.join(", ")),
        ("Artifact Count", custody.artifact_count.to_string()),
        ("Status", custody.status.clone()),
        (
            "AIF SHA-256 (custody record)",
            if custody.aif_sha256.is_empty() {
                "recorded post-packaging in the sidecar / external custody record".to_string()
            } else {
                custody.aif_sha256.clone()
            },
        ),
    ] {
        html.push_str(&format!(
            "<tr><th>{}</th><td class=\"mono\">{}</td></tr>",
            escape(k),
            escape(&v)
        ));
    }
    html.push_str("</table>\n");

    html.push_str(
        "<p><em>This report only describes what was acquired. It contains no forensic \
         conclusions, no threat labels and no accusations. Integrity metadata generated \
         by MEMO Collector; it is not a legal certification.</em></p>\n",
    );
    html.push_str("</main>\n<footer>MEMO Collector &mdash; NEUROFORENSICS AI &middot; Volatile Evidence. Stronger Forensics.</footer>\n</body>\n</html>\n");
    html
}
