//! PDF forensic report with a professional document layout: a navy
//! cover page with case identity + contents, sectioned body pages with
//! accent-bar headings, semantic severity colors, and a running footer
//! with page numbers. Produced locally with printpdf; text is
//! sanitized to the built-in font charset.

use printpdf::*;

use super::{collect, ReportInputs};

const PAGE_W: f32 = 210.0; // A4
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 18.0;
/// Body top edge on content pages (below the running header).
const BODY_TOP: f32 = 20.0;
/// Reserved strip at the bottom for the running footer.
const BODY_BOT: f32 = 15.0;
const LINE_H: f32 = 4.3;
const FONT_SIZE: f32 = 8.5;

fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(Rgb {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        icc_profile: None,
    })
}

// Document palette (light, print-oriented).
const NAVY: Color = Color::Rgb(Rgb { r: 0.110, g: 0.169, b: 0.227, icc_profile: None }); // #1C2B3A
const NAVY_DEEP: Color = Color::Rgb(Rgb { r: 0.070, g: 0.106, b: 0.145, icc_profile: None });
const ACCENT: Color = Color::Rgb(Rgb { r: 0.122, g: 0.373, b: 0.659, icc_profile: None }); // #1F5FA8
const TEXT: Color = Color::Rgb(Rgb { r: 0.106, g: 0.137, b: 0.180, icc_profile: None });
const DIM: Color = Color::Rgb(Rgb { r: 0.341, g: 0.384, b: 0.435, icc_profile: None });
const MUTED: Color = Color::Rgb(Rgb { r: 0.537, g: 0.576, b: 0.631, icc_profile: None });
const RULE: Color = Color::Rgb(Rgb { r: 0.843, g: 0.859, b: 0.882, icc_profile: None });
const STRIPE: Color = Color::Rgb(Rgb { r: 0.961, g: 0.965, b: 0.973, icc_profile: None });
const DANGER: Color = Color::Rgb(Rgb { r: 0.753, g: 0.224, b: 0.169, icc_profile: None });
const WARN: Color = Color::Rgb(Rgb { r: 0.702, g: 0.447, b: 0.043, icc_profile: None });
const GOOD: Color = Color::Rgb(Rgb { r: 0.122, g: 0.478, b: 0.271, icc_profile: None });
const WHITE: Color = Color::Rgb(Rgb { r: 1.0, g: 1.0, b: 1.0, icc_profile: None });
const WHITE_DIM: Color = Color::Rgb(Rgb { r: 0.663, g: 0.718, b: 0.769, icc_profile: None });

/// Replace characters the built-in PDF fonts cannot render.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{2014}' | '\u{2013}' => '-',
            '\u{2192}' => '>',
            '\u{2190}' => '<',
            '\u{00B7}' => '.',
            '\u{2691}' => '*',
            '\u{2022}' => '-',
            '\u{2026}' => '.',
            '\u{21B3}' => '>', // ↳
            c if (c as u32) < 256 => c,
            _ => '?',
        })
        .collect()
}

/// Wrap a line to fit the page width (approximate character-based).
/// Counts/slices by chars, not bytes — report lines contain multi-byte
/// UTF-8 glyphs ('·', '—' …) and byte slicing panicked mid-character.
fn wrap(line: &str, max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line.to_string();
    while rest.chars().count() > max_chars {
        // Byte index of the char at position `max_chars` (a valid boundary).
        let cut_char = rest
            .char_indices()
            .nth(max_chars)
            .map(|(b, _)| b)
            .unwrap_or(rest.len());
        // Back off to a space boundary when possible.
        let mut cut = cut_char;
        if let Some(space) = rest[..cut_char].rfind(' ') {
            if space > cut_char / 2 {
                cut = space;
            }
        }
        out.push(rest[..cut].to_string());
        rest = rest[cut..].trim_start().to_string();
    }
    out.push(rest);
    out
}

/// Semantic color for one report line (severity markers, integrity).
fn line_color(line: &str) -> Color {
    let t = line.trim_start();
    if t.contains("MISMATCH")
        || t.contains("FAILED")
        || t.starts_with("[HIGH]")
        || t.starts_with("[CRITICAL]")
        || t.contains("CONTAINER HASH MISMATCH")
    {
        DANGER
    } else if t.starts_with("[MEDIUM]") || t.contains("WARNING:") || t.starts_with("NOT EVALUATED") {
        WARN
    } else if t.starts_with("[LOW]") || t.starts_with("[CLEAN]") || t.contains("VERIFIED") || t.starts_with("EVALUATED") {
        GOOD
    } else {
        TEXT
    }
}

/// Sequential page writer over the printpdf document (top-based cursor).
struct Writer {
    doc: PdfDocumentReference,
    page: printpdf::indices::PdfPageIndex,
    layer: printpdf::indices::PdfLayerIndex,
    y: f32,
    pages: Vec<(printpdf::indices::PdfPageIndex, printpdf::indices::PdfLayerIndex)>,
    font: IndirectFontRef,
    font_bold: IndirectFontRef,
}

impl Writer {
    fn layer(&self) -> printpdf::pdf_layer::PdfLayerReference {
        self.doc.get_page(self.page).get_layer(self.layer)
    }

    fn new_page(&mut self) {
        let (p, l) = self.doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
        self.page = p;
        self.layer = l;
        self.pages.push((p, l));
        self.y = BODY_TOP;
    }

    fn ensure(&mut self, h: f32) {
        if self.y + h > PAGE_H - BODY_BOT {
            self.new_page();
        }
    }

    /// `y_top` is the top of the text line; baseline is derived from it.
    fn text(&self, x: f32, y_top: f32, size: f32, bold: bool, color: Color, s: &str) {
        let layer = self.layer();
        layer.set_fill_color(color);
        layer.use_text(
            sanitize(s),
            size,
            Mm(x),
            Mm(PAGE_H - y_top - size * 0.82),
            if bold { &self.font_bold } else { &self.font },
        );
    }

    fn bar(&self, x0: f32, y0: f32, x1: f32, y1: f32, color: Color) {
        let layer = self.layer();
        layer.set_fill_color(color);
        layer.add_rect(
            printpdf::rectangle::Rect::new(
                Mm(x0),
                Mm(PAGE_H - y1),
                Mm(x1),
                Mm(PAGE_H - y0),
            )
            .with_mode(printpdf::path::PaintMode::Fill),
        );
    }

    fn hline(&self, y: f32, x0: f32, x1: f32, color: Color, thickness: f32) {
        let layer = self.layer();
        layer.set_outline_color(color);
        layer.set_outline_thickness(thickness);
        layer.add_line(printpdf::line::Line {
            points: vec![
                (printpdf::point::Point::new(Mm(x0), Mm(PAGE_H - y)), false),
                (printpdf::point::Point::new(Mm(x1), Mm(PAGE_H - y)), false),
            ],
            is_closed: false,
        });
    }

    /// Approximate rendered width in mm (Helvetica average advance).
    fn text_w(s: &str, size: f32) -> f32 {
        s.len() as f32 * size * 0.5 * 0.3528
    }
}

/// Render the canonical report content to PDF bytes.
pub fn generate(inputs: &ReportInputs) -> Result<Vec<u8>, String> {
    let content = collect(inputs);

    let (doc, page, layer) = PdfDocument::new(
        &sanitize(&content.title),
        Mm(PAGE_W),
        Mm(PAGE_H),
        "Layer 1",
    );
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("PDF font error: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("PDF font error: {e}"))?;

    let mut w = Writer {
        doc,
        page,
        layer,
        y: 0.0,
        pages: vec![(page, layer)],
        font,
        font_bold,
    };

    let case_ref = if content.title.contains("CASE-") {
        content.title.clone()
    } else {
        format!("{} — {}", inputs.meta.case_number, inputs.meta.case_name)
    };

    cover_page(&mut w, inputs, &content, &case_ref);

    // ---------------- body sections ----------------
    for (section, lines) in &content.sections {
        w.new_page();
        section_heading(&mut w, section);
        for line in lines {
            let sub = line.starts_with("    ") || line.starts_with('\t');
            let trimmed = line.trim_start();
            let max_chars = if sub { 100 } else { 112 };
            let chunks = wrap(trimmed, max_chars);
            for (i, chunk) in chunks.iter().enumerate() {
                w.ensure(LINE_H + 1.0);
                let x = MARGIN + if sub { 6.0 } else { 0.0 };
                let color = if sub && i == 0 { DIM } else { line_color(trimmed) };
                let size = if sub { 7.8 } else { FONT_SIZE };
                w.text(x, w.y, size, false, color, chunk);
                w.y += LINE_H;
            }
        }
        w.y += 4.0;
    }

    // ---------------- running footer on every page ----------------
    let total = w.pages.len();
    for (i, (p, l)) in w.pages.clone().into_iter().enumerate() {
        w.page = p;
        w.layer = l;
        let fy = PAGE_H - 10.0;
        w.hline(fy - 2.0, MARGIN, PAGE_W - MARGIN, RULE, 0.2);
        w.text(
            MARGIN,
            fy,
            7.5,
            false,
            MUTED,
            &format!(
                "{} · {} — Forensic Report · generated {}",
                super::tool_version(),
                inputs.meta.case_number,
                chrono::Local::now().format("%Y-%m-%d %H:%M")
            ),
        );
        let page_no = format!("Page {} of {total}", i + 1);
        let pw = Writer::text_w(&page_no, 7.5);
        w.text(PAGE_W - MARGIN - pw, fy, 7.5, true, DIM, &page_no);
    }

    w.doc.save_to_bytes().map_err(|e| format!("PDF export failed: {e}"))
}

/// Cover page: navy masthead, case identity table, contents list and
/// the evidence-classification notice.
fn cover_page(w: &mut Writer, inputs: &ReportInputs, content: &super::ReportContent, case_ref: &str) {
    // Masthead band.
    w.bar(0.0, 0.0, PAGE_W, 36.0, NAVY);
    w.bar(0.0, 36.0, PAGE_W, 37.6, ACCENT);
    w.text(MARGIN, 9.0, 15.0, true, WHITE, "NEUROFORENSICS AI");
    let tag = "FORENSIC CASE REPORT";
    w.text(PAGE_W - MARGIN - Writer::text_w(tag, 9.0), 12.0, 9.0, true, WHITE_DIM, tag);
    w.text(
        MARGIN,
        20.0,
        8.0,
        false,
        WHITE_DIM,
        "AI-Powered CPU & GPU Forensic Analyzer — MEMO Collector AIF evidence examination",
    );
    if content.demo_mode {
        w.text(MARGIN, 27.0, 8.5, true, WARN, "DEMO / SYNTHETIC EVIDENCE — NOT A REAL CASE");
    }

    // Title block.
    w.y = 52.0;
    w.text(MARGIN, w.y, 19.0, true, TEXT, "Forensic Examination Report");
    w.y += 9.0;
    w.text(MARGIN, w.y, 11.5, true, ACCENT, case_ref);
    w.y += 10.0;
    w.hline(w.y, MARGIN, PAGE_W - MARGIN, RULE, 0.3);
    w.y += 6.0;

    // Case identity table (striped key/value rows).
    let meta = inputs.meta;
    let rows: Vec<(String, String)> = vec![
        ("Case number".into(), meta.case_number.clone()),
        ("Case name".into(), meta.case_name.clone()),
        ("Examiner".into(), meta.examiner.clone()),
        ("Organization".into(), meta.organization.clone()),
        ("Case created".into(), meta.created_at.clone()),
        ("Case directory".into(), meta.case_dir.clone()),
        (
            "Evidence image".into(),
            inputs
                .exam
                .map(|e| format!("{} ({} bytes)", e.image_name, e.size_bytes))
                .unwrap_or_else(|| "none ingested".into()),
        ),
        (
            "Container SHA-256".into(),
            inputs.exam.map(|e| e.container_check.calculated.clone()).unwrap_or_else(|| "-".into()),
        ),
        (
            "Integrity status".into(),
            match inputs.exam.map(|e| e.container_check.ok) {
                Some(Some(true)) => "VERIFIED against external sidecar".into(),
                Some(Some(false)) => "MISMATCH against external sidecar".into(),
                Some(None) => "no external hash — not independently verifiable".into(),
                None => "not evaluated — no evidence ingested".into(),
            },
        ),
        ("Tool version".into(), super::tool_version()),
        (
            "Report generated".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(),
        ),
    ];
    let row_h = 6.4;
    for (i, (k, v)) in rows.iter().enumerate() {
        if i % 2 == 0 {
            w.bar(MARGIN - 2.0, w.y - 1.2, PAGE_W - MARGIN + 2.0, w.y + row_h - 1.6, STRIPE);
        }
        w.text(MARGIN, w.y, 8.5, true, DIM, k);
        let vx = MARGIN + 46.0;
        let max = 105;
        for (j, chunk) in wrap(v, max).iter().enumerate() {
            if j > 0 {
                w.y += row_h - 2.0;
            }
            let color = if k == "Integrity status" { line_color(chunk) } else { TEXT };
            w.text(vx, w.y, 8.5, false, color, chunk);
            if j == 0 && wrap(v, max).len() > 1 {
                w.y += row_h - 2.0;
            }
        }
        w.y += row_h;
    }
    w.y += 6.0;

    // Contents.
    w.bar(MARGIN, w.y, MARGIN + 1.8, w.y + 5.6, ACCENT);
    w.text(MARGIN + 4.5, w.y, 11.0, true, NAVY_DEEP, "CONTENTS");
    w.y += 9.0;
    for (i, (section, _)) in content.sections.iter().enumerate() {
        w.ensure(6.0);
        w.text(MARGIN + 2.0, w.y, 8.5, false, DIM, &format!("{:>2}.", i + 1));
        w.text(MARGIN + 10.0, w.y, 8.5, true, TEXT, section);
        w.y += 5.4;
    }
    w.y += 6.0;

    // Evidence-classification notice box.
    w.ensure(26.0);
    w.bar(MARGIN - 2.0, w.y - 1.5, PAGE_W - MARGIN + 2.0, w.y + 20.5, STRIPE);
    w.bar(MARGIN - 2.0, w.y - 1.5, MARGIN - 0.6, w.y + 20.5, ACCENT);
    w.text(MARGIN + 2.0, w.y, 8.0, true, NAVY_DEEP, "EVIDENCE CLASSIFICATION");
    w.y += 4.6;
    for note in [
        "OBSERVED FACT / INTEGRITY VERIFICATION / ANALYTICAL INDICATOR / ML ANOMALY /",
        "INVESTIGATOR INTERPRETATION are strictly separated. Findings are POTENTIAL",
        "indicators, not confirmations. The original AIF evidence was never modified.",
    ] {
        w.text(MARGIN + 2.0, w.y, 7.6, false, DIM, note);
        w.y += 4.0;
    }
}

/// Accent-bar section heading with a hairline rule.
fn section_heading(w: &mut Writer, section: &str) {
    w.bar(MARGIN, w.y, MARGIN + 1.8, w.y + 6.0, ACCENT);
    w.text(MARGIN + 4.5, w.y, 11.0, true, NAVY_DEEP, section);
    w.y += 8.0;
    w.hline(w.y, MARGIN, PAGE_W - MARGIN, RULE, 0.3);
    w.y += 5.0;
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_case_produces_pdf_bytes() {
        let meta = crate::casemgmt::db::CaseMeta {
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
        let bytes = super::generate(&inputs).expect("pdf generates");
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 500);
    }

    /// Regression: wrapping must never panic on multi-byte UTF-8 text
    /// ('·' is 2 bytes — byte-index slicing used to crash the app).
    #[test]
    fn wrap_never_panics_on_multibyte_text() {
        let line = "évidence · ".repeat(60); // mixed 2-byte glyphs
        let chunks = super::wrap(&line, 112);
        assert!(!chunks.is_empty());
        let joined: String = chunks.join("");
        assert!(joined.contains('·'));
    }

    #[test]
    fn real_case_pdf_is_substantially_bigger_than_a_stub() {
        let Some(exam) = crate::ingest::tests::real_exam_if_available() else { return };
        let report = crate::analysis::AnalysisReport::run(&exam);
        let meta = crate::casemgmt::db::CaseMeta {
            case_number: "CASE-REAL-001".into(),
            case_name: "Real evidence case".into(),
            ..Default::default()
        };
        let inputs = crate::reporting::ReportInputs {
            meta: &meta,
            exam: Some(&exam),
            report: Some(&report),
            correlations: None,
            ai: None,
            finding_workflow: &[],
            timeline: &[],
            custody: &[],
            notes: &[],
        };
        let bytes = super::generate(&inputs).expect("pdf generates");
        assert!(bytes.starts_with(b"%PDF"));
        // A real multi-section report must span several pages of content.
        assert!(bytes.len() > 20_000, "pdf too small: {} bytes", bytes.len());
    }
}
