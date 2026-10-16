//! Self-contained HTML scan reports.

use crate::model::ScanRecord;
use seccom_engine::Verdict;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn fmt_time(ts: u64) -> String {
    use chrono::{Local, TimeZone};
    Local.timestamp_opt(ts as i64, 0).single().map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

pub fn html(r: &ScanRecord, lang: &str) -> String {
    let ru = lang == "ru";
    let tr = |a: &'static str, b: &'static str| if ru { a } else { b };
    let kind = match r.kind.as_str() {
        "quick" => tr("Быстрая проверка", "Quick scan"),
        "full" => tr("Полная проверка", "Full scan"),
        "apps" => tr("Проверка приложений", "App scan"),
        _ => tr("Выборочная проверка", "Custom scan"),
    };
    let mut rows = String::new();
    for t in &r.threats {
        let d = t.primary_detection();
        let verdict = match t.verdict {
            Verdict::Malicious => tr("Опасно", "Malicious"),
            Verdict::Suspicious => tr("Подозрительно", "Suspicious"),
            Verdict::Clean => tr("Чисто", "Clean"),
        };
        rows.push_str(&format!(
            "<tr><td class=\"{cls}\">{verdict}</td><td>{name}</td><td class=\"path\">{path}{loc}</td><td>{sha}</td></tr>",
            cls = if t.verdict == Verdict::Malicious { "bad" } else { "warn" },
            name = esc(d.map(|d| d.name.as_str()).unwrap_or("-")),
            path = esc(&t.path),
            loc = d.and_then(|d| d.location.as_ref()).map(|l| format!("<br><small>{}</small>", esc(l))).unwrap_or_default(),
            sha = esc(t.sha256.as_deref().map(|s| &s[..16.min(s.len())]).unwrap_or("-")),
        ));
    }
    if rows.is_empty() {
        rows = format!("<tr><td colspan=\"4\" class=\"ok\">{}</td></tr>", tr("Угроз не обнаружено", "No threats found"));
    }
    format!(
        r#"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><title>SecCorp — {title}</title>
<style>
body{{font-family:-apple-system,"Segoe UI",Roboto,sans-serif;margin:40px;color:#0f172a;background:#f8fafc}}
h1{{margin:0 0 4px;font-size:24px}} .sub{{color:#64748b;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:14px}}
.card b{{display:block;font-size:22px;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;vertical-align:top}}
th{{background:#f1f5f9;color:#475569;font-weight:600}} .path{{word-break:break-all}}
.bad{{color:#dc2626;font-weight:600}} .warn{{color:#d97706;font-weight:600}} .ok{{color:#059669;font-weight:600}}
</style></head><body>
<h1>SecCorp — {title}</h1>
<div class="sub">{started}: {start} · {finished}: {finish}{cancelled}</div>
<div class="grid">
<div class="card">{files}<b>{n_files}</b></div>
<div class="card">{volume}<b>{bytes}</b></div>
<div class="card">{threats}<b>{n_threats}</b></div>
<div class="card">{errors}<b>{n_errors}</b></div>
</div>
<table><thead><tr><th>{verdict_h}</th><th>{threat_h}</th><th>{file_h}</th><th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"#,
        title = kind,
        started = tr("Начало", "Started"),
        start = fmt_time(r.started_at),
        finished = tr("Окончание", "Finished"),
        finish = fmt_time(r.finished_at),
        cancelled = if r.cancelled { tr(" · прервана", " · cancelled") } else { "" },
        files = tr("Проверено файлов", "Files scanned"),
        n_files = r.files_scanned,
        volume = tr("Объём", "Data"),
        bytes = human_bytes(r.bytes_scanned),
        threats = tr("Угроз", "Threats"),
        n_threats = r.threat_count,
        errors = tr("Ошибок доступа", "Access errors"),
        n_errors = r.errors,
        verdict_h = tr("Вердикт", "Verdict"),
        threat_h = tr("Угроза", "Threat"),
        file_h = tr("Файл", "File"),
    )
}
