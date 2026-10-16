//! File-name tricks used to make programs look like documents.

use super::Finding;
use crate::util::file_name;

const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt", "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4",
    "avi", "mov", "wav", "zip", "rar", "7z", "html", "htm", "xml", "json",
];

const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "ps1", "msi", "jar", "reg",
    "app", "command", "apk",
];

/// Unicode bidirectional control characters that can reverse displayed text.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
}

pub fn analyze(path: &str, out: &mut Vec<Finding>) {
    let name = file_name(path);
    if name.chars().any(is_bidi_control) {
        out.push(Finding::new(
            "Heur.Filename.BidiOverride",
            60,
            "File name contains invisible text-direction characters used to fake the extension",
        ));
        return;
    }

    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() >= 3 {
        let outer = parts[parts.len() - 1].trim();
        let inner = parts[parts.len() - 2].trim();
        if RISKY_EXTENSIONS.contains(&outer) && DOCUMENT_EXTENSIONS.contains(&inner) {
            out.push(Finding::new(
                "Heur.Filename.DoubleExtension",
                35,
                format!("Program disguised as a .{inner} file (double extension .{inner}.{outer})"),
            ));
        }
    }

    // "invoice.pdf          .exe" – the real extension pushed out of view.
    if let Some(dot) = lower.rfind('.') {
        let before = &lower[..dot];
        let padding = before.chars().rev().take_while(|c| c.is_whitespace() || *c == '_').count();
        let outer = &lower[dot + 1..];
        if padding >= 6 && RISKY_EXTENSIONS.contains(&outer) {
            out.push(Finding::new("Heur.Filename.PaddedExtension", 25, "File name uses padding to hide the real extension"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(p: &str) -> Vec<&'static str> {
        let mut v = Vec::new();
        analyze(p, &mut v);
        v.into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn detects_tricks() {
        assert_eq!(names("C:\\Users\\a\\Downloads\\Invoice.PDF.exe"), vec!["Heur.Filename.DoubleExtension"]);
        assert_eq!(names("photo\u{202E}gpj.scr"), vec!["Heur.Filename.BidiOverride"]);
        assert_eq!(names("report.pdf            .exe").len(), 2);
        assert!(names("archive.tar.gz").is_empty());
        assert!(names("setup-1.2.3.exe").is_empty());
        assert!(names("my.document.pdf").is_empty());
    }
}
