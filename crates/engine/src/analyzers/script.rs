//! Generic obfuscation metrics for scripts and HTML.
//!
//! The analyzer does not look for specific commands. It measures properties
//! that legitimate, human-maintained scripts rarely have: huge encoded blobs,
//! extreme density of character escapes, and enormous single lines.

use super::{AnalysisInput, Finding};
use crate::util::extension;

/// Script types executed directly by the operating system.
const SYSTEM_SCRIPTS: &[&str] = &[
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "bat",
    "cmd",
    "sh",
    "bash",
    "zsh",
    "command",
    "py",
    "pl",
    "applescript",
    "scpt",
];

fn longest_run(data: &[u8], pred: impl Fn(u8) -> bool) -> (usize, usize) {
    let (mut best, mut best_start, mut cur, mut start) = (0usize, 0usize, 0usize, 0usize);
    for (i, &b) in data.iter().enumerate() {
        if pred(b) {
            if cur == 0 {
                start = i;
            }
            cur += 1;
            if cur > best {
                best = cur;
                best_start = start;
            }
        } else {
            cur = 0;
        }
    }
    (best, best_start)
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

fn looks_like_base64(run: &[u8]) -> bool {
    let upper = run.iter().any(|b| b.is_ascii_uppercase());
    let lower = run.iter().any(|b| b.is_ascii_lowercase());
    let digit = run.iter().any(|b| b.is_ascii_digit());
    upper && lower && digit
}

fn count_escapes(data: &[u8]) -> usize {
    let mut n = 0usize;
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    for pat in [&b"\\x"[..], b"\\u", b"%u", b"&#", b"chr(", b"chrw(", b"fromcharcode", b"[char]"] {
        n += memchr::memmem::find_iter(&lower, pat).count();
    }
    n
}

pub fn analyze(input: &AnalysisInput, out: &mut Vec<Finding>) {
    let data = &input.data[..input.data.len().min(8 << 20)];
    if data.len() < 256 {
        return;
    }
    let ext = extension(input.name);
    let system = SYSTEM_SCRIPTS.contains(&ext.as_str()) || (data.starts_with(b"#!") && !matches!(ext.as_str(), "js" | "mjs"));

    let (b64_len, b64_start) = longest_run(data, is_b64);
    if b64_len >= 1000 && looks_like_base64(&data[b64_start..b64_start + b64_len]) {
        let (score, threshold_note) = if system {
            if b64_len >= 10_000 { (25, "large") } else { (15, "") }
        } else if b64_len >= 200_000 {
            (5, "large")
        } else {
            (0, "")
        };
        if score > 0 {
            out.push(Finding::new(
                "Heur.Script.EncodedBlob",
                score,
                format!(
                    "Script carries a {}encoded data block of {} KB",
                    if threshold_note.is_empty() { "" } else { "large " },
                    b64_len / 1024
                ),
            ));
        }
    }

    if system {
        let (hex_len, _) = longest_run(data, |b| b.is_ascii_hexdigit());
        if hex_len >= 4000 {
            out.push(Finding::new("Heur.Script.HexBlob", 15, format!("Script carries {} KB of hex-encoded data", hex_len / 2048)));
        }
        let longest_line = data.split(|&b| b == b'\n').map(<[u8]>::len).max().unwrap_or(0);
        if longest_line >= 10_000 {
            out.push(Finding::new("Heur.Script.LongLine", 10, format!("Script contains a single line of {longest_line} characters")));
        }
    }

    let escapes = count_escapes(data);
    let per_kb = escapes * 1024 / data.len();
    if escapes >= 100 && per_kb >= 40 {
        out.push(Finding::new(
            "Heur.Script.Obfuscated",
            if system { 25 } else { 15 },
            format!("Heavily obfuscated code ({escapes} character escapes)"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filetype::FileType;

    fn run(name: &str, data: &[u8]) -> Vec<&'static str> {
        let input =
            AnalysisInput { data, name, file_type: FileType::Script, full_size: data.len() as u64, truncated: false, in_archive: false };
        let mut out = Vec::new();
        analyze(&input, &mut out);
        out.into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn normal_script_is_quiet() {
        let s = "param($Path)\nGet-ChildItem $Path | ForEach-Object { Write-Output $_.Name }\n".repeat(20);
        assert!(run("list.ps1", s.as_bytes()).is_empty());
    }

    #[test]
    fn blob_and_escapes() {
        let blob: String = (0..3000).map(|i| ["Ab1", "Zx9", "Qw0"][i % 3]).collect();
        let s = format!("$data = '{blob}'\n");
        assert_eq!(run("a.ps1", s.as_bytes()), vec!["Heur.Script.EncodedBlob"]);
        // The same blob in a web bundle is normal (fonts/images).
        assert!(run("bundle.js", s.as_bytes()).is_empty());

        let esc = "\\x41\\x42".repeat(300);
        let s = format!("var s = \"{esc}\";\n");
        assert!(run("x.vbs", s.as_bytes()).contains(&"Heur.Script.Obfuscated"));
    }
}
