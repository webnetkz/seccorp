//! PDF structure analysis (keyword statistics in the spirit of `pdfid`).
//!
//! Compressed (Flate) streams are inflated with strict limits so that
//! keywords hidden in object streams are counted as well.

use super::Finding;
use std::io::Read;

const MAX_STREAM: u64 = 8 << 20;
const MAX_TOTAL: u64 = 32 << 20;

#[derive(Default, Debug, Clone, Copy)]
struct Counts {
    js: usize,
    auto_action: usize,
    launch: usize,
    embedded: usize,
    rich_media: usize,
    xfa: usize,
    obfuscated_names: usize,
}

fn is_delim(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'{' | b'}' | b'%')
}

fn decode_name(raw: &[u8]) -> Option<Vec<u8>> {
    if !raw.contains(&b'#') {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' {
            let h = raw.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(h).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Some(out)
}

fn count_names(data: &[u8], c: &mut Counts) {
    let mut i = 0;
    while let Some(p) = memchr::memchr(b'/', &data[i..]) {
        let start = i + p + 1;
        let mut end = start;
        while end < data.len() && !is_delim(data[end]) {
            end += 1;
        }
        let raw = &data[start..end];
        let (name, obfuscated) = match decode_name(raw) {
            Some(decoded) => (decoded, true),
            None => (raw.to_vec(), false),
        };
        let known = match name.as_slice() {
            b"JS" | b"JavaScript" => {
                c.js += 1;
                true
            }
            b"OpenAction" | b"AA" => {
                c.auto_action += 1;
                true
            }
            b"Launch" => {
                c.launch += 1;
                true
            }
            b"EmbeddedFile" | b"EmbeddedFiles" => {
                c.embedded += 1;
                true
            }
            b"RichMedia" => {
                c.rich_media += 1;
                true
            }
            b"XFA" => {
                c.xfa += 1;
                true
            }
            _ => false,
        };
        if known && obfuscated {
            c.obfuscated_names += 1;
        }
        i = end.max(start);
        if i >= data.len() {
            break;
        }
    }
}

fn inflate_streams(data: &[u8], c: &mut Counts) {
    let mut budget = MAX_TOTAL;
    let mut pos = 0;
    let mut streams = 0;
    while let Some(p) = memchr::memmem::find(&data[pos..], b"stream") {
        let kw = pos + p;
        pos = kw + 6;
        // Skip "endstream".
        if kw >= 3 && &data[kw - 3..kw] == b"end" {
            continue;
        }
        streams += 1;
        if streams > 5000 || budget == 0 {
            break;
        }
        let dict = &data[kw.saturating_sub(400)..kw];
        if memchr::memmem::find(dict, b"/FlateDecode").is_none() && memchr::memmem::find(dict, b"/Fl ").is_none() {
            continue;
        }
        let mut start = kw + 6;
        if data.get(start) == Some(&b'\r') {
            start += 1;
        }
        if data.get(start) == Some(&b'\n') {
            start += 1;
        }
        let Some(len) = memchr::memmem::find(&data[start.min(data.len())..], b"endstream") else { break };
        let raw = &data[start..start + len];
        let mut out = Vec::new();
        let limit = MAX_STREAM.min(budget);
        let _ = flate2::read::ZlibDecoder::new(raw).take(limit).read_to_end(&mut out);
        budget = budget.saturating_sub(out.len() as u64);
        if !out.is_empty() {
            count_names(&out, c);
        }
        pos = start + len;
    }
}

pub fn analyze(data: &[u8], out: &mut Vec<Finding>) {
    let mut c = Counts::default();
    count_names(data, &mut c);
    inflate_streams(data, &mut c);

    if c.js > 0 {
        if c.auto_action > 0 {
            out.push(Finding::new("Heur.PDF.AutoRunScript", 30, "PDF runs JavaScript automatically when opened"));
        } else {
            out.push(Finding::new("Heur.PDF.JavaScript", 10, "PDF contains JavaScript"));
        }
    }
    if c.launch > 0 {
        out.push(Finding::new("Heur.PDF.LaunchAction", 35, "PDF can launch external programs"));
    }
    if c.embedded > 0 {
        let score = if c.js > 0 || c.auto_action > 0 { 20 } else { 5 };
        out.push(Finding::new("Heur.PDF.EmbeddedFile", score, "PDF contains embedded files"));
    }
    if c.rich_media > 0 {
        out.push(Finding::new("Heur.PDF.RichMedia", 10, "PDF contains embedded rich media (Flash)"));
    }
    if c.xfa > 0 && c.js > 0 {
        out.push(Finding::new("Heur.PDF.XfaScript", 10, "PDF uses XFA forms with scripts"));
    }
    if c.obfuscated_names > 0 {
        out.push(Finding::new("Heur.PDF.ObfuscatedNames", 25, "PDF hides active-content keywords with hex escapes"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn names(d: &[u8]) -> Vec<&'static str> {
        let mut v = Vec::new();
        analyze(d, &mut v);
        v.into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn plain_pdf_is_clean() {
        assert!(names(b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n").is_empty());
    }

    #[test]
    fn auto_script_and_obfuscation() {
        let d = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /J#61vaScript /JS (x) >> endobj";
        let n = names(d);
        assert!(n.contains(&"Heur.PDF.AutoRunScript"), "{n:?}");
        assert!(n.contains(&"Heur.PDF.ObfuscatedNames"), "{n:?}");
    }

    #[test]
    fn keywords_inside_compressed_streams() {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"<< /Launch << /F (x) >> >>").unwrap();
        let comp = z.finish().unwrap();
        let mut d = b"%PDF-1.5\n3 0 obj << /Length 10 /Filter /FlateDecode >>\nstream\n".to_vec();
        d.extend_from_slice(&comp);
        d.extend_from_slice(b"\nendstream\nendobj\n");
        assert_eq!(names(&d), vec!["Heur.PDF.LaunchAction"]);
    }
}
