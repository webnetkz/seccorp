//! Office documents: VBA macros (OLE2 and OOXML), embedded packages,
//! external templates and RTF embedded objects.
//!
//! VBA source code is stored compressed (MS-OVBA); it is decompressed here so
//! that auto-run entry points can be recognised the same way established
//! macro scanners do.

use super::Finding;
use crate::util::contains_ignore_ascii_case;
use std::io::{Cursor, Read};

const MAX_STREAM: u64 = 32 << 20;

/// Macro entry points that Office runs automatically.
const AUTO_EXEC: &[&str] = &[
    "autoopen",
    "auto_open",
    "document_open",
    "documentopen",
    "workbook_open",
    "workbook_activate",
    "autoexec",
    "autoclose",
    "auto_close",
    "document_close",
    "documentbeforeclose",
    "document_new",
    "autonew",
    "auto_new",
];

/// Calls that reach outside the document (other programs or objects).
const EXTERNAL_CALLS: &[&str] = &["shell", "createobject", "getobject", "callbyname", " lib \""];

/// Decompresses an MS-OVBA "CompressedContainer".
pub fn decompress_vba(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() != Some(&0x01) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 2);
    let mut pos = 1usize;
    while pos + 2 <= data.len() {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let chunk_size = (header & 0x0FFF) as usize + 3;
        if (header >> 12) & 0x7 != 0b011 {
            break;
        }
        let compressed = header & 0x8000 != 0;
        let chunk_end = (pos + chunk_size).min(data.len());
        let mut p = pos + 2;
        if !compressed {
            let end = (p + 4096).min(data.len());
            out.extend_from_slice(&data[p..end]);
            pos = end;
            continue;
        }
        let chunk_start = out.len();
        while p < chunk_end {
            let flags = data[p];
            p += 1;
            for bit in 0..8 {
                if p >= chunk_end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(data[p]);
                    p += 1;
                } else {
                    if p + 2 > chunk_end {
                        return Some(out);
                    }
                    let token = u16::from_le_bytes([data[p], data[p + 1]]);
                    p += 2;
                    let difference = out.len() - chunk_start;
                    let mut bit_count = 4u32;
                    while (1usize << bit_count) < difference {
                        bit_count += 1;
                    }
                    if bit_count > 12 {
                        return None;
                    }
                    let length_mask: u16 = 0xFFFF >> bit_count;
                    let length = (token & length_mask) as usize + 3;
                    let offset = ((token & !length_mask) >> (16 - bit_count)) as usize + 1;
                    if offset > difference {
                        return None;
                    }
                    let src = out.len() - offset;
                    for k in 0..length {
                        let b = out[src + k];
                        out.push(b);
                    }
                }
            }
        }
        pos = chunk_end;
    }
    Some(out)
}

/// Parses the decompressed `dir` stream: `(module stream name, text offset)`.
fn parse_vba_dir(dir: &[u8]) -> Vec<(String, u32)> {
    let mut modules = Vec::new();
    let mut name: Option<String> = None;
    let mut offset = 0u32;
    let mut p = 0usize;
    while p + 6 <= dir.len() {
        let id = u16::from_le_bytes([dir[p], dir[p + 1]]);
        let size = u32::from_le_bytes([dir[p + 2], dir[p + 3], dir[p + 4], dir[p + 5]]) as usize;
        p += 6;
        if id == 0x0009 {
            // PROJECTVERSION: the size field is a reserved constant, 6 bytes follow.
            p += 6;
            continue;
        }
        if p + size > dir.len() {
            break;
        }
        let body = &dir[p..p + size];
        match id {
            0x001A => name = Some(String::from_utf8_lossy(body).into_owned()),
            0x0031 if size >= 4 => offset = u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
            0x002B => {
                if let Some(n) = name.take() {
                    modules.push((n, offset));
                }
                offset = 0;
            }
            _ => {}
        }
        p += size;
    }
    modules
}

/// Information extracted from macros.
#[derive(Debug, Default, Clone)]
pub struct MacroInfo {
    pub has_macros: bool,
    pub auto_exec: Vec<String>,
    pub external_calls: Vec<String>,
    pub source_bytes: usize,
}

fn read_stream<R: Read + std::io::Seek>(cf: &mut cfb::CompoundFile<R>, path: &std::path::Path) -> Option<Vec<u8>> {
    let mut s = cf.open_stream(path).ok()?;
    let mut v = Vec::new();
    (&mut s).take(MAX_STREAM).read_to_end(&mut v).ok()?;
    Some(v)
}

/// Extracts macro information from an OLE2 compound file.
pub fn macro_info(data: &[u8]) -> Option<MacroInfo> {
    let mut cf = cfb::CompoundFile::open(Cursor::new(data)).ok()?;
    let vba_dirs: Vec<std::path::PathBuf> = cf
        .walk()
        .filter(|e| e.is_stream() && e.name().eq_ignore_ascii_case("dir"))
        .filter(|e| e.path().parent().and_then(|p| p.file_name()).is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("VBA")))
        .map(|e| e.path().to_path_buf())
        .collect();
    if vba_dirs.is_empty() {
        return None;
    }
    let mut info = MacroInfo { has_macros: true, ..Default::default() };
    for dir_path in vba_dirs {
        let Some(raw_dir) = read_stream(&mut cf, &dir_path) else { continue };
        let Some(dir) = decompress_vba(&raw_dir) else { continue };
        let storage = dir_path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        for (module, offset) in parse_vba_dir(&dir).into_iter().take(500) {
            let Some(stream) = read_stream(&mut cf, &storage.join(&module)) else { continue };
            let Some(code) = stream.get(offset as usize..).and_then(decompress_vba) else { continue };
            info.source_bytes += code.len();
            for kw in AUTO_EXEC {
                if contains_ignore_ascii_case(&code, kw.as_bytes()) && !info.auto_exec.iter().any(|k| k == kw) {
                    info.auto_exec.push(kw.to_string());
                }
            }
            for kw in EXTERNAL_CALLS {
                let k = kw.trim().trim_matches('"').to_string();
                if contains_ignore_ascii_case(&code, kw.as_bytes()) && !info.external_calls.contains(&k) {
                    info.external_calls.push(k);
                }
            }
        }
    }
    Some(info)
}

/// Label of an embedded OLE package (`\x01Ole10Native` stream).
fn ole_package_labels(data: &[u8]) -> Vec<String> {
    let Ok(mut cf) = cfb::CompoundFile::open(Cursor::new(data)) else { return Vec::new() };
    let paths: Vec<std::path::PathBuf> =
        cf.walk().filter(|e| e.is_stream() && e.name() == "\u{1}Ole10Native").map(|e| e.path().to_path_buf()).collect();
    let mut labels = Vec::new();
    for p in paths {
        let Some(s) = read_stream(&mut cf, &p) else { continue };
        // u32 size, u16 flags, then a NUL-terminated label.
        let rest = s.get(6..).unwrap_or(&[]);
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len().min(260));
        labels.push(String::from_utf8_lossy(&rest[..end.min(260)]).into_owned());
    }
    labels
}

fn macro_findings(info: &MacroInfo, out: &mut Vec<Finding>) {
    if !info.has_macros {
        return;
    }
    if !info.auto_exec.is_empty() && !info.external_calls.is_empty() {
        out.push(Finding::new(
            "Heur.Macro.AutoRunExternal",
            50,
            format!(
                "Macro runs automatically ({}) and calls external programs or objects ({})",
                info.auto_exec.join(", "),
                info.external_calls.join(", ")
            ),
        ));
    } else if !info.auto_exec.is_empty() {
        out.push(Finding::new(
            "Heur.Macro.AutoRun",
            25,
            format!("Macro runs automatically when the document is opened ({})", info.auto_exec.join(", ")),
        ));
    } else {
        out.push(Finding::new("Heur.Macro.Present", 5, "Document contains VBA macros"));
    }
}

fn package_findings(labels: &[String], out: &mut Vec<Finding>) {
    if labels.is_empty() {
        return;
    }
    let risky = labels.iter().find(|l| crate::filetype::has_executable_extension(l));
    match risky {
        Some(l) => out.push(Finding::new(
            "Heur.Office.EmbeddedProgram",
            40,
            format!("Document embeds a runnable file '{}'", crate::util::file_name(l)),
        )),
        None => out.push(Finding::new("Heur.Office.EmbeddedPackage", 10, "Document embeds packaged files")),
    }
}

pub fn analyze_ole(data: &[u8], out: &mut Vec<Finding>) {
    if let Some(info) = macro_info(data) {
        macro_findings(&info, out);
    }
    package_findings(&ole_package_labels(data), out);
}

/// Office Open XML (docx/xlsx/pptx and macro-enabled variants).
pub fn analyze_ooxml(data: &[u8], out: &mut Vec<Finding>) {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(data)) else { return };
    if zip.index_for_name("[Content_Types].xml").is_none() {
        return;
    }
    let mut external_template = false;
    let mut labels = Vec::new();
    let mut macro_seen = false;
    for i in 0..zip.len().min(5000) {
        let Ok(mut f) = zip.by_index(i) else { continue };
        let name = f.name().map(|n| n.into_owned()).unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned());
        let lname = name.to_ascii_lowercase();
        let wanted = lname.ends_with("vbaproject.bin")
            || (lname.contains("/embeddings/") && lname.ends_with(".bin"))
            || (lname.ends_with(".rels") && f.size() < (1 << 20));
        if !wanted {
            continue;
        }
        let mut buf = Vec::new();
        if (&mut f).take(MAX_STREAM).read_to_end(&mut buf).is_err() {
            continue;
        }
        if lname.ends_with("vbaproject.bin") {
            if let Some(info) = macro_info(&buf)
                && !macro_seen
            {
                macro_findings(&info, out);
                macro_seen = true;
            }
        } else if lname.ends_with(".bin") {
            labels.extend(ole_package_labels(&buf));
        } else if !external_template {
            let text = String::from_utf8_lossy(&buf);
            let external = text.contains("TargetMode=\"External\"") || text.contains("TargetMode='External'");
            let kind = text.contains("/attachedTemplate") || text.contains("/oleObject") || text.contains("/frame\"");
            if external && kind {
                external_template = true;
            }
        }
    }
    if external_template {
        out.push(Finding::new("Heur.Office.RemoteContent", 30, "Document loads a template or object from the internet when opened"));
    }
    package_findings(&labels, out);
}

/// Rich Text Format: embedded OLE objects.
pub fn analyze_rtf(data: &[u8], out: &mut Vec<Finding>) {
    let head = &data[..data.len().min(32 << 20)];
    let objdata = memchr::memmem::find(head, b"\\objdata").is_some();
    if !objdata {
        return;
    }
    if memchr::memmem::find(head, b"\\objupdate").is_some() {
        out.push(Finding::new("Heur.RTF.AutoUpdateObject", 30, "RTF document contains an embedded object that activates automatically"));
    } else {
        out.push(Finding::new("Heur.RTF.EmbeddedObject", 10, "RTF document contains embedded objects"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wraps raw bytes into an MS-OVBA container: full 4096-byte blocks as
    /// uncompressed chunks, the tail as a literal-only compressed chunk.
    fn compress_literal(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01];
        for chunk in data.chunks(4096) {
            if chunk.len() == 4096 {
                out.extend_from_slice(&0x3FFFu16.to_le_bytes());
                out.extend_from_slice(chunk);
                continue;
            }
            let mut body = Vec::new();
            for group in chunk.chunks(8) {
                body.push(0u8); // all literals
                body.extend_from_slice(group);
            }
            assert!(body.len() + 2 <= 4098);
            let header: u16 = 0x8000 | 0x3000 | ((body.len() + 2 - 3) as u16 & 0x0FFF);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    #[test]
    fn decompresses_literal_and_copy_tokens() {
        let text = b"Attribute VB_Name = \"Module1\"\r\nSub Test()\r\nEnd Sub\r\n".repeat(100);
        assert_eq!(decompress_vba(&compress_literal(&text)).unwrap(), text);

        // "abcabcabc": three literals then a copy token (offset 3, length 6).
        // difference = 3 -> bit_count 4, length_mask 0x0FFF:
        // token = ((offset-1) << 12) | (length-3) = (2 << 12) | 3
        let token: u16 = (2 << 12) | 3;
        let mut body = vec![0b0000_1000u8, b'a', b'b', b'c'];
        body.extend_from_slice(&token.to_le_bytes());
        let header: u16 = 0x8000 | 0x3000 | ((body.len() + 2 - 3) as u16);
        let mut c = vec![0x01];
        c.extend_from_slice(&header.to_le_bytes());
        c.extend_from_slice(&body);
        assert_eq!(decompress_vba(&c).unwrap(), b"abcabcabc");
    }

    #[test]
    fn dir_stream_modules() {
        let mut dir = Vec::new();
        let mut rec = |id: u16, data: &[u8]| {
            dir.extend_from_slice(&id.to_le_bytes());
            dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
            dir.extend_from_slice(data);
        };
        rec(0x0001, &[1, 0, 0, 0]);
        // PROJECTVERSION is irregular: size=4 but 6 bytes follow.
        dir.extend_from_slice(&0x0009u16.to_le_bytes());
        dir.extend_from_slice(&4u32.to_le_bytes());
        dir.extend_from_slice(&[0; 6]);
        let mut rec = |id: u16, data: &[u8]| {
            dir.extend_from_slice(&id.to_le_bytes());
            dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
            dir.extend_from_slice(data);
        };
        rec(0x0019, b"Module1");
        rec(0x001A, b"Module1");
        rec(0x0032, b"M\0o\0");
        rec(0x0031, &1234u32.to_le_bytes());
        rec(0x002B, &[]);
        rec(0x0010, &[]);
        assert_eq!(parse_vba_dir(&dir), vec![("Module1".to_string(), 1234)]);
    }

    #[test]
    fn rtf_objects() {
        let mut v = Vec::new();
        analyze_rtf(b"{\\rtf1 {\\object\\objupdate{\\objdata 0105}}}", &mut v);
        assert_eq!(v[0].name, "Heur.RTF.AutoUpdateObject");
    }
}
