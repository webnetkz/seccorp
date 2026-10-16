//! Heuristic analyzers.
//!
//! Each analyzer inspects the *structure* of a file and reports findings with
//! a score. Scores of one buffer are summed (capped at 100) and compared with
//! the thresholds of the selected [`HeuristicLevel`](crate::HeuristicLevel).
//! Heuristics never act alone on low evidence: a single weak indicator stays
//! below the "suspicious" threshold at the default level.

pub mod apk;
pub mod exe;
pub mod filename;
pub mod office;
pub mod pdf;
pub mod script;

use crate::filetype::FileType;
use crate::report::Severity;
use crate::util::extension;

/// One heuristic observation.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub name: &'static str,
    pub score: u32,
    pub description: String,
}

impl Finding {
    pub fn new(name: &'static str, score: u32, description: impl Into<String>) -> Self {
        Finding { name, score, description: description.into() }
    }

    pub fn severity(&self) -> Severity {
        Severity::from_score(self.score)
    }
}

/// Input of the analyzers.
pub struct AnalysisInput<'a> {
    /// File content (may be truncated, see `truncated`).
    pub data: &'a [u8],
    /// File name or archive entry path.
    pub name: &'a str,
    pub file_type: FileType,
    pub full_size: u64,
    pub truncated: bool,
    /// True when the buffer comes from inside an archive.
    pub in_archive: bool,
}

/// Extensions of documents / media that should never contain native code.
const NON_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "mp3",
    "mp4", "mov", "avi", "mkv", "wav", "odt", "ods", "svg",
];

/// Runs every analyzer applicable to the input.
pub fn analyze(input: &AnalysisInput) -> Vec<Finding> {
    let mut out = Vec::new();
    filename::analyze(input.name, &mut out);

    let ext = extension(input.name);
    if input.file_type.is_executable() && NON_EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
        out.push(Finding::new("Heur.Exe.Disguised", 40, format!("Executable program disguised with a .{ext} extension")));
    }

    match input.file_type {
        FileType::Pe | FileType::Elf | FileType::MachO => exe::analyze(input, &mut out),
        FileType::Ole2 => office::analyze_ole(input.data, &mut out),
        FileType::Zip => {
            office::analyze_ooxml(input.data, &mut out);
            apk::analyze(input.data, &mut out);
        }
        FileType::Rtf => office::analyze_rtf(input.data, &mut out),
        FileType::Pdf => pdf::analyze(input.data, &mut out),
        FileType::Script | FileType::Html => script::analyze(input, &mut out),
        _ => {}
    }

    if matches!(input.file_type, FileType::Pdf | FileType::Rtf | FileType::Image | FileType::Media | FileType::Text | FileType::Html) {
        embedded_executable(input.data, &mut out);
    }
    out
}

/// Total score of a set of findings (capped at 100).
pub fn total_score(findings: &[Finding]) -> u32 {
    findings.iter().map(|f| f.score).sum::<u32>().min(100)
}

/// File offset of the entry point for PE and ELF files (used by ClamAV `EP`
/// offsets and the `entrypoint` rule keyword).
pub fn entry_point_offset(data: &[u8], ft: FileType) -> Option<u64> {
    match ft {
        FileType::Pe => exe::pe_entry_offset(data),
        FileType::Elf => exe::elf_entry_offset(data),
        _ => None,
    }
}

/// Looks for a complete PE header embedded inside a document or image.
fn embedded_executable(data: &[u8], out: &mut Vec<Finding>) {
    let mut start = 1usize;
    let mut checked = 0;
    while let Some(pos) = memchr::memmem::find(&data[start.min(data.len())..], b"MZ") {
        let off = start + pos;
        checked += 1;
        if checked > 2000 {
            break;
        }
        if let Some(e_lfanew) = crate::util::le_u32(data, off + 0x3C) {
            let pe = off + e_lfanew as usize;
            if e_lfanew > 0x40 && e_lfanew < 0x1000 && data.get(pe..pe + 4) == Some(b"PE\0\0") {
                out.push(Finding::new("Heur.Embedded.Executable", 25, format!("Contains an embedded Windows executable at offset {off}")));
                return;
            }
        }
        start = off + 2;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn tiny_pe() -> Vec<u8> {
        // Minimal PE32 header + one section; enough for structural checks.
        let mut d = vec![0u8; 1024];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3C] = 0x80;
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes()); // i386
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        d[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // optional header size
        d[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics
        let oh = 0x98;
        d[oh..oh + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic
        d[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point RVA
        d[oh + 28..oh + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
        d[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        d[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        d[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        d[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        d[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem console
        d[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes()); // number of rva and sizes
        let sh = oh + 0xE0;
        d[sh..sh + 5].copy_from_slice(b".text");
        d[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
        d[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        d[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        d[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw pointer
        d[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code | exec | read
        d
    }

    #[test]
    fn disguised_executable() {
        let pe = tiny_pe();
        let input = AnalysisInput {
            data: &pe,
            name: "photo.jpg",
            file_type: FileType::Pe,
            full_size: pe.len() as u64,
            truncated: false,
            in_archive: false,
        };
        let f = analyze(&input);
        assert!(f.iter().any(|f| f.name == "Heur.Exe.Disguised"), "{f:?}");
    }

    #[test]
    fn embedded_pe_in_document() {
        let mut doc = b"%PDF-1.4\n".to_vec();
        doc.extend_from_slice(&[0u8; 100]);
        doc.extend_from_slice(&tiny_pe());
        let input = AnalysisInput {
            data: &doc,
            name: "doc.pdf",
            file_type: FileType::Pdf,
            full_size: doc.len() as u64,
            truncated: false,
            in_archive: false,
        };
        assert!(analyze(&input).iter().any(|f| f.name == "Heur.Embedded.Executable"));
    }

    #[test]
    fn entry_point_of_tiny_pe() {
        assert_eq!(entry_point_offset(&tiny_pe(), FileType::Pe), Some(0x200));
    }
}
