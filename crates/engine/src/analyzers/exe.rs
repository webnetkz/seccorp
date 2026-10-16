//! Structural checks for native executables (PE, ELF, Mach-O).

use super::{AnalysisInput, Finding};
use crate::filetype::FileType;
use crate::util::{entropy, now_unix};
use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

/// Section names of well-known executable packers / protectors. Packing is
/// also used by legitimate software, so this is only a weak signal.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".packed", "generic packer"),
    (".themida", "Themida"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma"),
];

const HIGH_ENTROPY: f64 = 7.2;

pub fn analyze(input: &AnalysisInput, out: &mut Vec<Finding>) {
    match input.file_type {
        FileType::Pe => analyze_pe(input, out),
        FileType::Elf => analyze_elf(input, out),
        FileType::MachO => analyze_macho(input, out),
        _ => {}
    }
}

fn section_bytes(data: &[u8], ptr: u64, size: u64) -> &[u8] {
    let start = (ptr as usize).min(data.len());
    let end = (ptr.saturating_add(size) as usize).min(data.len());
    &data[start..end]
}

fn analyze_pe(input: &AnalysisInput, out: &mut Vec<Finding>) {
    let data = input.data;
    let pe = match goblin::pe::PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => {
            if !input.truncated && data.len() > 64 {
                out.push(Finding::new("Heur.Exe.Malformed", 15, "Corrupted or deliberately malformed Windows executable"));
            }
            return;
        }
    };

    let mut local: Vec<Finding> = Vec::new();
    let mut packers: Vec<&str> = Vec::new();
    let mut packed_section = None;
    let mut wx_section = None;

    for s in &pe.sections {
        let name = s.name().unwrap_or("").trim_end_matches('\0').to_string();
        if let Some((_, p)) = PACKER_SECTIONS.iter().find(|(n, _)| n.eq_ignore_ascii_case(&name))
            && !packers.contains(p)
        {
            packers.push(p);
        }
        let exec = s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
        let write = s.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        if exec && write && wx_section.is_none() {
            wx_section = Some(name.clone());
        }
        if exec && s.size_of_raw_data >= 4096 {
            let bytes = section_bytes(data, s.pointer_to_raw_data as u64, s.size_of_raw_data as u64);
            if bytes.len() >= 4096 && entropy(bytes) >= HIGH_ENTROPY && packed_section.is_none() {
                packed_section = Some(name.clone());
            }
        }
    }

    if !packers.is_empty() {
        local.push(Finding::new("Heur.Exe.Packer", 10, format!("Packed with {}", packers.join(", "))));
    }
    if let Some(n) = packed_section {
        local.push(Finding::new("Heur.Exe.PackedCode", 15, format!("Code section '{n}' is compressed or encrypted (high entropy)")));
    }
    if let Some(n) = wx_section {
        local.push(Finding::new("Heur.Exe.WritableCode", 15, format!("Section '{n}' is both writable and executable")));
    }

    // Entry point location.
    let ep = pe.entry;
    if ep != 0 && !pe.sections.is_empty() {
        let idx = pe.sections.iter().position(|s| {
            let size = s.virtual_size.max(s.size_of_raw_data);
            ep >= s.virtual_address && ep < s.virtual_address.saturating_add(size)
        });
        match idx {
            None => local.push(Finding::new("Heur.Exe.EntryPointOutside", 20, "Entry point lies outside of all sections")),
            Some(i) => {
                let s = &pe.sections[i];
                if s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) == 0 {
                    local.push(Finding::new("Heur.Exe.EntryPointNotCode", 15, "Entry point is in a non-executable section"));
                } else if pe.sections.len() > 2 && i == pe.sections.len() - 1 {
                    local.push(Finding::new("Heur.Exe.EntryPointLastSection", 10, "Entry point is in the last section"));
                }
            }
        }
    }

    let is_dotnet = pe.header.optional_header.as_ref().is_some_and(|oh| oh.data_directories.get_clr_runtime_header().is_some());
    if pe.imports.is_empty() && !is_dotnet && !pe.is_lib {
        local.push(Finding::new("Heur.Exe.NoImports", 10, "Program imports no functions (typical for packed code)"));
    }

    // Overlay: data appended after the last section.
    let sections_end = pe.sections.iter().map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64).max().unwrap_or(0);
    let signed =
        pe.header.optional_header.as_ref().and_then(|oh| oh.data_directories.get_certificate_table().copied()).filter(|dd| dd.size > 0);
    if !input.truncated && input.full_size > sections_end + 64 * 1024 {
        let overlay = &data[(sections_end as usize).min(data.len())..];
        let overlay = match signed {
            Some(dd) if (dd.virtual_address as u64) >= sections_end => {
                &overlay[..overlay.len().min((dd.virtual_address as u64 - sections_end) as usize)]
            }
            _ => overlay,
        };
        if overlay.len() >= 64 * 1024 && entropy(overlay) >= 7.5 {
            local.push(Finding::new("Heur.Exe.EncryptedOverlay", 5, "Large encrypted data appended to the program"));
        }
    }

    let ts = pe.header.coff_header.time_date_stamp as u64;
    if ts > now_unix() + 86_400 * 2 && ts < 0xFFFF_FFF0 {
        local.push(Finding::new("Heur.Exe.FutureTimestamp", 5, "Build timestamp lies in the future"));
    }

    // A (present, not verified) Authenticode signature lowers the risk.
    if signed.is_some() {
        let total: u32 = local.iter().map(|f| f.score).sum();
        if total > 0 {
            for f in local.iter_mut() {
                f.score = f.score * 2 / 3;
            }
        }
    }
    out.extend(local);
}

/// File offset of `AddressOfEntryPoint`.
pub fn pe_entry_offset(data: &[u8]) -> Option<u64> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let ep = pe.entry;
    for s in &pe.sections {
        let size = s.virtual_size.max(s.size_of_raw_data);
        if ep >= s.virtual_address && ep < s.virtual_address.saturating_add(size) {
            return Some(s.pointer_to_raw_data as u64 + (ep - s.virtual_address) as u64);
        }
    }
    None
}

/// File offset of the ELF entry point.
pub fn elf_entry_offset(data: &[u8]) -> Option<u64> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    elf.program_headers
        .iter()
        .find(|ph| ph.p_type == PT_LOAD && elf.entry >= ph.p_vaddr && elf.entry < ph.p_vaddr + ph.p_filesz)
        .map(|ph| ph.p_offset + (elf.entry - ph.p_vaddr))
}

fn analyze_elf(input: &AnalysisInput, out: &mut Vec<Finding>) {
    let data = input.data;
    let head = &data[..data.len().min(4096)];
    if memchr::memmem::find(head, b"UPX!").is_some() {
        out.push(Finding::new("Heur.Exe.Packer", 10, "Packed with UPX"));
    }
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        if !input.truncated {
            out.push(Finding::new("Heur.Exe.Malformed", 15, "Corrupted or deliberately malformed ELF file"));
        }
        return;
    };
    for ph in elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD) {
        if ph.p_flags & PF_X != 0 && ph.p_flags & PF_W != 0 {
            out.push(Finding::new("Heur.Exe.WritableCode", 15, "Loadable segment is both writable and executable"));
            break;
        }
    }
    for ph in elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0) {
        let bytes = section_bytes(data, ph.p_offset, ph.p_filesz);
        if bytes.len() >= 8192 && entropy(bytes) >= HIGH_ENTROPY {
            out.push(Finding::new("Heur.Exe.PackedCode", 15, "Executable segment is compressed or encrypted"));
            break;
        }
    }
    if elf.section_headers.is_empty() && !input.truncated && elf.header.e_type == goblin::elf::header::ET_EXEC {
        out.push(Finding::new("Heur.Exe.NoSections", 5, "Executable without section headers"));
    }
}

fn analyze_macho(input: &AnalysisInput, out: &mut Vec<Finding>) {
    use goblin::mach::{Mach, SingleArch};
    let data = input.data;
    let macho = match Mach::parse(data) {
        Ok(Mach::Binary(m)) => m,
        Ok(Mach::Fat(fat)) => match fat.get(0) {
            Ok(SingleArch::MachO(m)) => m,
            _ => return,
        },
        Err(_) => {
            if !input.truncated {
                out.push(Finding::new("Heur.Exe.Malformed", 15, "Corrupted or deliberately malformed Mach-O file"));
            }
            return;
        }
    };
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    for seg in macho.segments.iter() {
        if seg.initprot & VM_PROT_WRITE != 0 && seg.initprot & VM_PROT_EXECUTE != 0 {
            out.push(Finding::new("Heur.Exe.WritableCode", 15, "Segment is both writable and executable"));
            break;
        }
    }
    for seg in macho.segments.iter() {
        let name = String::from_utf8_lossy(&seg.segname).trim_end_matches('\0').to_string();
        if name == "__TEXT" {
            let bytes = section_bytes(data, seg.fileoff, seg.filesize);
            if bytes.len() >= 8192 && entropy(bytes) >= HIGH_ENTROPY {
                out.push(Finding::new("Heur.Exe.PackedCode", 15, "__TEXT segment is compressed or encrypted"));
            }
        }
    }
    let has_signature =
        macho.load_commands.iter().any(|lc| matches!(lc.command, goblin::mach::load_command::CommandVariant::CodeSignature(_)));
    if !has_signature && macho.header.filetype == goblin::mach::header::MH_EXECUTE {
        out.push(Finding::new("Heur.Exe.Unsigned", 5, "Program has no code signature"));
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::tiny_pe;
    use super::*;

    fn input<'a>(data: &'a [u8], name: &'a str) -> AnalysisInput<'a> {
        AnalysisInput { data, name, file_type: FileType::Pe, full_size: data.len() as u64, truncated: false, in_archive: false }
    }

    #[test]
    fn clean_tiny_pe_has_only_weak_findings() {
        let pe = tiny_pe();
        let mut out = Vec::new();
        analyze(&input(&pe, "tool.exe"), &mut out);
        assert!(out.iter().all(|f| f.score <= 10), "{out:?}");
    }

    #[test]
    fn packer_and_wx_section() {
        let mut pe = tiny_pe();
        let sh = 0x98 + 0xE0;
        pe[sh..sh + 8].copy_from_slice(b"UPX1\0\0\0\0");
        pe[sh + 36..sh + 40].copy_from_slice(&0xE000_0020u32.to_le_bytes());
        let mut out = Vec::new();
        analyze(&input(&pe, "a.exe"), &mut out);
        let names: Vec<_> = out.iter().map(|f| f.name).collect();
        assert!(names.contains(&"Heur.Exe.Packer"), "{names:?}");
        assert!(names.contains(&"Heur.Exe.WritableCode"), "{names:?}");
    }

    #[test]
    fn malformed_pe() {
        let mut out = Vec::new();
        let mut d = vec![0u8; 200];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3C] = 0xF0; // points past the end
        analyze(&input(&d, "x.exe"), &mut out);
        assert_eq!(out[0].name, "Heur.Exe.Malformed");
    }
}
