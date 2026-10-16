//! File type detection by magic bytes (with the file name as a hint).

use crate::util::{be_u32, extension, le_u32, looks_like_text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    /// Windows PE (EXE/DLL/SYS/SCR...).
    Pe,
    /// Linux/Android ELF.
    Elf,
    /// Apple Mach-O (thin or universal).
    MachO,
    /// Android DEX bytecode.
    Dex,
    /// Java class file.
    JavaClass,
    /// ZIP container (also APK, JAR, IPA, DOCX/XLSX/PPTX...).
    Zip,
    /// OLE2 compound file (DOC/XLS/PPT/MSI...).
    Ole2,
    Pdf,
    Rtf,
    Gzip,
    Tar,
    SevenZip,
    Rar,
    /// Windows shortcut (.lnk).
    Lnk,
    Html,
    /// Script (PowerShell, JavaScript, VBScript, batch, shell, Python...).
    Script,
    Text,
    Image,
    Media,
    Unknown,
}

impl FileType {
    pub fn as_str(self) -> &'static str {
        match self {
            FileType::Pe => "pe",
            FileType::Elf => "elf",
            FileType::MachO => "macho",
            FileType::Dex => "dex",
            FileType::JavaClass => "class",
            FileType::Zip => "zip",
            FileType::Ole2 => "ole2",
            FileType::Pdf => "pdf",
            FileType::Rtf => "rtf",
            FileType::Gzip => "gzip",
            FileType::Tar => "tar",
            FileType::SevenZip => "7z",
            FileType::Rar => "rar",
            FileType::Lnk => "lnk",
            FileType::Html => "html",
            FileType::Script => "script",
            FileType::Text => "text",
            FileType::Image => "image",
            FileType::Media => "media",
            FileType::Unknown => "unknown",
        }
    }

    /// Native executable formats.
    pub fn is_executable(self) -> bool {
        matches!(self, FileType::Pe | FileType::Elf | FileType::MachO)
    }

    /// Containers that the archive module can unpack.
    pub fn is_unpackable(self) -> bool {
        matches!(self, FileType::Zip | FileType::Gzip | FileType::Tar)
    }

    pub fn is_textual(self) -> bool {
        matches!(self, FileType::Html | FileType::Script | FileType::Text)
    }
}

/// Extensions treated as scripts when the content is text.
pub const SCRIPT_EXTENSIONS: &[&str] = &[
    "ps1",
    "psm1",
    "psd1",
    "js",
    "jse",
    "mjs",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "bat",
    "cmd",
    "sh",
    "bash",
    "zsh",
    "py",
    "pl",
    "rb",
    "php",
    "lua",
    "applescript",
    "scpt",
    "command",
    "tool",
];

/// Extensions of executable / directly runnable files.
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "msi", "msix", "appx", "dll", "sys", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "ps1", "lnk", "jar", "apk", "app", "command", "sh", "elf", "bin", "run", "dmg", "pkg", "iso", "img",
];

/// Detects the type of `data` (`name` is used as a hint for text formats).
pub fn detect(data: &[u8], name: &str) -> FileType {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return FileType::Pe;
    }
    if data.starts_with(b"\x7fELF") {
        return FileType::Elf;
    }
    if let Some(magic) = be_u32(data, 0) {
        match magic {
            0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE => return FileType::MachO,
            0xCAFEBABE | 0xCAFEBABF => {
                // Universal Mach-O and Java class files share this magic.
                // Fat headers store a small architecture count next.
                return match be_u32(data, 4) {
                    Some(n) if n > 0 && n < 0x30 => FileType::MachO,
                    _ => FileType::JavaClass,
                };
            }
            _ => {}
        }
    }
    if data.starts_with(b"dex\n") {
        return FileType::Dex;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") || data.starts_with(b"PK\x07\x08") {
        return FileType::Zip;
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileType::Ole2;
    }
    if data.starts_with(b"{\\rt") {
        return FileType::Rtf;
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return FileType::Gzip;
    }
    if data.len() > 262 && &data[257..262] == b"ustar" {
        return FileType::Tar;
    }
    if data.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        return FileType::SevenZip;
    }
    if data.starts_with(b"Rar!\x1A\x07") {
        return FileType::Rar;
    }
    if data.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return FileType::Lnk;
    }
    if is_image(data) {
        return FileType::Image;
    }
    if is_media(data) {
        return FileType::Media;
    }
    // PDF header may be preceded by junk (allowed by readers).
    if memchr::memmem::find(&data[..data.len().min(1024)], b"%PDF-").is_some() {
        return FileType::Pdf;
    }
    if looks_like_text(data) {
        let ext = extension(name);
        let head = &data[..data.len().min(2048)];
        if head.starts_with(b"#!") || SCRIPT_EXTENSIONS.contains(&ext.as_str()) {
            return FileType::Script;
        }
        let lower: Vec<u8> = head.iter().map(|b| b.to_ascii_lowercase()).collect();
        if memchr::memmem::find(&lower, b"<html").is_some()
            || memchr::memmem::find(&lower, b"<!doctype html").is_some()
            || memchr::memmem::find(&lower, b"<script").is_some()
            || matches!(ext.as_str(), "htm" | "html" | "xhtml" | "svg")
        {
            return FileType::Html;
        }
        return FileType::Text;
    }
    FileType::Unknown
}

fn is_image(data: &[u8]) -> bool {
    data.starts_with(&[0x89, b'P', b'N', b'G'])
        || data.starts_with(&[0xFF, 0xD8, 0xFF])
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || (data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP")
        || data.starts_with(b"II*\0")
        || data.starts_with(b"MM\0*")
        || (data.len() >= 12 && &data[4..8] == b"ftyp" && matches!(&data[8..12], b"heic" | b"heix" | b"avif" | b"mif1"))
        || (data.starts_with(b"BM") && le_u32(data, 2).is_some_and(|s| s as usize == data.len()))
}

fn is_media(data: &[u8]) -> bool {
    (data.len() >= 12 && &data[4..8] == b"ftyp")
        || data.starts_with(b"ID3")
        || data.starts_with(b"OggS")
        || data.starts_with(b"fLaC")
        || (data.len() >= 12 && &data[..4] == b"RIFF" && matches!(&data[8..12], b"WAVE" | b"AVI "))
        || data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
}

/// Returns true when a file name has an executable extension.
pub fn has_executable_extension(name: &str) -> bool {
    EXECUTABLE_EXTENSIONS.contains(&extension(name).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_formats() {
        assert_eq!(detect(b"MZ\x90\x00", "a.exe"), FileType::Pe);
        assert_eq!(detect(b"\x7fELF\x02\x01", "a"), FileType::Elf);
        assert_eq!(detect(&[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1], "a"), FileType::MachO);
        assert_eq!(detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2], "a"), FileType::MachO);
        assert_eq!(detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52], "A.class"), FileType::JavaClass);
        assert_eq!(detect(b"PK\x03\x04rest", "a.apk"), FileType::Zip);
        assert_eq!(detect(b"%PDF-1.7\n", "a.pdf"), FileType::Pdf);
        assert_eq!(detect(b"Write-Host 'hi'\n", "x.ps1"), FileType::Script);
        assert_eq!(detect(b"#!/bin/sh\necho hi\n", "x"), FileType::Script);
        assert_eq!(detect(b"<!DOCTYPE html><html></html>", "x"), FileType::Html);
        assert_eq!(detect(b"just some notes", "notes.txt"), FileType::Text);
        assert_eq!(detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A], "a.png"), FileType::Image);
        assert_eq!(detect(&[0x00, 0x01, 0x02, 0xFF, 0x00], "blob"), FileType::Unknown);
    }
}
