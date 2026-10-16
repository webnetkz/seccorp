//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UNIX time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Current UNIX time in milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut e = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e
}

/// Stable 64-bit FNV-1a hash (used for cache keys; must not change between releases).
/// macOS: a file or folder whose contents live only in iCloud Drive or another
/// File Provider (a "dataless" placeholder). Reading it would download it, so
/// scans skip it.
#[cfg(target_os = "macos")]
pub fn is_cloud_placeholder(meta: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    const SF_DATALESS: u32 = 0x4000_0000;
    meta.st_flags() & SF_DATALESS != 0
}

/// Cloud placeholders only exist on macOS.
#[cfg(not(target_os = "macos"))]
pub fn is_cloud_placeholder(_meta: &std::fs::Metadata) -> bool {
    false
}

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Lower-case extension of a file name (without the dot).
pub fn extension(name: &str) -> String {
    let file = file_name(name);
    match file.rfind('.') {
        Some(i) if i > 0 && i + 1 < file.len() => file[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Last path component of a `/` or `\` separated path.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Heuristic check whether a buffer is (mostly) text.
pub fn looks_like_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(8192)];
    if sample.is_empty() {
        return true;
    }
    // UTF-16 LE/BE BOM
    if sample.starts_with(&[0xFF, 0xFE]) || sample.starts_with(&[0xFE, 0xFF]) {
        return true;
    }
    if memchr::memchr(0, sample).is_some() {
        return false;
    }
    let mut bad = 0usize;
    for &b in sample {
        if b < 0x09 || (b > 0x0D && b < 0x20 && b != 0x1B) || b == 0x7F {
            bad += 1;
        }
    }
    bad * 100 <= sample.len() * 2
}

/// Reads a little-endian u16 at `off`.
pub fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a little-endian u32 at `off`.
pub fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a big-endian u16 at `off`.
pub fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off.checked_add(2)?).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// Reads a big-endian u32 at `off`.
pub fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off.checked_add(4)?).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Case-insensitive ASCII substring search.
pub fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Counts non-overlapping occurrences of `needle`.
pub fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    memchr::memmem::find_iter(haystack, needle).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn extension_and_name() {
        assert_eq!(extension("C:\\Users\\a\\Doc.PDF"), "pdf");
        assert_eq!(extension("/tmp/.bashrc"), "");
        assert_eq!(extension("archive.tar.gz"), "gz");
        assert_eq!(file_name("a/b\\c.txt"), "c.txt");
    }

    #[test]
    fn text_detection() {
        assert!(looks_like_text(b"hello world\nline 2\n"));
        assert!(!looks_like_text(&[0x4d, 0x5a, 0x00, 0x01, 0x02]));
    }
}
