//! In-memory archive unpacking with decompression-bomb protection.
//!
//! Supported containers: ZIP (including APK, JAR, IPA and Office Open XML),
//! GZIP and TAR. Every entry is size-limited while it is being read, so
//! forged size fields cannot bypass the limits.

use crate::filetype::FileType;
use std::cell::Cell;
use std::io::{Cursor, Read};

/// Limits applied while unpacking one top-level file.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    /// Maximum size of a single extracted entry.
    pub max_entry: u64,
    pub max_ratio: u64,
}

/// What happened while walking one archive.
#[derive(Debug, Default, Clone)]
pub struct ArchiveReport {
    pub entries: usize,
    pub bytes: u64,
    /// Names of encrypted entries that could not be scanned.
    pub encrypted: Vec<String>,
    /// Set when bomb heuristics triggered (entry name).
    pub bomb: Option<String>,
    /// Entry or byte budget exhausted.
    pub truncated: bool,
    pub error: Option<String>,
}

/// Visitor callback: `(entry name, entry bytes)`. Return `false` to stop.
pub type EntryVisitor<'a> = dyn FnMut(&str, &[u8]) -> bool + 'a;

/// Walks the entries of `data`. `budget` is the remaining number of bytes
/// that may be extracted (shared by nested archives).
pub fn walk(
    data: &[u8],
    ft: FileType,
    outer_name: &str,
    limits: &ArchiveLimits,
    budget: &Cell<u64>,
    cancelled: &dyn Fn() -> bool,
    visit: &mut EntryVisitor,
) -> ArchiveReport {
    let mut report = ArchiveReport::default();
    match ft {
        FileType::Zip => walk_zip(data, limits, budget, cancelled, visit, &mut report),
        FileType::Gzip => walk_gzip(data, outer_name, limits, budget, visit, &mut report),
        FileType::Tar => walk_tar(data, limits, budget, cancelled, visit, &mut report),
        _ => {}
    }
    report
}

fn read_limited<R: Read>(r: R, limit: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    r.take(limit + 1).read_to_end(&mut buf)?;
    let over = buf.len() as u64 > limit;
    if over {
        buf.truncate(limit as usize);
    }
    Ok((buf, over))
}

fn walk_zip(
    data: &[u8],
    limits: &ArchiveLimits,
    budget: &Cell<u64>,
    cancelled: &dyn Fn() -> bool,
    visit: &mut EntryVisitor,
    report: &mut ArchiveReport,
) {
    let mut zip = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(z) => z,
        Err(e) => {
            report.error = Some(format!("zip: {e}"));
            return;
        }
    };
    for i in 0..zip.len() {
        if cancelled() {
            return;
        }
        if report.entries >= limits.max_entries || budget.get() == 0 {
            report.truncated = true;
            return;
        }
        let (name, encrypted, is_dir, declared, compressed) = match zip.by_index_raw(i) {
            Ok(f) => (
                f.name().map(|n| n.into_owned()).unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned()),
                f.encrypted(),
                f.is_dir(),
                f.size(),
                f.compressed_size(),
            ),
            Err(_) => continue,
        };
        if is_dir {
            continue;
        }
        if encrypted {
            report.encrypted.push(name);
            continue;
        }
        if compressed > 0 && declared > 16 << 20 && declared / compressed > limits.max_ratio {
            report.bomb = Some(name);
            return;
        }
        let limit = limits.max_entry.min(budget.get());
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let (buf, over) = match read_limited(&mut f, limit) {
            Ok(r) => r,
            Err(_) => continue,
        };
        report.entries += 1;
        report.bytes += buf.len() as u64;
        budget.set(budget.get().saturating_sub(buf.len() as u64));
        if over {
            // Real data exceeded the limit: check the actual ratio.
            if compressed > 0 && (limit / compressed.max(1)) > limits.max_ratio {
                report.bomb = Some(name);
                return;
            }
            report.truncated = true;
        }
        if !visit(&name, &buf) {
            return;
        }
    }
}

fn walk_gzip(
    data: &[u8],
    outer_name: &str,
    limits: &ArchiveLimits,
    budget: &Cell<u64>,
    visit: &mut EntryVisitor,
    report: &mut ArchiveReport,
) {
    let limit = limits.max_entry.min(budget.get());
    let decoder = flate2::read::MultiGzDecoder::new(data);
    let (buf, over) = match read_limited(decoder, limit) {
        Ok(r) => r,
        Err(e) => {
            report.error = Some(format!("gzip: {e}"));
            return;
        }
    };
    if over && (limit / (data.len() as u64).max(1)) > limits.max_ratio {
        report.bomb = Some(outer_name.to_string());
        return;
    }
    report.truncated |= over;
    report.entries = 1;
    report.bytes = buf.len() as u64;
    budget.set(budget.get().saturating_sub(buf.len() as u64));
    let base = crate::util::file_name(outer_name);
    let inner = base
        .strip_suffix(".gz")
        .or_else(|| base.strip_suffix(".GZ"))
        .map(str::to_string)
        .or_else(|| base.strip_suffix(".tgz").map(|s| format!("{s}.tar")))
        .unwrap_or_else(|| format!("{base}.out"));
    visit(&inner, &buf);
}

fn walk_tar(
    data: &[u8],
    limits: &ArchiveLimits,
    budget: &Cell<u64>,
    cancelled: &dyn Fn() -> bool,
    visit: &mut EntryVisitor,
    report: &mut ArchiveReport,
) {
    let mut ar = tar::Archive::new(Cursor::new(data));
    let entries = match ar.entries() {
        Ok(e) => e,
        Err(e) => {
            report.error = Some(format!("tar: {e}"));
            return;
        }
    };
    for entry in entries {
        if cancelled() {
            return;
        }
        if report.entries >= limits.max_entries || budget.get() == 0 {
            report.truncated = true;
            return;
        }
        let Ok(mut entry) = entry else { break };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let limit = limits.max_entry.min(budget.get());
        let Ok((buf, over)) = read_limited(&mut entry, limit) else { continue };
        report.entries += 1;
        report.bytes += buf.len() as u64;
        report.truncated |= over;
        budget.set(budget.get().saturating_sub(buf.len() as u64));
        if !visit(&name, &buf) {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn limits() -> ArchiveLimits {
        ArchiveLimits { max_entries: 100, max_entry: 1 << 20, max_ratio: 100 }
    }

    #[test]
    fn walks_zip_entries() {
        let z = make_zip(&[("a.txt", b"hello"), ("dir/b.bin", &[1, 2, 3])]);
        let mut seen = Vec::new();
        let budget = Cell::new(10 << 20);
        let r = walk(&z, FileType::Zip, "x.zip", &limits(), &budget, &|| false, &mut |n, d| {
            seen.push((n.to_string(), d.len()));
            true
        });
        assert_eq!(r.entries, 2);
        assert_eq!(seen, vec![("a.txt".to_string(), 5), ("dir/b.bin".to_string(), 3)]);
    }

    #[test]
    fn detects_zip_bomb_by_real_size() {
        // 4 MiB of zeros compresses to a few KB: ratio far above the limit.
        let zeros = vec![0u8; 4 << 20];
        let z = make_zip(&[("zeros.bin", &zeros)]);
        let budget = Cell::new(100 << 20);
        let lim = ArchiveLimits { max_entries: 10, max_entry: 1 << 20, max_ratio: 50 };
        let r = walk(&z, FileType::Zip, "bomb.zip", &lim, &budget, &|| false, &mut |_, _| true);
        assert_eq!(r.bomb.as_deref(), Some("zeros.bin"));
    }

    #[test]
    fn gzip_and_tar() {
        let mut tar_buf = Vec::new();
        {
            let mut t = tar::Builder::new(&mut tar_buf);
            let mut h = tar::Header::new_gnu();
            h.set_size(4);
            h.set_mode(0o644);
            h.set_cksum();
            t.append_data(&mut h, "inner/file.txt", &b"data"[..]).unwrap();
            t.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_buf).unwrap();
        let gz = gz.finish().unwrap();
        let budget = Cell::new(10 << 20);
        let mut inner = Vec::new();
        walk(&gz, FileType::Gzip, "pkg.tgz", &limits(), &budget, &|| false, &mut |n, d| {
            inner.push((n.to_string(), d.to_vec()));
            true
        });
        assert_eq!(inner[0].0, "pkg.tar");
        let mut names = Vec::new();
        walk(&inner[0].1, FileType::Tar, "pkg.tar", &limits(), &budget, &|| false, &mut |n, _| {
            names.push(n.to_string());
            true
        });
        assert_eq!(names, vec!["inner/file.txt"]);
    }
}
