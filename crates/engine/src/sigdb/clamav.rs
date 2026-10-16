//! ClamAV database formats.
//!
//! Supported: `.hdb/.hsb` (MD5 / SHA-1 / SHA-256 hash signatures),
//! `.hdu/.hsu` (same, potentially unwanted), `.ndb/.ndu` (body signatures),
//! `.fp/.sfp` (false-positive allowlists), `.ign/.ign2` (ignored signature
//! names) and `.cvd/.cld/.cud` containers produced by `freshclam` or
//! `cvdupdate`. Logical (`.ldb`), PE-section (`.mdb/.msb`), phishing and
//! bytecode signatures are skipped and counted.
//!
//! Note: check the license and usage terms of any ClamAV database you
//! download; databases are not bundled with SecCorp.

use crate::patterns::{OffsetConstraint, PatternOptions, PatternSpec, TargetFilter, parse_clamav_hex};
use crate::report::Severity;
use crate::{Error, Result};
use std::io::Read;

use super::hashdb::{ANY_SIZE, HashDbBuilder};

/// One parsed body signature, ready to be added to a pattern set.
pub struct BodySignature {
    pub name: String,
    pub spec: PatternSpec,
    pub options: PatternOptions,
    pub severity: Severity,
}

/// Counters for one imported file.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImportStats {
    pub added: u64,
    pub skipped: u64,
}

fn clean_name(name: &str) -> &str {
    name.trim().trim_end_matches(".UNOFFICIAL")
}

/// Parses `.hdb/.hsb/.hdu/.hsu` content (`hash:size:name[:flevel]`).
pub fn parse_hash_sigs(text: &str, severity: Severity, out: &mut HashDbBuilder) -> ImportStats {
    let mut st = ImportStats::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let (Some(hash), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            st.skipped += 1;
            continue;
        };
        let size = if size == "*" {
            ANY_SIZE
        } else {
            match size.parse::<u64>() {
                Ok(s) => s,
                Err(_) => {
                    st.skipped += 1;
                    continue;
                }
            }
        };
        match out.add_hex(hash, size, clean_name(name), severity) {
            Ok(()) => st.added += 1,
            Err(_) => st.skipped += 1,
        }
    }
    st
}

/// Parses `.fp/.sfp` allowlists (`hash:size:name`).
pub fn parse_allowlist(text: &str, out: &mut HashDbBuilder) -> ImportStats {
    let mut st = ImportStats::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hash = line.split(':').next().unwrap_or("");
        match out.add_allow_hex(hash) {
            Ok(()) => st.added += 1,
            Err(_) => st.skipped += 1,
        }
    }
    st
}

/// Parses `.ign/.ign2` content and returns the ignored signature names.
pub fn parse_ignore_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            // .ign format is "db:line:name"; .ign2 is just the name (optionally "name:md5").
            let parts: Vec<&str> = l.split(':').collect();
            let name = if parts.len() >= 3 { parts[2] } else { parts[0] };
            clean_name(name).to_string()
        })
        .collect()
}

fn parse_offset(spec: &str) -> Option<OffsetConstraint> {
    let spec = spec.trim();
    if spec == "*" {
        return Some(OffsetConstraint::Any);
    }
    let (base, len) = match spec.split_once(',') {
        Some((b, l)) => (b, l.parse::<u64>().ok()?),
        None => (spec, 0),
    };
    if let Ok(n) = base.parse::<u64>() {
        return Some(OffsetConstraint::Absolute { start: n, len });
    }
    if let Some(rest) = base.strip_prefix("EOF-") {
        return Some(OffsetConstraint::FromEnd { back: rest.parse().ok()?, len });
    }
    if let Some(rest) = base.strip_prefix("EP+") {
        return Some(OffsetConstraint::EntryPoint { delta: rest.parse().ok()?, len });
    }
    if let Some(rest) = base.strip_prefix("EP-") {
        let d: i64 = rest.parse().ok()?;
        return Some(OffsetConstraint::EntryPoint { delta: -d, len });
    }
    None
}

/// Parses `.ndb/.ndu` content (`name:target:offset:hexsig[:minfl[:maxfl]]`).
pub fn parse_body_sigs(text: &str, severity: Severity, out: &mut Vec<BodySignature>) -> ImportStats {
    let mut st = ImportStats::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            st.skipped += 1;
            continue;
        }
        let parsed = (|| {
            let target = TargetFilter::from_clamav(parts[1].trim().parse().ok()?)?;
            let constraint = parse_offset(parts[2])?;
            let tokens = parse_clamav_hex(parts[3]).ok()?;
            Some(BodySignature {
                name: clean_name(parts[0]).to_string(),
                spec: PatternSpec::Hex(tokens),
                options: PatternOptions { constraint, target, fullword: false, max_matches: 1 },
                severity,
            })
        })();
        match parsed {
            Some(sig) => {
                out.push(sig);
                st.added += 1;
            }
            None => st.skipped += 1,
        }
    }
    st
}

/// Header of a CVD/CLD container.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CvdHeader {
    pub build_time: String,
    pub version: u64,
    pub signatures: u64,
    pub functionality_level: u64,
}

/// Files contained in a CVD: `(file name, content)`.
pub type CvdFiles = Vec<(String, Vec<u8>)>;

/// Unpacks a `.cvd/.cld/.cud` container.
pub fn unpack_cvd(bytes: &[u8]) -> Result<(CvdHeader, CvdFiles)> {
    const MAX_ENTRY: u64 = 1 << 30;
    if bytes.len() < 512 || !bytes.starts_with(b"ClamAV-VDB:") {
        return Err(Error::Database("not a ClamAV CVD/CLD file".into()));
    }
    let header_text = String::from_utf8_lossy(&bytes[..512]);
    let fields: Vec<&str> = header_text.trim_end_matches(['\0', ' ']).split(':').collect();
    let header = CvdHeader {
        build_time: fields.get(1).copied().unwrap_or("").trim().to_string(),
        version: fields.get(2).and_then(|v| v.trim().parse().ok()).unwrap_or(0),
        signatures: fields.get(3).and_then(|v| v.trim().parse().ok()).unwrap_or(0),
        functionality_level: fields.get(4).and_then(|v| v.trim().parse().ok()).unwrap_or(0),
    };
    let body = &bytes[512..];
    let mut tar_bytes = Vec::new();
    let tar_data: &[u8] = if body.starts_with(&[0x1F, 0x8B]) {
        flate2::read::GzDecoder::new(body)
            .take(4 * MAX_ENTRY)
            .read_to_end(&mut tar_bytes)
            .map_err(|e| Error::Database(format!("CVD decompression failed: {e}")))?;
        &tar_bytes
    } else {
        body
    };
    let mut archive = tar::Archive::new(tar_data);
    let mut files = Vec::new();
    for entry in archive.entries().map_err(|e| Error::Database(format!("CVD archive error: {e}")))? {
        let mut entry = entry.map_err(|e| Error::Database(format!("CVD archive error: {e}")))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry.path().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let mut content = Vec::new();
        (&mut entry).take(MAX_ENTRY).read_to_end(&mut content).map_err(|e| Error::Database(format!("CVD read error: {e}")))?;
        files.push((name, content));
    }
    Ok((header, files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_lines() {
        let mut b = HashDbBuilder::new();
        let st =
            parse_hash_sigs("# comment\n44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test\nbadline\n0123:*:Short\n", Severity::High, &mut b);
        assert_eq!(st.added, 1);
        assert_eq!(st.skipped, 2);
    }

    #[test]
    fn body_lines() {
        let mut v = Vec::new();
        let st = parse_body_sigs(
            "Win.Test.A:1:*:4d5a{2-4}deadbeef\nTxt.Test.B:7:0:6869\nUnsupported.C:1:SL+4:aabb\nBad.D:99:*:aabb\n",
            Severity::High,
            &mut v,
        );
        assert_eq!(st.added, 2);
        assert_eq!(st.skipped, 2);
        assert_eq!(v[0].options.target, TargetFilter::Pe);
        assert_eq!(v[1].options.constraint, OffsetConstraint::Absolute { start: 0, len: 0 });
        assert_eq!(parse_offset("EP-10,5"), Some(OffsetConstraint::EntryPoint { delta: -10, len: 5 }));
        assert_eq!(parse_offset("EOF-100"), Some(OffsetConstraint::FromEnd { back: 100, len: 0 }));
    }

    #[test]
    fn cvd_roundtrip() {
        // Build a tiny CVD in memory: 512-byte header + gzip(tar).
        let mut tar_buf = Vec::new();
        {
            let mut t = tar::Builder::new(&mut tar_buf);
            let data = b"44d88612fea8a8f36de82e1278abb02f:68:Test.Sig\n";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            t.append_data(&mut h, "test.hdb", &data[..]).unwrap();
            t.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap();
        }
        let mut cvd = b"ClamAV-VDB:13 Oct 2026 10-00 +0000:27000:1:90:x:y:builder:0".to_vec();
        cvd.resize(512, b' ');
        cvd.extend_from_slice(&gz);
        let (hdr, files) = unpack_cvd(&cvd).unwrap();
        assert_eq!(hdr.version, 27000);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "test.hdb");

        let mut loader = crate::sigdb::DbLoader::new(false);
        loader.add_bytes("daily.cvd", &cvd).unwrap();
        let db = loader.build();
        assert_eq!(db.info().version, "clamav-27000");
        assert_eq!(db.info().hash_signatures, 1);

        let mut bundled_loader = crate::sigdb::DbLoader::new(false);
        let bundled_manifest = serde_json::to_vec(&crate::sigdb::DbManifest {
            name: "SecCorp bundled signatures".into(),
            version: "2026.10.16.1".into(),
            released: 1,
            min_engine: None,
        })
        .unwrap();
        bundled_loader.add_bytes("manifest.json", &bundled_manifest).unwrap();
        bundled_loader.add_bytes("daily.cvd", &cvd).unwrap();
        assert_eq!(bundled_loader.build().info().version, "clamav-27000");

        let mut signed_loader = crate::sigdb::DbLoader::new(false);
        let signed_manifest = serde_json::to_vec(&crate::sigdb::DbManifest {
            name: "SecCorp signatures".into(),
            version: "2026.10.16.2".into(),
            released: 1,
            min_engine: None,
        })
        .unwrap();
        signed_loader.add_bytes("manifest.json", &signed_manifest).unwrap();
        signed_loader.add_bytes("daily.cvd", &cvd).unwrap();
        assert_eq!(signed_loader.build().info().version, "2026.10.16.2");
    }
}
