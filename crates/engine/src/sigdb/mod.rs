//! Signature database: loading, merging and querying all signature sources.

pub mod clamav;
pub mod hashdb;
pub mod hashlist;

use crate::hashing::Hashes;
use crate::patterns::{PatternSet, PatternSetBuilder, ScanContext};
use crate::report::{Detection, DetectionKind, Severity};
use crate::rules::RuleSet;
use crate::util::{extension, file_name, now_unix};
use crate::{Error, Result};
use clamav::{BodySignature, ImportStats};
use hashdb::{HashDb, HashDbBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const BUILTIN_HSB: &str = include_str!("../../builtin/builtin.hsb");
const BUILTIN_HDB: &str = include_str!("../../builtin/builtin.hdb");
const BUILTIN_YAR: &str = include_str!("../../builtin/builtin.yar");

/// Manifest stored in every signature directory / update bundle.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct DbManifest {
    pub name: String,
    pub version: String,
    /// UNIX seconds.
    pub released: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_engine: Option<String>,
}

/// Information about one loaded source.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SourceInfo {
    pub name: String,
    pub kind: String,
    pub signatures: u64,
    pub skipped: u64,
}

/// Summary shown in the GUI.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DbInfo {
    pub version: String,
    pub released: u64,
    pub loaded_at: u64,
    pub hash_signatures: u64,
    pub body_signatures: u64,
    pub rules: u64,
    pub skipped: u64,
    pub sources: Vec<SourceInfo>,
    pub warnings: Vec<String>,
}

impl DbInfo {
    pub fn total_signatures(&self) -> u64 {
        self.hash_signatures + self.body_signatures + self.rules
    }
}

struct BodyMeta {
    name: String,
    severity: Severity,
}

/// The complete, immutable signature database.
pub struct SignatureDb {
    info: DbInfo,
    hashes: HashDb,
    body: PatternSet,
    body_text: PatternSet,
    body_meta: Vec<BodyMeta>,
    ignored: HashSet<String>,
    rules: RuleSet,
}

impl SignatureDb {
    /// Database containing only the built-in signatures.
    pub fn builtin() -> SignatureDb {
        DbLoader::new(true).build()
    }

    /// Built-in signatures plus everything found in `dirs` (missing
    /// directories are ignored).
    pub fn load_dirs(dirs: &[PathBuf]) -> Result<SignatureDb> {
        let mut loader = DbLoader::new(true);
        for d in dirs {
            if d.exists() {
                loader.add_path(d)?;
            }
        }
        Ok(loader.build())
    }

    pub fn info(&self) -> &DbInfo {
        &self.info
    }

    pub fn needs_md5(&self, size: u64) -> bool {
        self.hashes.needs_md5(size)
    }

    pub fn needs_sha1(&self, size: u64) -> bool {
        self.hashes.needs_sha1(size)
    }

    pub fn is_allowlisted(&self, hashes: &Hashes) -> bool {
        self.hashes.is_allowlisted(hashes)
    }

    pub fn lookup_hash(&self, hashes: &Hashes, size: u64) -> Option<Detection> {
        let hit = self.hashes.lookup(hashes, size)?;
        Some(Detection {
            name: hit.name,
            kind: DetectionKind::Hash,
            severity: hit.severity,
            score: 0,
            description: format!("Known malicious file ({} match)", hit.algorithm.to_uppercase()),
            location: None,
        })
    }

    /// Body (byte pattern) signatures.
    pub fn scan_body(&self, data: &[u8], ctx: &ScanContext) -> Vec<Detection> {
        let mut out = Vec::new();
        if !self.body.is_empty() {
            let m = self.body.scan(data, ctx);
            self.push_body_hits(&self.body, &m, &mut out);
        }
        if !self.body_text.is_empty() && ctx.file_type.is_textual() {
            let lower = data.to_ascii_lowercase();
            let m = self.body_text.scan(&lower, ctx);
            self.push_body_hits(&self.body_text, &m, &mut out);
        }
        out
    }

    fn push_body_hits(&self, set: &PatternSet, m: &crate::patterns::PatternMatches, out: &mut Vec<Detection>) {
        let mut seen = HashSet::new();
        for id in m.matched() {
            let meta = &self.body_meta[set.tag(id) as usize];
            if self.ignored.contains(&meta.name) || !seen.insert(meta.name.clone()) {
                continue;
            }
            out.push(Detection {
                name: meta.name.clone(),
                kind: DetectionKind::Pattern,
                severity: meta.severity,
                score: 0,
                description: "Matches a known malicious byte pattern".into(),
                location: None,
            });
        }
    }

    /// YARA-compatible rules.
    pub fn scan_rules(&self, data: &[u8], filesize: u64, ctx: &ScanContext) -> Vec<Detection> {
        self.rules
            .scan(data, filesize, ctx)
            .into_iter()
            .filter(|m| !self.ignored.contains(&m.rule) && !self.ignored.contains(&m.threat_name))
            .map(|m| Detection {
                name: m.threat_name,
                kind: DetectionKind::Rule,
                severity: m.severity,
                score: 0,
                description: if m.description.is_empty() { format!("Matched rule {}", m.rule) } else { m.description },
                location: None,
            })
            .collect()
    }

    /// A stable key identifying this database content (for caches).
    pub fn fingerprint(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.info.version, self.info.released, self.info.hash_signatures, self.info.body_signatures, self.info.rules
        )
    }
}

/// Incrementally loads signature sources.
pub struct DbLoader {
    hashes: HashDbBuilder,
    body_sigs: Vec<BodySignature>,
    rule_sources: Vec<(String, String)>,
    ignored: HashSet<String>,
    info: DbInfo,
}

impl DbLoader {
    pub fn new(include_builtin: bool) -> Self {
        let mut l = DbLoader {
            hashes: HashDbBuilder::new(),
            body_sigs: Vec::new(),
            rule_sources: Vec::new(),
            ignored: HashSet::new(),
            info: DbInfo { version: format!("builtin-{}", crate::ENGINE_VERSION), ..Default::default() },
        };
        if include_builtin {
            let a = clamav::parse_hash_sigs(BUILTIN_HSB, Severity::High, &mut l.hashes);
            let b = clamav::parse_hash_sigs(BUILTIN_HDB, Severity::High, &mut l.hashes);
            l.rule_sources.push(("builtin.yar".into(), BUILTIN_YAR.into()));
            l.info.sources.push(SourceInfo {
                name: "SecCorp built-in".into(),
                kind: "builtin".into(),
                signatures: a.added + b.added + 1,
                skipped: 0,
            });
        }
        l
    }

    /// Adds a file or every supported file inside a directory (one level of
    /// sub-directories is searched as well).
    pub fn add_path(&mut self, path: &Path) -> Result<()> {
        if path.is_dir() {
            let mut files = Vec::new();
            collect_files(path, 2, &mut files)?;
            // Ignore lists and manifests first so they apply to everything.
            files.sort_by_key(|p| {
                let ext = extension(&p.to_string_lossy());
                let rank = match ext.as_str() {
                    "json" => 0,
                    "ign" | "ign2" => 1,
                    _ => 2,
                };
                (rank, p.clone())
            });
            for f in files {
                let name = f.to_string_lossy().to_string();
                if let Err(e) = self.add_file(&f) {
                    self.info.warnings.push(format!("{name}: {e}"));
                }
            }
            Ok(())
        } else {
            self.add_file(path)
        }
    }

    fn add_file(&mut self, path: &Path) -> Result<()> {
        let bytes = std::fs::read(path).map_err(|e| Error::io_path(path, e))?;
        self.add_bytes(&path.to_string_lossy(), &bytes)
    }

    /// Adds one source given its file name (used for type detection) and content.
    pub fn add_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        let ext = extension(name);
        let short = file_name(name).to_string();
        let text = || String::from_utf8_lossy(bytes).into_owned();
        let record = |info: &mut DbInfo, kind: &str, st: ImportStats| {
            info.sources.push(SourceInfo { name: short.clone(), kind: kind.into(), signatures: st.added, skipped: st.skipped });
            info.skipped += st.skipped;
        };
        match ext.as_str() {
            "json" => {
                if file_name(name).eq_ignore_ascii_case("manifest.json") {
                    let m: DbManifest = serde_json::from_slice(bytes)?;
                    if let Some(min) = &m.min_engine
                        && crate::update::compare_versions(crate::ENGINE_VERSION, min) == std::cmp::Ordering::Less
                    {
                        return Err(Error::Database(format!("database requires engine {min} or newer")));
                    }
                    if !m.version.is_empty() {
                        self.info.version = m.version;
                        self.info.released = m.released;
                    }
                }
            }
            "hdb" | "hsb" => record(&mut self.info, "clamav-hash", clamav::parse_hash_sigs(&text(), Severity::High, &mut self.hashes)),
            "hdu" | "hsu" => record(&mut self.info, "clamav-hash-pua", clamav::parse_hash_sigs(&text(), Severity::Low, &mut self.hashes)),
            "ndb" => record(&mut self.info, "clamav-body", clamav::parse_body_sigs(&text(), Severity::High, &mut self.body_sigs)),
            "ndu" => record(&mut self.info, "clamav-body-pua", clamav::parse_body_sigs(&text(), Severity::Low, &mut self.body_sigs)),
            "fp" | "sfp" => record(&mut self.info, "allowlist", clamav::parse_allowlist(&text(), &mut self.hashes)),
            "ign" | "ign2" => {
                for n in clamav::parse_ignore_list(&text()) {
                    self.hashes.ignore_name(&n);
                    self.ignored.insert(n);
                }
            }
            "cvd" | "cld" | "cud" => {
                let (header, files) = clamav::unpack_cvd(bytes)?;
                // Process ignore lists first.
                let mut files = files;
                files.sort_by_key(|(n, _)| !matches!(extension(n).as_str(), "ign" | "ign2"));
                let before = self.info.sources.len();
                for (inner, content) in files {
                    let inner_name = format!("{short}/{inner}");
                    if let Err(e) = self.add_bytes(&inner_name, &content) {
                        self.info.warnings.push(format!("{inner_name}: {e}"));
                    }
                }
                let added: u64 = self.info.sources[before..].iter().map(|s| s.signatures).sum();
                let skipped: u64 = self.info.sources[before..].iter().map(|s| s.skipped).sum();
                self.info.sources.truncate(before);
                self.info.sources.push(SourceInfo {
                    name: format!("{short} (v{})", header.version),
                    kind: "clamav-cvd".into(),
                    signatures: added,
                    skipped,
                });
            }
            "yar" | "yara" => {
                self.rule_sources.push((short.clone(), text()));
            }
            "txt" | "csv" | "sha256" | "md5" | "sha1" | "hashes" | "lst" => {
                let source = short.rsplit_once('.').map(|(s, _)| s).unwrap_or(&short).to_string();
                record(&mut self.info, "hash-list", hashlist::parse_hash_list(&text(), &source, &mut self.hashes))
            }
            // Recognised ClamAV formats we do not implement.
            "ldb" | "ldu" | "mdb" | "mdu" | "msb" | "msu" | "cdb" | "pdb" | "gdb" | "wdb" | "ftm" | "idb" | "crb" | "cbc" | "hdbx"
            | "imp" | "pwdb" | "info" | "cfg" | "sign" => {}
            _ => {}
        }
        Ok(())
    }

    pub fn build(mut self) -> SignatureDb {
        let mut body = PatternSetBuilder::new();
        let mut body_text = PatternSetBuilder::new();
        let mut body_meta = Vec::with_capacity(self.body_sigs.len());
        for sig in self.body_sigs.drain(..) {
            let tag = body_meta.len() as u32;
            let set = if sig.options.target.is_normalized_text() { &mut body_text } else { &mut body };
            match set.add(tag, sig.spec, sig.options) {
                Ok(_) => body_meta.push(BodyMeta { name: sig.name, severity: sig.severity }),
                Err(e) => {
                    self.info.skipped += 1;
                    log::debug!("body signature {} skipped: {e}", sig.name);
                }
            }
        }
        let rules = RuleSet::compile(&self.rule_sources);
        self.info.warnings.extend(rules.warnings.iter().cloned());
        for (origin, compiled, skipped) in &rules.origins {
            if origin != "builtin.yar" {
                self.info.sources.push(SourceInfo { name: origin.clone(), kind: "yara".into(), signatures: *compiled, skipped: *skipped });
                self.info.skipped += *skipped;
            }
        }
        let hashes = self.hashes.build();
        self.info.hash_signatures = hashes.len() as u64;
        self.info.body_signatures = body_meta.len() as u64;
        self.info.rules = rules.len() as u64;
        self.info.loaded_at = now_unix();
        if self.info.warnings.len() > 200 {
            let extra = self.info.warnings.len() - 200;
            self.info.warnings.truncate(200);
            self.info.warnings.push(format!("... and {extra} more warnings"));
        }
        SignatureDb { info: self.info, hashes, body: body.build(), body_text: body_text.build(), body_meta, ignored: self.ignored, rules }
    }
}

fn collect_files(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) -> Result<()> {
    let rd = std::fs::read_dir(dir).map_err(|e| Error::io_path(dir, e))?;
    for entry in rd.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if depth > 1 {
                collect_files(&p, depth - 1, out)?;
            }
        } else if ft.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filetype::FileType;
    use crate::hashing::hash_bytes;

    /// The EICAR test string, assembled at runtime (see builtin.yar).
    pub(crate) fn eicar() -> Vec<u8> {
        let rev = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
        rev.bytes().rev().collect()
    }

    #[test]
    fn builtin_detects_eicar_by_hash_and_rule() {
        let db = SignatureDb::builtin();
        assert!(db.info().hash_signatures >= 2);
        assert_eq!(db.info().rules, 1, "{:?}", db.info().warnings);
        let e = eicar();
        let h = hash_bytes(&e, db.needs_md5(e.len() as u64), false);
        assert_eq!(db.lookup_hash(&h, e.len() as u64).unwrap().name, "EICAR-Test-File");
        let ctx = ScanContext { file_type: FileType::Text, entry_point: None };
        let mut with_newline = e.clone();
        with_newline.extend_from_slice(b"\r\n");
        let r = db.scan_rules(&with_newline, with_newline.len() as u64, &ctx);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "EICAR-Test-File");
        assert!(db.scan_rules(b"hello", 5, &ctx).is_empty());
    }

    #[test]
    fn loads_directory_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("manifest.json"), r#"{"name":"t","version":"2026.10.13.1","released":1790000000}"#).unwrap();
        std::fs::write(dir.path().join("custom.ndb"), "Test.Body.Sig:0:*:deadbeef??cafe\nTest.Text.Sig:7:*:68656c6c6f\n").unwrap();
        std::fs::write(dir.path().join("rules.yar"), "rule Custom { strings: $a = \"marker-123\" condition: $a }").unwrap();
        let sha = hex::encode(hash_bytes(b"bad file", false, false).sha256);
        std::fs::write(dir.path().join("list.txt"), format!("{sha} Bad.File\n")).unwrap();
        std::fs::write(dir.path().join("skip.ign2"), "Test.Ignored\n").unwrap();
        std::fs::write(dir.path().join("ignored.ndb"), "Test.Ignored:0:*:0102030405\n").unwrap();

        let db = SignatureDb::load_dirs(&[dir.path().to_path_buf()]).unwrap();
        let info = db.info();
        assert_eq!(info.version, "2026.10.13.1");
        assert_eq!(info.body_signatures, 3);
        assert_eq!(info.rules, 2);

        let ctx = ScanContext { file_type: FileType::Unknown, entry_point: None };
        let d = db.scan_body(&[0, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xca, 0xfe], &ctx);
        assert_eq!(d[0].name, "Test.Body.Sig");
        assert!(db.scan_body(&[1, 2, 3, 4, 5], &ctx).is_empty(), "ignored signature must not fire");
        let text_ctx = ScanContext { file_type: FileType::Text, entry_point: None };
        assert_eq!(db.scan_body(b"Say HELLO world", &text_ctx)[0].name, "Test.Text.Sig");
        assert_eq!(db.scan_rules(b"xx marker-123", 13, &ctx)[0].name, "Custom");
        let h = hash_bytes(b"bad file", false, false);
        assert_eq!(db.lookup_hash(&h, 8).unwrap().name, "Bad.File");
    }
}
