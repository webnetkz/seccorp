//! Signed signature-database updates.
//!
//! A release consists of two files hosted on any static web server:
//!
//! * `seccom-db-<version>.tar.gz` – the bundle (signature files + `manifest.json`);
//! * `update.json` – an [`UpdateIndex`] with the bundle URL, size, SHA-256 and an
//!   Ed25519 signature over the bundle bytes.
//!
//! Clients only accept bundles signed with the public key compiled into the
//! application, never install an older version than the current one, extract
//! into a staging directory with path-traversal protection, validate the
//! database by loading it, and then swap it in atomically (keeping the previous
//! version for rollback).

use crate::hashing::sha256_hex;
use crate::sigdb::{DbLoader, DbManifest};
use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_TOTAL: u64 = 4 << 30;

/// `update.json` published next to a bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIndex {
    pub version: String,
    pub released: u64,
    /// Bundle URL (absolute, or relative to the `update.json` URL).
    pub url: String,
    pub size: u64,
    pub sha256: String,
    /// Hex-encoded Ed25519 signature over the raw bundle bytes.
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Compares dotted versions numerically (`2026.10.2 < 2026.10.10`).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let split = |s: &str| -> Vec<String> { s.trim_start_matches(['v', 'V']).split(['.', '-', '+']).map(str::to_string).collect() };
    let (pa, pb) = (split(a), split(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).map(String::as_str).unwrap_or("0");
        let y = pb.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(m), Ok(n)) => m.cmp(&n),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Parses a hex-encoded 32-byte Ed25519 public key.
pub fn parse_public_key(hex_key: &str) -> Result<VerifyingKey> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut bytes).map_err(|_| Error::Signature("public key must be 64 hex characters".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| Error::Signature(format!("invalid public key: {e}")))
}

/// Checks size, SHA-256 and the Ed25519 signature of a downloaded bundle.
pub fn verify_bundle(bundle: &[u8], index: &UpdateIndex, key: &VerifyingKey) -> Result<()> {
    if bundle.len() as u64 != index.size {
        return Err(Error::Update(format!("size mismatch: expected {}, got {}", index.size, bundle.len())));
    }
    let digest = sha256_hex(bundle);
    if !digest.eq_ignore_ascii_case(index.sha256.trim()) {
        return Err(Error::Update("SHA-256 mismatch".into()));
    }
    let sig_bytes = hex::decode(index.signature.trim()).map_err(|_| Error::Signature("signature is not hex".into()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Error::Signature("malformed signature".into()))?;
    key.verify_strict(bundle, &sig).map_err(|_| Error::Signature("bundle signature does not match the trusted key".into()))
}

/// Generates a new Ed25519 key pair `(secret seed, public key)`.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Other(format!("random generator failed: {e}")))?;
    let sk = SigningKey::from_bytes(&seed);
    Ok((seed, sk.verifying_key().to_bytes()))
}

/// Signs bundle bytes, returning a hex signature.
pub fn sign_bundle(bundle: &[u8], secret_seed: &[u8; 32]) -> String {
    let sk = SigningKey::from_bytes(secret_seed);
    hex::encode(sk.sign(bundle).to_bytes())
}

/// Packs a signature directory into a `.tar.gz` bundle with a fresh manifest.
pub fn create_bundle(src_dir: &Path, manifest: &DbManifest) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect(src_dir, src_dir, &mut files)?;
    files.sort();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    {
        let mut tar = tar::Builder::new(&mut gz);
        let manifest_json = serde_json::to_vec_pretty(manifest)?;
        append(&mut tar, "manifest.json", &manifest_json)?;
        for rel in files {
            if rel == Path::new("manifest.json") {
                continue;
            }
            let data = std::fs::read(src_dir.join(&rel)).map_err(|e| Error::io_path(src_dir.join(&rel), e))?;
            append(&mut tar, &rel.to_string_lossy().replace('\\', "/"), &data)?;
        }
        tar.finish()?;
    }
    Ok(gz.finish()?)
}

fn append<W: Write>(tar: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_cksum();
    tar.append_data(&mut h, name, data)?;
    Ok(())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir).map_err(|e| Error::io_path(dir, e))?.flatten() {
        let p = e.path();
        let ft = e.file_type()?;
        if ft.is_dir() {
            collect(root, &p, out)?;
        } else if ft.is_file() {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }
            out.push(p.strip_prefix(root).unwrap_or(&p).to_path_buf());
        }
    }
    Ok(())
}

/// Creates the `update.json` index for a bundle.
pub fn build_index(bundle: &[u8], manifest: &DbManifest, url: &str, secret_seed: &[u8; 32]) -> UpdateIndex {
    UpdateIndex {
        version: manifest.version.clone(),
        released: manifest.released,
        url: url.to_string(),
        size: bundle.len() as u64,
        sha256: sha256_hex(bundle),
        signature: sign_bundle(bundle, secret_seed),
        min_engine: manifest.min_engine.clone(),
        notes: None,
    }
}

fn safe_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Extracts a verified bundle, validates it and makes it the current database
/// under `db_root/current` (the old one is kept as `db_root/previous`).
/// `current_version` prevents downgrades.
pub fn install_bundle(bundle: &[u8], db_root: &Path, current_version: Option<&str>) -> Result<DbManifest> {
    std::fs::create_dir_all(db_root).map_err(|e| Error::io_path(db_root, e))?;
    let staging = db_root.join(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<DbManifest> {
        std::fs::create_dir_all(&staging).map_err(|e| Error::io_path(&staging, e))?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bundle));
        let mut total = 0u64;
        let mut count = 0usize;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let rel = entry.path()?.into_owned();
            let rel = safe_relative(&rel).ok_or_else(|| Error::Update(format!("unsafe path in bundle: {}", rel.display())))?;
            count += 1;
            if count > MAX_BUNDLE_FILES {
                return Err(Error::Update("bundle contains too many files".into()));
            }
            let dest = staging.join(&rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io_path(parent, e))?;
            }
            let mut data = Vec::new();
            (&mut entry).take(MAX_BUNDLE_TOTAL - total + 1).read_to_end(&mut data)?;
            total += data.len() as u64;
            if total > MAX_BUNDLE_TOTAL {
                return Err(Error::Update("bundle is too large".into()));
            }
            std::fs::write(&dest, &data).map_err(|e| Error::io_path(&dest, e))?;
        }
        let manifest_path = staging.join("manifest.json");
        let manifest: DbManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).map_err(|_| Error::Update("bundle has no manifest.json".into()))?)?;
        if manifest.version.is_empty() {
            return Err(Error::Update("manifest has no version".into()));
        }
        if let Some(cur) = current_version
            && compare_versions(&manifest.version, cur) != Ordering::Greater
        {
            return Err(Error::Update(format!("bundle {} is not newer than installed {cur}", manifest.version)));
        }
        // Validate: the database must load and must not be empty.
        let mut loader = DbLoader::new(false);
        loader.add_path(&staging)?;
        let db = loader.build();
        if db.info().total_signatures() == 0 {
            return Err(Error::Update("bundle contains no signatures".into()));
        }
        Ok(manifest)
    })();

    let manifest = match result {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    let current = db_root.join("current");
    let previous = db_root.join("previous");
    if previous.exists() {
        std::fs::remove_dir_all(&previous).map_err(|e| Error::io_path(&previous, e))?;
    }
    if current.exists() {
        std::fs::rename(&current, &previous).map_err(|e| Error::io_path(&current, e))?;
    }
    if let Err(e) = std::fs::rename(&staging, &current) {
        // Try to restore the previous database.
        if previous.exists() {
            let _ = std::fs::rename(&previous, &current);
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(Error::io_path(&current, e));
    }
    Ok(manifest)
}

/// Restores `db_root/previous` as the current database.
pub fn rollback(db_root: &Path) -> Result<()> {
    let current = db_root.join("current");
    let previous = db_root.join("previous");
    if !previous.exists() {
        return Err(Error::Update("no previous database to roll back to".into()));
    }
    let tmp = db_root.join(format!(".rollback-{}", uuid::Uuid::new_v4().simple()));
    if current.exists() {
        std::fs::rename(&current, &tmp).map_err(|e| Error::io_path(&current, e))?;
    }
    std::fs::rename(&previous, &current).map_err(|e| Error::io_path(&previous, e))?;
    if tmp.exists() {
        let _ = std::fs::rename(&tmp, &previous);
    }
    Ok(())
}

/// Resolves the bundle URL of an index relative to the index URL.
pub fn resolve_bundle_url(index_url: &str, bundle_url: &str) -> String {
    if bundle_url.starts_with("https://") || bundle_url.starts_with("http://") {
        return bundle_url.to_string();
    }
    match index_url.rfind('/') {
        Some(i) => format!("{}/{}", &index_url[..i], bundle_url.trim_start_matches('/')),
        None => bundle_url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db_dir(dir: &Path) {
        std::fs::write(dir.join("rules.yar"), "rule UpdTest { strings: $a = \"update-marker\" condition: $a }").unwrap();
        std::fs::create_dir_all(dir.join("hashes")).unwrap();
        std::fs::write(dir.join("hashes/list.txt"), format!("{}\n", "a".repeat(64))).unwrap();
    }

    #[test]
    fn version_ordering() {
        assert_eq!(compare_versions("2026.10.2", "2026.10.10"), Ordering::Less);
        assert_eq!(compare_versions("v1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(compare_versions("2", "1.9.9"), Ordering::Greater);
    }

    #[test]
    fn sign_verify_install_and_rollback() {
        let src = tempfile::tempdir().unwrap();
        make_db_dir(src.path());
        let (secret, public) = generate_keypair().unwrap();
        let key = VerifyingKey::from_bytes(&public).unwrap();

        let m1 = DbManifest { name: "test".into(), version: "2026.10.13.1".into(), released: 1, min_engine: None };
        let b1 = create_bundle(src.path(), &m1).unwrap();
        let idx = build_index(&b1, &m1, "seccom-db.tar.gz", &secret);
        verify_bundle(&b1, &idx, &key).unwrap();

        // Tampering is detected.
        let mut bad = b1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(verify_bundle(&bad, &idx, &key).is_err());
        let mut forged = idx.clone();
        forged.sha256 = sha256_hex(&bad);
        assert!(matches!(verify_bundle(&bad, &forged, &key), Err(Error::Signature(_))));
        let (_, other_pub) = generate_keypair().unwrap();
        assert!(verify_bundle(&b1, &idx, &VerifyingKey::from_bytes(&other_pub).unwrap()).is_err());

        let root = tempfile::tempdir().unwrap();
        let installed = install_bundle(&b1, root.path(), None).unwrap();
        assert_eq!(installed.version, "2026.10.13.1");
        assert!(root.path().join("current/rules.yar").exists());
        assert!(root.path().join("current/hashes/list.txt").exists());

        // Same version again is refused (no downgrade / replay).
        assert!(install_bundle(&b1, root.path(), Some("2026.10.13.1")).is_err());

        let m2 = DbManifest { version: "2026.10.14.1".into(), ..m1.clone() };
        let b2 = create_bundle(src.path(), &m2).unwrap();
        install_bundle(&b2, root.path(), Some("2026.10.13.1")).unwrap();
        assert!(root.path().join("previous/manifest.json").exists());
        rollback(root.path()).unwrap();
        let cur: DbManifest = serde_json::from_slice(&std::fs::read(root.path().join("current/manifest.json")).unwrap()).unwrap();
        assert_eq!(cur.version, "2026.10.13.1");
    }

    #[test]
    fn rejects_path_traversal() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        {
            let mut t = tar::Builder::new(&mut gz);
            let data = b"x";
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            // Write the raw name bytes to bypass tar-rs path validation.
            {
                let name = b"../evil.txt";
                let gnu = h.as_gnu_mut().unwrap();
                gnu.name[..name.len()].copy_from_slice(name);
            }
            h.set_cksum();
            t.append(&h, &data[..]).unwrap();
            t.finish().unwrap();
        }
        let bundle = gz.finish().unwrap();
        let root = tempfile::tempdir().unwrap();
        assert!(install_bundle(&bundle, root.path(), None).is_err());
        assert!(!root.path().parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn bundle_url_resolution() {
        assert_eq!(resolve_bundle_url("https://h/db/update.json", "b.tar.gz"), "https://h/db/b.tar.gz");
        assert_eq!(resolve_bundle_url("https://h/update.json", "https://cdn/b.tar.gz"), "https://cdn/b.tar.gz");
    }
}
