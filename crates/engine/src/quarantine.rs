//! Encrypted quarantine vault.
//!
//! Quarantined files are encrypted with ChaCha20-Poly1305 (chunked STREAM
//! construction, 1 MiB chunks) using a per-installation random key, so they
//! cannot be executed or opened by accident and are not re-detected by other
//! security products. Metadata is stored next to each item as JSON.
//!
//! Vault layout: `<dir>/vault.key`, `<dir>/<id>.bin`, `<dir>/<id>.json`.

use crate::hashing::MultiHasher;
use crate::util::{file_name, now_unix};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"SCQ1";
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;

/// Metadata of a quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub threat: String,
    pub size: u64,
    pub sha256: String,
    pub quarantined_at: u64,
}

pub struct Quarantine {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
}

fn nonce(base: &[u8; 7], counter: u32, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(base);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    Nonce::from(n)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

impl Quarantine {
    /// Opens (or creates) the vault in `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io_path(dir, e))?;
        let key_path = dir.join("vault.key");
        let key: [u8; 32] = match std::fs::read(&key_path) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            Ok(_) => return Err(Error::Quarantine("vault key is corrupted".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut k = [0u8; 32];
                getrandom::fill(&mut k).map_err(|e| Error::Quarantine(format!("random generator failed: {e}")))?;
                write_private(&key_path, &k)?;
                k
            }
            Err(e) => return Err(Error::io_path(&key_path, e)),
        };
        Ok(Quarantine { dir: dir.to_path_buf(), cipher: ChaCha20Poly1305::new(&Key::from(key)) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn paths(&self, id: &str) -> (PathBuf, PathBuf) {
        (self.dir.join(format!("{id}.bin")), self.dir.join(format!("{id}.json")))
    }

    /// Moves `path` into the vault.
    pub fn add(&self, path: &Path, threat: &str) -> Result<QuarantineItem> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let (bin, meta) = self.paths(&id);
        let tmp = self.dir.join(format!("{id}.bin.tmp"));

        let mut src = std::fs::File::open(path).map_err(|e| Error::io_path(path, e))?;
        let mut base = [0u8; 7];
        getrandom::fill(&mut base).map_err(|e| Error::Quarantine(format!("random generator failed: {e}")))?;
        let mut hasher = MultiHasher::new(false, false);
        let mut size = 0u64;
        let result = (|| -> Result<()> {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp).map_err(|e| Error::io_path(&tmp, e))?);
            out.write_all(MAGIC)?;
            out.write_all(&base)?;
            let mut cur = vec![0u8; CHUNK];
            let mut next = vec![0u8; CHUNK];
            let mut cur_len = read_full(&mut src, &mut cur)?;
            let mut counter = 0u32;
            loop {
                let next_len = if cur_len == CHUNK { read_full(&mut src, &mut next)? } else { 0 };
                let last = next_len == 0;
                hasher.update(&cur[..cur_len]);
                size += cur_len as u64;
                let ct = self
                    .cipher
                    .encrypt(&nonce(&base, counter, last), &cur[..cur_len])
                    .map_err(|_| Error::Quarantine("encryption failed".into()))?;
                out.write_all(&(ct.len() as u32).to_le_bytes())?;
                out.write_all(&ct)?;
                if last {
                    break;
                }
                counter = counter.checked_add(1).ok_or_else(|| Error::Quarantine("file too large".into()))?;
                std::mem::swap(&mut cur, &mut next);
                cur_len = next_len;
            }
            out.flush()?;
            out.get_ref().sync_all().ok();
            Ok(())
        })();
        drop(src);
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        let item = QuarantineItem {
            id: id.clone(),
            original_path: path.to_string_lossy().into_owned(),
            file_name: file_name(&path.to_string_lossy()).to_string(),
            threat: threat.to_string(),
            size,
            sha256: hex::encode(hasher.finish().sha256),
            quarantined_at: now_unix(),
        };
        std::fs::rename(&tmp, &bin).map_err(|e| Error::io_path(&bin, e))?;
        std::fs::write(&meta, serde_json::to_vec_pretty(&item)?).map_err(|e| Error::io_path(&meta, e))?;

        // Finally remove the original. Clear read-only flags first (Windows).
        if let Ok(m) = std::fs::metadata(path) {
            let mut perms = m.permissions();
            if perms.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        if let Err(e) = std::fs::remove_file(path) {
            let _ = std::fs::remove_file(&bin);
            let _ = std::fs::remove_file(&meta);
            return Err(Error::Quarantine(format!("could not remove the original file (it may be in use): {e}")));
        }
        Ok(item)
    }

    /// Lists vault items, newest first.
    pub fn list(&self) -> Result<Vec<QuarantineItem>> {
        let mut items = Vec::new();
        for e in std::fs::read_dir(&self.dir).map_err(|e| Error::io_path(&self.dir, e))?.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p)
                && let Ok(item) = serde_json::from_slice::<QuarantineItem>(&bytes)
                && self.paths(&item.id).0.exists()
            {
                items.push(item);
            }
        }
        items.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at).then(a.id.cmp(&b.id)));
        Ok(items)
    }

    pub fn get(&self, id: &str) -> Result<QuarantineItem> {
        if !valid_id(id) {
            return Err(Error::Quarantine("invalid item id".into()));
        }
        let (_, meta) = self.paths(id);
        let bytes = std::fs::read(&meta).map_err(|e| Error::io_path(&meta, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Decrypts an item into `writer`, verifying integrity.
    fn decrypt_to<W: Write>(&self, id: &str, writer: &mut W) -> Result<(u64, String)> {
        let (bin, _) = self.paths(id);
        let mut f = std::io::BufReader::new(std::fs::File::open(&bin).map_err(|e| Error::io_path(&bin, e))?);
        let mut header = [0u8; 11];
        f.read_exact(&mut header)?;
        if &header[..4] != MAGIC {
            return Err(Error::Quarantine("not a vault file".into()));
        }
        let base: [u8; 7] = header[4..11].try_into().unwrap();
        let mut hasher = MultiHasher::new(false, false);
        let mut total = 0u64;
        let mut counter = 0u32;
        loop {
            let mut len = [0u8; 4];
            if read_full(&mut f, &mut len)? != 4 {
                return Err(Error::Quarantine("vault file is truncated".into()));
            }
            let len = u32::from_le_bytes(len) as usize;
            if len > CHUNK + TAG {
                return Err(Error::Quarantine("vault file is corrupted".into()));
            }
            let mut ct = vec![0u8; len];
            f.read_exact(&mut ct)?;
            // The nonce encodes whether this is the final chunk; exactly one variant authenticates.
            let (pt, last) = match self.cipher.decrypt(&nonce(&base, counter, false), ct.as_slice()) {
                Ok(pt) => (pt, false),
                Err(_) => (
                    self.cipher
                        .decrypt(&nonce(&base, counter, true), ct.as_slice())
                        .map_err(|_| Error::Quarantine("vault file failed authentication".into()))?,
                    true,
                ),
            };
            hasher.update(&pt);
            total += pt.len() as u64;
            writer.write_all(&pt)?;
            if last {
                let mut extra = [0u8; 1];
                if read_full(&mut f, &mut extra)? != 0 {
                    return Err(Error::Quarantine("unexpected data after the final chunk".into()));
                }
                break;
            }
            counter = counter.checked_add(1).ok_or_else(|| Error::Quarantine("vault file is corrupted".into()))?;
        }
        Ok((total, hex::encode(hasher.finish().sha256)))
    }

    /// Restores an item to its original location (or `target`). If a file
    /// already exists there, a numbered name is used. Returns the new path.
    pub fn restore(&self, id: &str, target: Option<&Path>) -> Result<PathBuf> {
        let item = self.get(id)?;
        let wanted = target.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&item.original_path));
        if let Some(parent) = wanted.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io_path(parent, e))?;
        }
        let dest = unique_path(&wanted);
        let tmp =
            dest.with_file_name(format!(".{}.restore", dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
        let result = (|| -> Result<()> {
            let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp).map_err(|e| Error::io_path(&tmp, e))?);
            let (_, sha) = self.decrypt_to(id, &mut out)?;
            out.flush()?;
            if !sha.eq_ignore_ascii_case(&item.sha256) {
                return Err(Error::Quarantine("restored data does not match the original checksum".into()));
            }
            Ok(())
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, &dest).map_err(|e| Error::io_path(&dest, e))?;
        self.delete(id)?;
        Ok(dest)
    }

    /// Decrypts an item into memory (for re-scanning or exporting samples).
    pub fn read(&self, id: &str) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.decrypt_to(id, &mut v)?;
        Ok(v)
    }

    /// Permanently deletes an item.
    pub fn delete(&self, id: &str) -> Result<()> {
        if !valid_id(id) {
            return Err(Error::Quarantine("invalid item id".into()));
        }
        let (bin, meta) = self.paths(id);
        if bin.exists() {
            std::fs::remove_file(&bin).map_err(|e| Error::io_path(&bin, e))?;
        }
        if meta.exists() {
            std::fs::remove_file(&meta).map_err(|e| Error::io_path(&meta, e))?;
        }
        Ok(())
    }

    /// Total size of the original files in the vault.
    pub fn total_size(&self) -> u64 {
        self.list().map(|l| l.iter().map(|i| i.size).sum()).unwrap_or(0)
    }
}

fn unique_path(p: &Path) -> PathBuf {
    if !p.exists() {
        return p.to_path_buf();
    }
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    for i in 1..10_000 {
        let candidate = p.with_file_name(format!("{stem} (restored {i}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    p.with_file_name(format!("{stem} (restored {}){ext}", uuid::Uuid::new_v4().simple()))
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| Error::io_path(path, e))?;
        f.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|e| Error::io_path(path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_restore_delete() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Quarantine::open(&dir.path().join("vault")).unwrap();
        let src = dir.path().join("bad.exe");
        // 2.5 MiB to exercise multiple chunks.
        let data: Vec<u8> = (0..(5 << 19)).map(|i: u32| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let item = vault.add(&src, "Test.Threat").unwrap();
        assert!(!src.exists(), "original must be removed");
        assert_eq!(item.size, data.len() as u64);
        let raw = std::fs::read(dir.path().join("vault").join(format!("{}.bin", item.id))).unwrap();
        assert!(raw.windows(16).all(|w| w != &data[1000..1016]), "vault must be encrypted");
        assert_eq!(vault.list().unwrap().len(), 1);
        assert_eq!(vault.read(&item.id).unwrap(), data);

        // Restoring next to an existing file picks a new name.
        std::fs::write(&src, b"new file").unwrap();
        let restored = vault.restore(&item.id, None).unwrap();
        assert_ne!(restored, src);
        assert_eq!(std::fs::read(&restored).unwrap(), data);
        assert!(vault.list().unwrap().is_empty());
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Quarantine::open(dir.path()).unwrap();
        let src = dir.path().join("x.bin");
        std::fs::write(&src, b"secret payload").unwrap();
        let item = vault.add(&src, "T").unwrap();
        let bin = dir.path().join(format!("{}.bin", item.id));
        let mut raw = std::fs::read(&bin).unwrap();
        let n = raw.len();
        raw[n - 3] ^= 0x55;
        std::fs::write(&bin, raw).unwrap();
        assert!(vault.read(&item.id).is_err());
        assert!(vault.delete("../etc").is_err());
    }

    #[test]
    fn empty_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Quarantine::open(dir.path()).unwrap();
        let src = dir.path().join("empty");
        std::fs::write(&src, b"").unwrap();
        let item = vault.add(&src, "T").unwrap();
        assert_eq!(vault.read(&item.id).unwrap(), Vec::<u8>::new());
    }
}
