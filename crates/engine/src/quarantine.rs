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

#[cfg(target_os = "windows")]
use std::time::Duration;

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

fn clear_read_only(path: &Path) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn remove_original(path: &Path) -> std::io::Result<()> {
    clear_read_only(path);
    std::fs::remove_file(path)
}

/// Windows scanners, indexers and preview handlers can keep a file open for a
/// short period after it has been read. Retry those transient failures and use
/// FileDispositionInfoEx as a fallback: unlike DeleteFileW, it can ignore the
/// read-only attribute and unlink a file while compatible handles remain open.
#[cfg(target_os = "windows")]
fn remove_original(path: &Path) -> std::io::Result<()> {
    const RETRY_DELAYS_MS: &[u64] = &[0, 40, 100, 250, 500, 1_000];

    clear_read_only(path);
    let mut last_error = None;
    for delay in RETRY_DELAYS_MS {
        if *delay != 0 {
            std::thread::sleep(Duration::from_millis(*delay));
        }

        let standard_error = match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => error,
        };

        match remove_file_posix(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // ERROR_INVALID_PARAMETER means this Windows/file-system version
            // does not implement FileDispositionInfoEx. Preserve the clearer
            // error returned by the normal deletion attempt in that case.
            Err(error) if error.raw_os_error() == Some(87) => last_error = Some(standard_error),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| std::io::Error::other("the original file could not be removed")))
}

#[cfg(target_os = "windows")]
fn remove_file_posix(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileDispositionInfoEx, OPEN_EXISTING, SetFileInformationByHandle,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a live, NUL-terminated UTF-16 path. The handle is
    // checked before use and closed on every path after CreateFileW succeeds.
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        let ok = SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        );
        let error = (ok == 0).then(std::io::Error::last_os_error);
        let _ = CloseHandle(handle);
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
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
        self.add_inner(path, threat, None)
    }

    /// Moves `path` into the vault, allowing the caller to retry the final
    /// source-file removal through a platform-specific privileged operation.
    /// The callback receives the SHA-256 of the bytes already committed to the
    /// encrypted vault and must remove exactly that file or return an error.
    pub fn add_with_remove_fallback(
        &self,
        path: &Path,
        threat: &str,
        mut fallback: impl FnMut(&Path, &str, &std::io::Error) -> Result<()>,
    ) -> Result<QuarantineItem> {
        self.add_inner(path, threat, Some(&mut fallback))
    }

    fn add_inner(
        &self,
        path: &Path,
        threat: &str,
        mut fallback: Option<&mut dyn FnMut(&Path, &str, &std::io::Error) -> Result<()>>,
    ) -> Result<QuarantineItem> {
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

        // The encrypted copy is committed before the original is removed. If
        // isolation fails, roll the copy back so the UI never reports a file
        // as quarantined while an executable original is still present.
        if let Err(error) = remove_original(path) {
            let fallback_result = match fallback.as_mut() {
                Some(remove) => remove(path, &item.sha256, &error),
                None => Err(Error::Quarantine(format!(
                    "could not isolate the original file after retrying; close any app using it and try again. Administrator permission may be required for protected folders: {error}"
                ))),
            };
            if let Err(fallback_error) = fallback_result {
                let _ = std::fs::remove_file(&bin);
                let _ = std::fs::remove_file(&meta);
                return Err(fallback_error);
            }
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

/// Removes a file only when its current contents still match the encrypted
/// quarantine copy. This is used by the short-lived Windows elevation helper;
/// it deliberately performs no scanning and cannot accept an unchecked path.
pub fn remove_file_if_hash_matches(path: &Path, expected_sha256: &str) -> Result<()> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Quarantine("invalid expected SHA-256".into()));
    }
    let file = std::fs::File::open(path).map_err(|error| Error::io_path(path, error))?;
    let metadata = file.metadata().map_err(|error| Error::io_path(path, error))?;
    if !metadata.is_file() {
        return Err(Error::Quarantine("the quarantine source is not a regular file".into()));
    }
    let (hashes, _) = crate::hashing::hash_reader(file, false, false).map_err(|error| Error::io_path(path, error))?;
    if !hex::encode(hashes.sha256).eq_ignore_ascii_case(expected_sha256) {
        return Err(Error::Quarantine("the source file changed after it was scanned; it was not removed".into()));
    }
    remove_original(path).map_err(|error| Error::io_path(path, error))
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

    #[test]
    fn read_only_file_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Quarantine::open(&dir.path().join("vault")).unwrap();
        let src = dir.path().join("read-only.exe");
        std::fs::write(&src, b"payload").unwrap();
        let mut permissions = std::fs::metadata(&src).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&src, permissions).unwrap();

        let item = vault.add(&src, "Test.Threat").unwrap();
        assert!(!src.exists());
        assert_eq!(vault.read(&item.id).unwrap(), b"payload");
    }

    #[test]
    fn checked_removal_rejects_changed_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("changed.exe");
        std::fs::write(&src, b"new payload").unwrap();

        let result = remove_file_if_hash_matches(&src, "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5");
        assert!(result.is_err());
        assert!(src.exists(), "a file with a different hash must remain untouched");
    }

    #[test]
    fn checked_removal_deletes_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("matching.exe");
        std::fs::write(&src, b"payload").unwrap();

        remove_file_if_hash_matches(&src, "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5").unwrap();
        assert!(!src.exists());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn retries_while_windows_handle_temporarily_blocks_delete() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

        let dir = tempfile::tempdir().unwrap();
        let vault = Quarantine::open(&dir.path().join("vault")).unwrap();
        let src = dir.path().join("temporarily-locked.exe");
        std::fs::write(&src, b"payload").unwrap();
        let held = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&src).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held);
        });

        let item = vault.add(&src, "Test.Threat").unwrap();
        release.join().unwrap();
        assert!(!src.exists());
        assert_eq!(vault.read(&item.id).unwrap(), b"payload");
    }
}
