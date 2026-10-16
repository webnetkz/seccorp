//! Persistent cache of files that were clean during a previous scan.
//!
//! Entries are keyed by a hash of the path and validated by size and
//! modification time. The whole cache is invalidated when the signature
//! database or detection-relevant options change (the `key`).

use crate::util::fnv1a64;
use crate::{Error, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const MAGIC: &[u8; 4] = b"SCC1";
const MAX_ENTRIES: usize = 2_000_000;

pub struct ScanCache {
    file: Option<PathBuf>,
    key: u64,
    map: Mutex<HashMap<u64, (u64, u64)>>,
    dirty: AtomicBool,
}

fn path_key(path: &Path) -> u64 {
    fnv1a64(path.to_string_lossy().as_bytes())
}

impl ScanCache {
    /// A cache that is never persisted.
    pub fn in_memory(key: &str) -> Self {
        ScanCache { file: None, key: fnv1a64(key.as_bytes()), map: Mutex::new(HashMap::new()), dirty: AtomicBool::new(false) }
    }

    /// Loads the cache from `file` if it exists and matches `key`.
    pub fn open(file: &Path, key: &str) -> Self {
        let mut cache = Self::in_memory(key);
        cache.file = Some(file.to_path_buf());
        if let Ok(bytes) = std::fs::read(file)
            && bytes.len() >= 20
            && &bytes[..4] == MAGIC
        {
            let stored_key = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
            let count = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
            if stored_key == cache.key && bytes.len() >= 20 + count.saturating_mul(24) {
                let mut map = HashMap::with_capacity(count.min(MAX_ENTRIES));
                let (records, _) = bytes[20..20 + count * 24].as_chunks::<24>();
                for rec in records {
                    let k = u64::from_le_bytes(rec[0..8].try_into().unwrap());
                    let size = u64::from_le_bytes(rec[8..16].try_into().unwrap());
                    let mtime = u64::from_le_bytes(rec[16..24].try_into().unwrap());
                    map.insert(k, (size, mtime));
                }
                cache.map = Mutex::new(map);
            }
        }
        cache
    }

    pub fn is_clean(&self, path: &Path, size: u64, mtime: u64) -> bool {
        if mtime == 0 {
            return false;
        }
        self.map.lock().map(|m| m.get(&path_key(path)) == Some(&(size, mtime))).unwrap_or(false)
    }

    pub fn mark_clean(&self, path: &Path, size: u64, mtime: u64) {
        if mtime == 0 {
            return;
        }
        if let Ok(mut m) = self.map.lock() {
            if m.len() >= MAX_ENTRIES {
                m.clear();
            }
            m.insert(path_key(path), (size, mtime));
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn invalidate(&self, path: &Path) {
        if let Ok(mut m) = self.map.lock()
            && m.remove(&path_key(path)).is_some()
        {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut m) = self.map.lock() {
            m.clear();
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes the cache atomically (no-op when unchanged or in-memory).
    pub fn save(&self) -> Result<()> {
        let Some(file) = &self.file else { return Ok(()) };
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let map = self.map.lock().map_err(|_| Error::Other("cache lock poisoned".into()))?;
        let mut buf = Vec::with_capacity(20 + map.len() * 24);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.key.to_le_bytes());
        buf.extend_from_slice(&(map.len() as u64).to_le_bytes());
        for (k, (size, mtime)) in map.iter() {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&mtime.to_le_bytes());
        }
        drop(map);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io_path(parent, e))?;
        }
        let tmp = file.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io_path(&tmp, e))?;
            f.write_all(&buf)?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, file).map_err(|e| Error::io_path(file, e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_and_invalidate() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("cache.bin");
        let p = Path::new("/some/file.txt");
        let c = ScanCache::open(&f, "db1");
        c.mark_clean(p, 10, 123);
        assert!(c.is_clean(p, 10, 123));
        assert!(!c.is_clean(p, 11, 123));
        c.save().unwrap();

        let c2 = ScanCache::open(&f, "db1");
        assert!(c2.is_clean(p, 10, 123));
        c2.invalidate(p);
        assert!(!c2.is_clean(p, 10, 123));

        // A different key (new database) discards everything.
        let c3 = ScanCache::open(&f, "db2");
        assert!(c3.is_empty());
    }
}
