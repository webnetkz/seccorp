//! Compact hash-signature storage.
//!
//! Entries are kept in sorted vectors (binary search) and names are interned
//! into one string blob, so millions of signatures fit in a modest amount of
//! memory. A per-size filter avoids computing MD5/SHA-1 for files whose size
//! cannot match any MD5/SHA-1 signature (ClamAV signatures carry the size).

use crate::hashing::Hashes;
use crate::report::Severity;
use std::collections::{HashMap, HashSet};

/// Size value meaning "any size".
pub const ANY_SIZE: u64 = u64::MAX;

#[derive(Clone, Copy)]
struct Entry<const N: usize> {
    hash: [u8; N],
    size: u64,
    name: u32,
    severity: Severity,
}

/// Interned signature names.
#[derive(Default)]
pub struct NameTable {
    blob: String,
    spans: Vec<(u32, u32)>,
    index: HashMap<String, u32>,
}

impl NameTable {
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let start = self.blob.len() as u32;
        self.blob.push_str(name);
        self.spans.push((start, name.len() as u32));
        let i = (self.spans.len() - 1) as u32;
        self.index.insert(name.to_string(), i);
        i
    }

    pub fn get(&self, i: u32) -> &str {
        let (s, l) = self.spans[i as usize];
        &self.blob[s as usize..(s + l) as usize]
    }

    /// Drops the lookup index (not needed after building).
    pub fn freeze(&mut self) {
        self.index = HashMap::new();
        self.blob.shrink_to_fit();
        self.spans.shrink_to_fit();
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

#[derive(Default)]
struct SizeFilter {
    any: bool,
    sizes: HashSet<u64>,
}

impl SizeFilter {
    fn add(&mut self, size: u64) {
        if size == ANY_SIZE {
            self.any = true;
        } else {
            self.sizes.insert(size);
        }
    }
    fn contains(&self, size: u64) -> bool {
        self.any || self.sizes.contains(&size)
    }
}

/// A hash signature hit.
#[derive(Debug, Clone, PartialEq)]
pub struct HashHit {
    pub name: String,
    pub algorithm: &'static str,
    pub severity: Severity,
}

/// Immutable hash signature database.
#[derive(Default)]
pub struct HashDb {
    sha256: Vec<Entry<32>>,
    sha1: Vec<Entry<20>>,
    md5: Vec<Entry<16>>,
    names: NameTable,
    md5_sizes: SizeFilter,
    sha1_sizes: SizeFilter,
    allow_sha256: HashSet<[u8; 32]>,
    allow_sha1: HashSet<[u8; 20]>,
    allow_md5: HashSet<[u8; 16]>,
}

fn find<const N: usize>(v: &[Entry<N>], hash: &[u8; N], size: u64) -> Option<Entry<N>> {
    let start = v.partition_point(|e| e.hash < *hash);
    v[start..].iter().take_while(|e| e.hash == *hash).find(|e| e.size == ANY_SIZE || e.size == size).copied()
}

impl HashDb {
    pub fn len(&self) -> usize {
        self.sha256.len() + self.sha1.len() + self.md5.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether MD5 must be computed for a file of this size.
    pub fn needs_md5(&self, size: u64) -> bool {
        self.md5_sizes.contains(size) || !self.allow_md5.is_empty()
    }

    /// Whether SHA-1 must be computed for a file of this size.
    pub fn needs_sha1(&self, size: u64) -> bool {
        self.sha1_sizes.contains(size) || !self.allow_sha1.is_empty()
    }

    pub fn lookup(&self, h: &Hashes, size: u64) -> Option<HashHit> {
        if let Some(e) = find(&self.sha256, &h.sha256, size) {
            return Some(self.hit(e.name, e.severity, "sha256"));
        }
        if let Some(sha1) = &h.sha1
            && let Some(e) = find(&self.sha1, sha1, size)
        {
            return Some(self.hit(e.name, e.severity, "sha1"));
        }
        if let Some(md5) = &h.md5
            && let Some(e) = find(&self.md5, md5, size)
        {
            return Some(self.hit(e.name, e.severity, "md5"));
        }
        None
    }

    /// True when the file is on a false-positive allowlist.
    pub fn is_allowlisted(&self, h: &Hashes) -> bool {
        self.allow_sha256.contains(&h.sha256)
            || h.sha1.as_ref().is_some_and(|x| self.allow_sha1.contains(x))
            || h.md5.as_ref().is_some_and(|x| self.allow_md5.contains(x))
    }

    fn hit(&self, name: u32, severity: Severity, algorithm: &'static str) -> HashHit {
        HashHit { name: self.names.get(name).to_string(), algorithm, severity }
    }
}

/// Collects hash signatures before building a [`HashDb`].
#[derive(Default)]
pub struct HashDbBuilder {
    sha256: Vec<Entry<32>>,
    sha1: Vec<Entry<20>>,
    md5: Vec<Entry<16>>,
    names: NameTable,
    allow_sha256: HashSet<[u8; 32]>,
    allow_sha1: HashSet<[u8; 20]>,
    allow_md5: HashSet<[u8; 16]>,
    ignored: HashSet<String>,
}

fn decode<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

impl HashDbBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.sha256.len() + self.sha1.len() + self.md5.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds a signature; the algorithm is inferred from the hex length.
    pub fn add_hex(&mut self, hash_hex: &str, size: u64, name: &str, severity: Severity) -> Result<(), String> {
        let h = hash_hex.trim();
        let name_id = self.names.intern(name);
        match h.len() {
            64 => {
                let hash = decode::<32>(h).ok_or("invalid SHA-256")?;
                self.sha256.push(Entry { hash, size, name: name_id, severity });
            }
            40 => {
                let hash = decode::<20>(h).ok_or("invalid SHA-1")?;
                self.sha1.push(Entry { hash, size, name: name_id, severity });
            }
            32 => {
                let hash = decode::<16>(h).ok_or("invalid MD5")?;
                self.md5.push(Entry { hash, size, name: name_id, severity });
            }
            _ => return Err(format!("unsupported hash length {}", h.len())),
        }
        Ok(())
    }

    /// Adds a false-positive allowlist entry.
    pub fn add_allow_hex(&mut self, hash_hex: &str) -> Result<(), String> {
        let h = hash_hex.trim();
        match h.len() {
            64 => {
                self.allow_sha256.insert(decode::<32>(h).ok_or("invalid SHA-256")?);
            }
            40 => {
                self.allow_sha1.insert(decode::<20>(h).ok_or("invalid SHA-1")?);
            }
            32 => {
                self.allow_md5.insert(decode::<16>(h).ok_or("invalid MD5")?);
            }
            _ => return Err(format!("unsupported hash length {}", h.len())),
        }
        Ok(())
    }

    /// Signatures with this name are dropped at build time.
    pub fn ignore_name(&mut self, name: &str) {
        self.ignored.insert(name.to_string());
    }

    pub fn build(mut self) -> HashDb {
        let ignored: HashSet<u32> = self.ignored.iter().filter_map(|n| self.names.index.get(n).copied()).collect();
        fn finish<const N: usize>(v: &mut Vec<Entry<N>>, ignored: &HashSet<u32>) {
            if !ignored.is_empty() {
                v.retain(|e| !ignored.contains(&e.name));
            }
            v.sort_unstable_by(|a, b| a.hash.cmp(&b.hash).then(a.size.cmp(&b.size)));
            v.dedup_by(|a, b| a.hash == b.hash && a.size == b.size);
            v.shrink_to_fit();
        }
        finish(&mut self.sha256, &ignored);
        finish(&mut self.sha1, &ignored);
        finish(&mut self.md5, &ignored);

        let mut md5_sizes = SizeFilter::default();
        for e in &self.md5 {
            md5_sizes.add(e.size);
        }
        let mut sha1_sizes = SizeFilter::default();
        for e in &self.sha1 {
            sha1_sizes.add(e.size);
        }
        self.names.freeze();
        HashDb {
            sha256: self.sha256,
            sha1: self.sha1,
            md5: self.md5,
            names: self.names,
            md5_sizes,
            sha1_sizes,
            allow_sha256: self.allow_sha256,
            allow_sha1: self.allow_sha1,
            allow_md5: self.allow_md5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_bytes;

    #[test]
    fn lookup_by_each_algorithm() {
        let data = b"sample payload";
        let h = hash_bytes(data, true, true);
        let mut b = HashDbBuilder::new();
        b.add_hex(&hex::encode(h.sha256), ANY_SIZE, "Test.Sha256", Severity::High).unwrap();
        b.add_hex(&hex::encode(h.sha1.unwrap()), data.len() as u64, "Test.Sha1", Severity::High).unwrap();
        b.add_hex(&hex::encode(h.md5.unwrap()), 999, "Test.Md5.WrongSize", Severity::High).unwrap();
        let db = b.build();
        assert_eq!(db.len(), 3);
        assert_eq!(db.lookup(&h, data.len() as u64).unwrap().name, "Test.Sha256");
        assert!(db.needs_sha1(data.len() as u64));
        assert!(!db.needs_md5(data.len() as u64));
        assert!(db.needs_md5(999));

        let only_md5 = Hashes { sha256: [0; 32], sha1: None, md5: h.md5 };
        assert!(db.lookup(&only_md5, data.len() as u64).is_none());
        assert_eq!(db.lookup(&only_md5, 999).unwrap().name, "Test.Md5.WrongSize");
    }

    #[test]
    fn allowlist_and_ignore() {
        let h = hash_bytes(b"x", true, false);
        let mut b = HashDbBuilder::new();
        b.add_hex(&hex::encode(h.sha256), ANY_SIZE, "Noisy.Sig", Severity::High).unwrap();
        b.ignore_name("Noisy.Sig");
        b.add_allow_hex(&hex::encode(h.md5.unwrap())).unwrap();
        let db = b.build();
        assert!(db.lookup(&h, 1).is_none());
        assert!(db.is_allowlisted(&h));
        assert!(b"bad".len() == 3);
    }

    #[test]
    fn rejects_bad_hex() {
        let mut b = HashDbBuilder::new();
        assert!(b.add_hex("zz", ANY_SIZE, "x", Severity::High).is_err());
        assert!(b.add_hex(&"g".repeat(64), ANY_SIZE, "x", Severity::High).is_err());
    }
}
