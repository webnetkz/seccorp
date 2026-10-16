//! Multi-algorithm hashing in a single pass.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Digests of one file. MD5 and SHA-1 are only computed when the signature
/// database contains entries that could match the file size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashes {
    pub sha256: [u8; 32],
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
}

impl Hashes {
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// Incremental hasher for SHA-256 plus optional MD5 / SHA-1.
pub struct MultiHasher {
    sha256: Sha256,
    md5: Option<Md5>,
    sha1: Option<Sha1>,
}

impl MultiHasher {
    pub fn new(want_md5: bool, want_sha1: bool) -> Self {
        MultiHasher { sha256: Sha256::new(), md5: want_md5.then(Md5::new), sha1: want_sha1.then(Sha1::new) }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        if let Some(h) = self.md5.as_mut() {
            h.update(data);
        }
        if let Some(h) = self.sha1.as_mut() {
            h.update(data);
        }
    }

    pub fn finish(self) -> Hashes {
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(self.sha256.finalize().as_slice());
        let md5 = self.md5.map(|h| {
            let mut out = [0u8; 16];
            out.copy_from_slice(h.finalize().as_slice());
            out
        });
        let sha1 = self.sha1.map(|h| {
            let mut out = [0u8; 20];
            out.copy_from_slice(h.finalize().as_slice());
            out
        });
        Hashes { sha256, md5, sha1 }
    }
}

/// Hashes an in-memory buffer.
pub fn hash_bytes(data: &[u8], want_md5: bool, want_sha1: bool) -> Hashes {
    let mut h = MultiHasher::new(want_md5, want_sha1);
    h.update(data);
    h.finish()
}

/// Hashes everything readable from `reader` (streaming, 1 MiB buffer).
pub fn hash_reader<R: Read>(mut reader: R, want_md5: bool, want_sha1: bool) -> std::io::Result<(Hashes, u64)> {
    let mut h = MultiHasher::new(want_md5, want_sha1);
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total += n as u64;
        h.update(&buf[..n]);
    }
    Ok((h.finish(), total))
}

/// SHA-256 of a buffer as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(hash_bytes(data, false, false).sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let h = hash_bytes(b"abc", true, true);
        assert_eq!(hex::encode(h.sha256), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex::encode(h.md5.unwrap()), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex::encode(h.sha1.unwrap()), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn streaming_equals_oneshot() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let (streamed, n) = hash_reader(&data[..], true, false).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(streamed, hash_bytes(&data, true, false));
    }
}
