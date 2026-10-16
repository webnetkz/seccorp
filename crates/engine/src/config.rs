//! Scan configuration.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Heuristic sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HeuristicLevel {
    /// Heuristics disabled – signatures and rules only.
    Off,
    /// Only very strong heuristic evidence is reported.
    Low,
    /// Balanced (default).
    #[default]
    Normal,
    /// Aggressive – more detections, more false positives.
    High,
}

impl HeuristicLevel {
    /// `(suspicious, malicious)` score thresholds, `None` when disabled.
    pub fn thresholds(self) -> Option<(u32, u32)> {
        match self {
            HeuristicLevel::Off => None,
            HeuristicLevel::Low => Some((60, u32::MAX)),
            HeuristicLevel::Normal => Some((40, 90)),
            HeuristicLevel::High => Some((25, 70)),
        }
    }
}

/// Options controlling how files are scanned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanOptions {
    /// Unpack and scan archives (ZIP/APK/JAR/OOXML, GZIP, TAR).
    pub scan_archives: bool,
    /// Maximum nesting depth for archives.
    pub max_archive_depth: u32,
    /// Maximum number of entries examined per archive.
    pub max_archive_entries: usize,
    /// Maximum total bytes extracted from one top-level file.
    pub max_archive_total: u64,
    /// Entries whose compression ratio exceeds this are treated as bombs.
    pub max_compression_ratio: u64,
    /// Files larger than this are only hashed (content is not analysed).
    pub max_file_size: u64,
    /// Number of leading bytes analysed for patterns, rules and heuristics.
    pub max_content_scan: u64,
    pub heuristics: HeuristicLevel,
    pub follow_symlinks: bool,
    pub skip_hidden: bool,
    /// Excluded path prefixes and `*.ext` extension masks.
    pub exclusions: Vec<String>,
    /// Worker threads (0 = automatic).
    pub threads: usize,
    /// Skip unchanged files that were clean during a previous scan.
    pub use_cache: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            scan_archives: true,
            max_archive_depth: 4,
            max_archive_entries: 10_000,
            max_archive_total: 512 * 1024 * 1024,
            max_compression_ratio: 250,
            max_file_size: 512 * 1024 * 1024,
            max_content_scan: 64 * 1024 * 1024,
            heuristics: HeuristicLevel::Normal,
            follow_symlinks: false,
            skip_hidden: false,
            exclusions: Vec::new(),
            threads: 0,
            use_cache: true,
        }
    }
}

impl ScanOptions {
    /// Conservative limits for phones and tablets.
    pub fn mobile() -> Self {
        ScanOptions {
            max_archive_total: 256 * 1024 * 1024,
            max_file_size: 256 * 1024 * 1024,
            max_content_scan: 32 * 1024 * 1024,
            threads: 2,
            ..ScanOptions::default()
        }
    }

    pub fn effective_threads(&self) -> usize {
        if self.threads > 0 {
            return self.threads.min(64);
        }
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 16)
    }

    /// A key that changes whenever options that influence detection change
    /// (used to invalidate the scan cache).
    pub fn detection_fingerprint(&self) -> String {
        format!(
            "a{}d{}e{}t{}r{}f{}c{}h{:?}",
            self.scan_archives as u8,
            self.max_archive_depth,
            self.max_archive_entries,
            self.max_archive_total,
            self.max_compression_ratio,
            self.max_file_size,
            self.max_content_scan,
            self.heuristics
        )
    }

    /// Returns true when `path` matches one of the exclusions.
    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.exclusions.is_empty() {
            return false;
        }
        let p = normalize_for_match(&path.to_string_lossy());
        for raw in &self.exclusions {
            let rule = raw.trim();
            if rule.is_empty() {
                continue;
            }
            if let Some(ext) = rule.strip_prefix("*.") {
                let ext = normalize_for_match(ext);
                if p.rsplit('/').next().is_some_and(|name| {
                    name.len() > ext.len() + 1 && name.ends_with(&ext) && name.as_bytes()[name.len() - ext.len() - 1] == b'.'
                }) {
                    return true;
                }
                continue;
            }
            let prefix = normalize_for_match(rule);
            let prefix = prefix.trim_end_matches('/');
            if prefix.is_empty() {
                continue;
            }
            if p == prefix || (p.starts_with(prefix) && p.as_bytes().get(prefix.len()) == Some(&b'/')) {
                return true;
            }
        }
        false
    }
}

/// Lower-cases (on case-insensitive platforms) and unifies separators.
pub(crate) fn normalize_for_match(s: &str) -> String {
    let s = s.replace('\\', "/");
    if cfg!(any(target_os = "windows", target_os = "macos", target_os = "ios")) { s.to_lowercase() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn exclusions_match_prefix_and_extension() {
        let opts = ScanOptions { exclusions: vec!["/data/projects".into(), "*.iso".into()], ..Default::default() };
        assert!(opts.is_excluded(&PathBuf::from("/data/projects/a.txt")));
        assert!(opts.is_excluded(&PathBuf::from("/data/projects")));
        assert!(!opts.is_excluded(&PathBuf::from("/data/projects2/a.txt")));
        assert!(opts.is_excluded(&PathBuf::from("/tmp/image.iso")));
        assert!(!opts.is_excluded(&PathBuf::from("/tmp/iso")));
    }
}
