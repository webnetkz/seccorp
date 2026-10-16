//! The scanning engine: per-file analysis pipeline.

use crate::analyzers::{self, AnalysisInput};
use crate::archive::{self, ArchiveLimits};
use crate::cache::ScanCache;
use crate::config::{HeuristicLevel, ScanOptions};
use crate::filetype::{self, FileType};
use crate::hashing::{MultiHasher, hash_bytes};
use crate::patterns::ScanContext;
use crate::report::{Detection, DetectionKind, FileVerdict, ScanSummary, Severity, Verdict};
use crate::scanner::{self, ScanControl, ScanEvent};
use crate::sigdb::{DbInfo, SignatureDb};
use std::cell::Cell;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Thread-safe scanning engine. The signature database can be swapped at
/// runtime (after an update) without stopping running scans.
pub struct Engine {
    db: RwLock<Arc<SignatureDb>>,
}

/// Accumulated results while analysing one file and its archive entries.
struct Analysis {
    detections: Vec<Detection>,
    heuristic_score: u32,
    file_type: Option<FileType>,
    notes: Vec<String>,
}

impl Engine {
    pub fn new(db: SignatureDb) -> Self {
        Engine { db: RwLock::new(Arc::new(db)) }
    }

    /// Engine with built-in signatures only.
    pub fn with_builtin() -> Self {
        Self::new(SignatureDb::builtin())
    }

    pub fn db(&self) -> Arc<SignatureDb> {
        self.db.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_db(&self, db: SignatureDb) {
        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(db);
    }

    pub fn db_info(&self) -> DbInfo {
        self.db().info().clone()
    }

    /// Scans one file. Never fails: problems are reported in `skipped`.
    pub fn scan_file(&self, path: &Path, opts: &ScanOptions) -> FileVerdict {
        self.scan_file_with_cancel(path, opts, &|| false)
    }

    /// Like [`scan_file`](Self::scan_file) with a cancellation check used
    /// inside large archives.
    pub fn scan_file_with_cancel(&self, path: &Path, opts: &ScanOptions, cancelled: &dyn Fn() -> bool) -> FileVerdict {
        let start = Instant::now();
        let display = path.to_string_lossy().into_owned();
        let mut v = FileVerdict { path: display.clone(), ..Default::default() };

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                v.skipped = Some(format!("cannot access: {e}"));
                v.file_type = "unknown".into();
                return v;
            }
        };
        if !meta.is_file() {
            v.skipped = Some("not a regular file".into());
            v.file_type = "special".into();
            return v;
        }
        if crate::util::is_cloud_placeholder(&meta) {
            v.skipped = Some("cloud file is not downloaded".into());
            v.file_type = "cloud".into();
            v.size = meta.len();
            return v;
        }
        let size = meta.len();
        v.size = size;
        if size == 0 {
            v.file_type = "empty".into();
            v.duration_ms = start.elapsed().as_millis() as u64;
            return v;
        }

        let db = self.db();
        let want_md5 = db.needs_md5(size);
        let want_sha1 = db.needs_sha1(size);

        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                v.skipped = Some(format!("cannot open: {e}"));
                v.file_type = "unknown".into();
                return v;
            }
        };

        // Read the analysed prefix while hashing the whole file in one pass.
        let content_limit = if size > opts.max_file_size { 0 } else { size.min(opts.max_content_scan) as usize };
        let mut content = Vec::with_capacity(content_limit);
        let mut hasher = MultiHasher::new(want_md5, want_sha1);
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            if cancelled() {
                v.skipped = Some("scan cancelled".into());
                v.file_type = "unknown".into();
                return v;
            }
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    v.skipped = Some(format!("read error: {e}"));
                    v.file_type = "unknown".into();
                    return v;
                }
            };
            hasher.update(&buf[..n]);
            if content.len() < content_limit {
                let take = (content_limit - content.len()).min(n);
                content.extend_from_slice(&buf[..take]);
            }
            total += n as u64;
        }
        let hashes = hasher.finish();
        v.sha256 = Some(hashes.sha256_hex());
        v.size = total;

        if db.is_allowlisted(&hashes) {
            v.file_type = filetype::detect(&content, &display).as_str().into();
            v.duration_ms = start.elapsed().as_millis() as u64;
            return v;
        }

        let mut a = Analysis { detections: Vec::new(), heuristic_score: 0, file_type: None, notes: Vec::new() };
        if let Some(d) = db.lookup_hash(&hashes, total) {
            a.detections.push(d);
        }

        if content_limit == 0 {
            v.skipped = Some(format!("larger than {} MB: checked by hash only", opts.max_file_size >> 20));
        } else {
            let truncated = (content.len() as u64) < total;
            if truncated {
                a.notes.push(format!("only the first {} MB were analysed", content.len() >> 20));
            }
            let budget = Cell::new(opts.max_archive_total);
            self.analyze_buffer(&db, &display, &content, total, truncated, 0, None, opts, &budget, cancelled, &mut a);
        }
        self.finish(v, a, opts.heuristics, start)
    }

    /// Scans an in-memory buffer (e.g. a downloaded file or an APK).
    pub fn scan_bytes(&self, name: &str, data: &[u8], opts: &ScanOptions) -> FileVerdict {
        let start = Instant::now();
        let db = self.db();
        let size = data.len() as u64;
        let mut v = FileVerdict { path: name.to_string(), size, ..Default::default() };
        if data.is_empty() {
            v.file_type = "empty".into();
            return v;
        }
        let hashes = hash_bytes(data, db.needs_md5(size), db.needs_sha1(size));
        v.sha256 = Some(hashes.sha256_hex());
        if db.is_allowlisted(&hashes) {
            v.file_type = filetype::detect(data, name).as_str().into();
            return v;
        }
        let mut a = Analysis { detections: Vec::new(), heuristic_score: 0, file_type: None, notes: Vec::new() };
        if let Some(d) = db.lookup_hash(&hashes, size) {
            a.detections.push(d);
        }
        let limit = (opts.max_content_scan as usize).min(data.len());
        let budget = Cell::new(opts.max_archive_total);
        self.analyze_buffer(&db, name, &data[..limit], size, limit < data.len(), 0, None, opts, &budget, &|| false, &mut a);
        self.finish(v, a, opts.heuristics, start)
    }

    /// Scans files and directories in parallel (see [`scanner::scan_paths`]).
    pub fn scan_paths(
        &self,
        roots: &[PathBuf],
        opts: &ScanOptions,
        control: &ScanControl,
        cache: Option<&ScanCache>,
        on_event: &(dyn Fn(ScanEvent) + Sync),
    ) -> ScanSummary {
        scanner::scan_paths(self, roots, opts, control, cache, on_event)
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_buffer(
        &self,
        db: &SignatureDb,
        name: &str,
        data: &[u8],
        full_size: u64,
        truncated: bool,
        depth: u32,
        location: Option<&str>,
        opts: &ScanOptions,
        budget: &Cell<u64>,
        cancelled: &dyn Fn() -> bool,
        a: &mut Analysis,
    ) {
        let ft = filetype::detect(data, name);
        if depth == 0 {
            a.file_type = Some(ft);
        }
        let ctx = ScanContext { file_type: ft, entry_point: analyzers::entry_point_offset(data, ft) };
        let loc = |d: &mut Detection| {
            if let Some(l) = location {
                d.location = Some(l.to_string());
            }
        };

        for mut d in db.scan_body(data, &ctx) {
            loc(&mut d);
            a.detections.push(d);
        }
        for mut d in db.scan_rules(data, full_size, &ctx) {
            loc(&mut d);
            a.detections.push(d);
        }

        if opts.heuristics != HeuristicLevel::Off {
            let input = AnalysisInput { data, name, file_type: ft, full_size, truncated, in_archive: depth > 0 };
            let findings = analyzers::analyze(&input);
            let score = analyzers::total_score(&findings);
            a.heuristic_score = a.heuristic_score.max(score);
            for f in findings {
                let mut d = Detection {
                    name: f.name.to_string(),
                    kind: DetectionKind::Heuristic,
                    severity: f.severity(),
                    score: f.score,
                    description: f.description,
                    location: None,
                };
                loc(&mut d);
                a.detections.push(d);
            }
        }

        if !(opts.scan_archives && ft.is_unpackable() && depth < opts.max_archive_depth) || cancelled() {
            return;
        }
        let limits = ArchiveLimits {
            max_entries: opts.max_archive_entries,
            max_entry: opts.max_content_scan,
            max_ratio: opts.max_compression_ratio,
        };
        let outer = location.map(str::to_string).unwrap_or_else(|| crate::util::file_name(name).to_string());
        let report = archive::walk(data, ft, name, &limits, budget, cancelled, &mut |entry_name, entry_data| {
            if cancelled() {
                return false;
            }
            let entry_loc = format!("{outer} › {entry_name}");
            let size = entry_data.len() as u64;
            let hashes = hash_bytes(entry_data, db.needs_md5(size), db.needs_sha1(size));
            if db.is_allowlisted(&hashes) {
                return true;
            }
            if let Some(mut d) = db.lookup_hash(&hashes, size) {
                d.location = Some(entry_loc.clone());
                a.detections.push(d);
            }
            self.analyze_buffer(db, entry_name, entry_data, size, false, depth + 1, Some(&entry_loc), opts, budget, cancelled, a);
            true
        });

        if opts.heuristics != HeuristicLevel::Off {
            if let Some(entry) = report.bomb {
                a.heuristic_score = a.heuristic_score.max(50);
                a.detections.push(Detection {
                    name: "Heur.Archive.Bomb".into(),
                    kind: DetectionKind::Heuristic,
                    severity: Severity::Medium,
                    score: 50,
                    description: format!("Decompression bomb: entry '{entry}' expands far beyond safe limits"),
                    location: location.map(str::to_string),
                });
            }
            let risky: Vec<&String> = report.encrypted.iter().filter(|n| filetype::has_executable_extension(n)).collect();
            if !risky.is_empty() {
                let score = 30;
                a.heuristic_score = a.heuristic_score.max(score);
                a.detections.push(Detection {
                    name: "Heur.Archive.EncryptedProgram".into(),
                    kind: DetectionKind::Heuristic,
                    severity: Severity::from_score(score),
                    score,
                    description: format!(
                        "Password-protected archive hides a program ({}); it cannot be checked",
                        crate::util::file_name(risky[0])
                    ),
                    location: location.map(str::to_string),
                });
            } else if !report.encrypted.is_empty() {
                a.notes.push(format!("{} encrypted archive entries were not scanned", report.encrypted.len()));
            }
        }
        if report.truncated {
            a.notes.push("archive limits reached: some entries were not scanned".into());
        }
    }

    fn finish(&self, mut v: FileVerdict, a: Analysis, level: HeuristicLevel, start: Instant) -> FileVerdict {
        v.file_type = a.file_type.map(|t| t.as_str()).unwrap_or("unknown").into();
        let mut verdict = Verdict::Clean;
        for d in a.detections.iter().filter(|d| d.kind != DetectionKind::Heuristic) {
            let dv = if d.severity >= Severity::Medium { Verdict::Malicious } else { Verdict::Suspicious };
            verdict = verdict.max(dv);
        }
        let score = a.heuristic_score.min(100);
        if let Some((suspicious, malicious)) = level.thresholds() {
            if score >= malicious {
                verdict = verdict.max(Verdict::Malicious);
            } else if score >= suspicious {
                verdict = verdict.max(Verdict::Suspicious);
            }
        }
        v.verdict = verdict;
        v.score = score;
        v.detections = if verdict == Verdict::Clean {
            Vec::new()
        } else {
            let mut d = a.detections;
            d.sort_by(|x, y| y.severity.cmp(&x.severity).then(y.score.cmp(&x.score)));
            d.dedup_by(|x, y| x.name == y.name && x.location == y.location);
            d
        };
        if v.skipped.is_none() && !a.notes.is_empty() && verdict == Verdict::Clean {
            v.skipped = Some(a.notes.join("; "));
            // Partial analysis of a clean file is informational, not a failure.
            if v.skipped.as_deref().is_some_and(|s| s.contains("encrypted archive entries")) {
                v.skipped = None;
            }
        }
        v.duration_ms = start.elapsed().as_millis() as u64;
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::tests::make_zip;

    fn eicar() -> Vec<u8> {
        "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".bytes().rev().collect()
    }

    #[test]
    fn eicar_file_and_nested_archive() {
        let engine = Engine::with_builtin();
        let opts = ScanOptions::default();
        let dir = tempfile::tempdir().unwrap();

        let f = dir.path().join("eicar.com");
        std::fs::write(&f, eicar()).unwrap();
        let v = engine.scan_file(&f, &opts);
        assert_eq!(v.verdict, Verdict::Malicious);
        assert_eq!(v.threat_name(), Some("EICAR-Test-File"));
        assert_eq!(v.sha256.as_deref(), Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));

        let inner = make_zip(&[("readme.txt", b"hello"), ("eicar.com", &eicar())]);
        let outer = make_zip(&[("nested/inner.zip", &inner)]);
        let z = dir.path().join("outer.zip");
        std::fs::write(&z, &outer).unwrap();
        let v = engine.scan_file(&z, &opts);
        assert_eq!(v.verdict, Verdict::Malicious, "{v:?}");
        let d = v.primary_detection().unwrap();
        assert_eq!(d.name, "EICAR-Test-File");
        assert_eq!(d.location.as_deref(), Some("outer.zip › nested/inner.zip › eicar.com"));

        let no_archives = ScanOptions { scan_archives: false, ..ScanOptions::default() };
        assert_eq!(engine.scan_file(&z, &no_archives).verdict, Verdict::Clean);
    }

    #[test]
    fn clean_files_and_special_cases() {
        let engine = Engine::with_builtin();
        let opts = ScanOptions::default();
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().join("notes.txt");
        std::fs::write(&t, "just a normal text file\n").unwrap();
        let v = engine.scan_file(&t, &opts);
        assert_eq!(v.verdict, Verdict::Clean);
        assert!(v.detections.is_empty());
        assert_eq!(v.file_type, "text");

        let e = dir.path().join("empty.bin");
        std::fs::write(&e, b"").unwrap();
        assert_eq!(engine.scan_file(&e, &opts).file_type, "empty");

        let missing = engine.scan_file(&dir.path().join("missing"), &opts);
        assert!(missing.skipped.is_some());
        assert_eq!(missing.verdict, Verdict::Clean);
    }

    #[test]
    fn heuristics_respect_level() {
        let engine = Engine::with_builtin();
        let pe = crate::analyzers::tests::tiny_pe();
        let level = |l| ScanOptions { heuristics: l, ..Default::default() };
        // Double extension (35) + no imports (10) = 45.
        let normal = engine.scan_bytes("invoice.pdf.exe", &pe, &ScanOptions::default());
        assert_eq!(normal.verdict, Verdict::Suspicious, "{normal:?}");
        assert_eq!(normal.score, 45);
        assert_eq!(engine.scan_bytes("invoice.pdf.exe", &pe, &level(HeuristicLevel::Low)).verdict, Verdict::Clean);
        assert_eq!(engine.scan_bytes("invoice.pdf.exe", &pe, &level(HeuristicLevel::Off)).verdict, Verdict::Clean);
        // Text-direction trick (60) + no imports (10) = 70.
        let rtlo = "photo\u{202E}gpj.exe";
        assert_eq!(engine.scan_bytes(rtlo, &pe, &level(HeuristicLevel::High)).verdict, Verdict::Malicious);
        assert_eq!(engine.scan_bytes(rtlo, &pe, &level(HeuristicLevel::Normal)).verdict, Verdict::Suspicious);
        // A program renamed to a picture.
        let disguised = engine.scan_bytes("holiday.jpg", &pe, &ScanOptions::default());
        assert_eq!(disguised.verdict, Verdict::Suspicious);
        assert_eq!(disguised.detections[0].name, "Heur.Exe.Disguised");
    }

    #[test]
    fn large_files_are_hashed_only() {
        let engine = Engine::with_builtin();
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big.bin");
        std::fs::write(&f, vec![7u8; 4096]).unwrap();
        let v = engine.scan_file(&f, &ScanOptions { max_file_size: 1024, ..Default::default() });
        assert!(v.skipped.as_deref().unwrap().contains("hash only"));
        assert!(v.sha256.is_some());
    }
}
