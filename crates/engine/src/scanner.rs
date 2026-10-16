//! Scan session control: progress counters, pause/resume, cancellation and
//! the parallel directory walker.

use crate::cache::ScanCache;
use crate::config::ScanOptions;
use crate::engine::Engine;
use crate::report::{FileVerdict, ScanSummary};
use crate::util::{now_unix, now_unix_ms};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Instant;

/// Events emitted while scanning (progress is polled via [`ScanControl::progress`]).
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// A threat was found.
    Threat(FileVerdict),
    /// A file or directory could not be read.
    Error { path: String, message: String },
}

/// Snapshot of a running scan.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub files_scanned: u64,
    pub files_discovered: u64,
    pub files_cached: u64,
    pub files_skipped: u64,
    pub bytes_scanned: u64,
    pub threats: u64,
    pub errors: u64,
    pub walk_done: bool,
    pub paused: bool,
    pub cancelled: bool,
    pub current_path: String,
    pub elapsed_ms: u64,
}

/// Shared control block of one scan session. All methods are thread-safe.
pub struct ScanControl {
    cancelled: AtomicBool,
    paused: Mutex<bool>,
    resume: Condvar,
    files_scanned: AtomicU64,
    files_discovered: AtomicU64,
    files_cached: AtomicU64,
    files_skipped: AtomicU64,
    bytes_scanned: AtomicU64,
    threats: AtomicU64,
    errors: AtomicU64,
    walk_done: AtomicBool,
    current: Mutex<String>,
    started: Instant,
    paused_ms: AtomicU64,
    pause_started: Mutex<Option<Instant>>,
}

impl Default for ScanControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanControl {
    pub fn new() -> Self {
        ScanControl {
            cancelled: AtomicBool::new(false),
            paused: Mutex::new(false),
            resume: Condvar::new(),
            files_scanned: AtomicU64::new(0),
            files_discovered: AtomicU64::new(0),
            files_cached: AtomicU64::new(0),
            files_skipped: AtomicU64::new(0),
            bytes_scanned: AtomicU64::new(0),
            threats: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            walk_done: AtomicBool::new(false),
            current: Mutex::new(String::new()),
            started: Instant::now(),
            paused_ms: AtomicU64::new(0),
            pause_started: Mutex::new(None),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // Wake paused workers so they can exit.
        self.set_paused(false);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn pause(&self) {
        self.set_paused(true);
    }

    pub fn resume(&self) {
        self.set_paused(false);
    }

    fn set_paused(&self, value: bool) {
        let mut p = self.paused.lock().unwrap_or_else(|e| e.into_inner());
        if *p == value {
            return;
        }
        *p = value;
        let mut ps = self.pause_started.lock().unwrap_or_else(|e| e.into_inner());
        if value {
            *ps = Some(Instant::now());
        } else if let Some(t) = ps.take() {
            self.paused_ms.fetch_add(t.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
        self.resume.notify_all();
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Blocks while the scan is paused (returns immediately when cancelled).
    pub fn wait_if_paused(&self) {
        let mut p = self.paused.lock().unwrap_or_else(|e| e.into_inner());
        while *p && !self.is_cancelled() {
            p = self.resume.wait(p).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn set_current(&self, path: &Path) {
        if let Ok(mut c) = self.current.try_lock() {
            c.clear();
            c.push_str(&path.to_string_lossy());
        }
    }

    pub fn progress(&self) -> ScanProgress {
        let paused_now = self.pause_started.lock().ok().and_then(|p| p.map(|t| t.elapsed().as_millis() as u64)).unwrap_or(0);
        ScanProgress {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            files_discovered: self.files_discovered.load(Ordering::Relaxed),
            files_cached: self.files_cached.load(Ordering::Relaxed),
            files_skipped: self.files_skipped.load(Ordering::Relaxed),
            bytes_scanned: self.bytes_scanned.load(Ordering::Relaxed),
            threats: self.threats.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            walk_done: self.walk_done.load(Ordering::Relaxed),
            paused: self.is_paused(),
            cancelled: self.is_cancelled(),
            current_path: self.current.lock().map(|c| c.clone()).unwrap_or_default(),
            elapsed_ms: (self.started.elapsed().as_millis() as u64).saturating_sub(self.paused_ms.load(Ordering::Relaxed) + paused_now),
        }
    }
}

/// Drops duplicate roots and roots that lie inside another root, keeping the
/// original order, so that no file is scanned (or reported) twice — e.g. a
/// quick scan of `~/Downloads` plus `/tmp` when the home folder lives in `/tmp`,
/// or a running program located in an already scanned folder.
pub fn normalize_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    // `components()` folds `a//b`, `a/./b` and trailing separators.
    let list: Vec<PathBuf> = roots.iter().map(|p| p.components().collect()).collect();
    let mut out = Vec::with_capacity(list.len());
    for (i, p) in list.iter().enumerate() {
        let covered = list.iter().enumerate().any(|(j, q)| {
            if i == j {
                false
            } else if p == q {
                j < i
            } else {
                p.starts_with(q)
            }
        });
        if !covered {
            out.push(p.clone());
        }
    }
    out
}

fn is_hidden(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with('.')
}

fn mtime_ns(meta: &std::fs::Metadata) -> u64 {
    meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// Scans files and directories in parallel. Returns when everything was
/// scanned or the scan was cancelled.
pub fn scan_paths(
    engine: &Engine,
    roots: &[PathBuf],
    opts: &ScanOptions,
    control: &ScanControl,
    cache: Option<&ScanCache>,
    on_event: &(dyn Fn(ScanEvent) + Sync),
) -> ScanSummary {
    let started_at = now_unix();
    let threads = opts.effective_threads();
    let roots = normalize_roots(roots);
    let roots = roots.as_slice();
    let (tx, rx) = crossbeam_channel::bounded::<PathBuf>(4096);
    let threats: Mutex<Vec<FileVerdict>> = Mutex::new(Vec::new());

    std::thread::scope(|s| {
        // Directory walker.
        s.spawn(move || {
            for root in roots {
                if control.is_cancelled() {
                    break;
                }
                let walker = walkdir::WalkDir::new(root).follow_links(opts.follow_symlinks).into_iter().filter_entry(|e| {
                    if e.depth() > 0 && opts.skip_hidden && is_hidden(e.file_name()) {
                        return false;
                    }
                    if opts.is_excluded(e.path()) {
                        return false;
                    }
                    // Do not enumerate cloud-only folders: listing them makes macOS fetch them.
                    !(cfg!(target_os = "macos")
                        && e.file_type().is_dir()
                        && e.metadata().is_ok_and(|m| crate::util::is_cloud_placeholder(&m)))
                });
                for entry in walker {
                    if control.is_cancelled() {
                        break;
                    }
                    match entry {
                        Ok(e) => {
                            if e.file_type().is_file() {
                                control.files_discovered.fetch_add(1, Ordering::Relaxed);
                                if tx.send(e.into_path()).is_err() {
                                    break;
                                }
                            }
                        }
                        Err(err) => {
                            control.errors.fetch_add(1, Ordering::Relaxed);
                            let path = err.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                            on_event(ScanEvent::Error { path, message: err.to_string() });
                        }
                    }
                }
            }
            control.walk_done.store(true, Ordering::SeqCst);
            drop(tx);
        });

        for _ in 0..threads {
            let rx = rx.clone();
            let threats = &threats;
            s.spawn(move || {
                for path in rx.iter() {
                    if control.is_cancelled() {
                        break;
                    }
                    control.wait_if_paused();
                    if control.is_cancelled() {
                        break;
                    }
                    control.set_current(&path);
                    let meta = match std::fs::metadata(&path) {
                        Ok(m) => m,
                        Err(e) => {
                            control.errors.fetch_add(1, Ordering::Relaxed);
                            on_event(ScanEvent::Error { path: path.to_string_lossy().into_owned(), message: e.to_string() });
                            continue;
                        }
                    };
                    let size = meta.len();
                    let mtime = mtime_ns(&meta);
                    if opts.use_cache
                        && let Some(c) = cache
                        && c.is_clean(&path, size, mtime)
                    {
                        control.files_cached.fetch_add(1, Ordering::Relaxed);
                        control.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let verdict = engine.scan_file_with_cancel(&path, opts, &|| control.is_cancelled());
                    control.files_scanned.fetch_add(1, Ordering::Relaxed);
                    control.bytes_scanned.fetch_add(size, Ordering::Relaxed);
                    if verdict.skipped.is_some() {
                        control.files_skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    if verdict.is_threat() {
                        control.threats.fetch_add(1, Ordering::Relaxed);
                        if let Some(c) = cache {
                            c.invalidate(&path);
                        }
                        threats.lock().unwrap_or_else(|e| e.into_inner()).push(verdict.clone());
                        on_event(ScanEvent::Threat(verdict));
                    } else if verdict.skipped.is_none()
                        && !control.is_cancelled()
                        && let Some(c) = cache
                    {
                        c.mark_clean(&path, size, mtime);
                    }
                }
            });
        }
        drop(rx);
    });

    let p = control.progress();
    ScanSummary {
        id: uuid::Uuid::new_v4().to_string(),
        roots: roots.iter().map(|r| r.to_string_lossy().into_owned()).collect(),
        started_at,
        finished_at: now_unix().max(started_at),
        files_scanned: p.files_scanned,
        files_cached: p.files_cached,
        files_skipped: p.files_skipped,
        bytes_scanned: p.bytes_scanned,
        errors: p.errors,
        cancelled: control.is_cancelled(),
        threats: threats.into_inner().unwrap_or_else(|e| e.into_inner()),
    }
}

/// Milliseconds since the UNIX epoch (re-exported for callers measuring time).
pub fn timestamp_ms() -> u64 {
    now_unix_ms()
}
