//! Real-time file-system monitoring.
//!
//! Uses the native notification API of each platform through `notify`
//! (ReadDirectoryChangesW on Windows, FSEvents on macOS, inotify on Android,
//! kqueue on iOS). New or modified files are scanned once their size has
//! been stable for a short time, so partially written downloads are not
//! reported prematurely.

use crate::config::ScanOptions;
use crate::engine::Engine;
use crate::report::FileVerdict;
use crate::{Error, Result};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Called for every scanned file (clean or not).
pub type RealtimeCallback = Arc<dyn Fn(FileVerdict) + Send + Sync>;

/// Extensions of incomplete downloads; the final file is scanned after rename.
const TEMP_EXTENSIONS: &[&str] = &["crdownload", "part", "partial", "download", "tmp", "temp", "opdownload", "!ut", "aria2"];

const SETTLE: Duration = Duration::from_millis(800);
const MAX_PENDING: usize = 20_000;

pub struct RealtimeMonitor {
    watcher: Option<notify::RecommendedWatcher>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    watched: Vec<PathBuf>,
}

fn is_temp(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if name.starts_with("~$") || name.starts_with(".~") {
        return true;
    }
    let ext = name.rsplit('.').next().unwrap_or("");
    name.contains('.') && TEMP_EXTENSIONS.contains(&ext)
}

impl RealtimeMonitor {
    /// Starts watching `paths` recursively. Paths that do not exist are
    /// skipped; an error is returned only if nothing could be watched.
    /// Files under any of `ignore` (e.g. the quarantine vault) are skipped.
    pub fn start(
        engine: Arc<Engine>,
        paths: &[PathBuf],
        opts: ScanOptions,
        ignore: Vec<PathBuf>,
        on_result: RealtimeCallback,
    ) -> Result<Self> {
        let (tx, rx) = crossbeam_channel::unbounded::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })
        .map_err(|e| Error::Other(format!("file monitor unavailable: {e}")))?;

        let mut watched = Vec::new();
        let mut last_err = None;
        for p in paths {
            if !p.exists() {
                continue;
            }
            match watcher.watch(p, RecursiveMode::Recursive) {
                Ok(()) => watched.push(p.clone()),
                Err(e) => {
                    log::warn!("cannot watch {}: {e}", p.display());
                    last_err = Some(e.to_string());
                }
            }
        }
        if watched.is_empty() {
            return Err(Error::Other(format!("no folder could be monitored{}", last_err.map(|e| format!(": {e}")).unwrap_or_default())));
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let worker = std::thread::Builder::new()
            .name("seccom-realtime".into())
            .spawn(move || {
                let mut pending: HashMap<PathBuf, (Instant, Option<u64>)> = HashMap::new();
                let mut last_scanned: HashMap<PathBuf, (u64, Option<std::time::SystemTime>)> = HashMap::new();
                while !stop_flag.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(Ok(event)) => {
                            let relevant =
                                matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any | EventKind::Other);
                            if relevant && pending.len() < MAX_PENDING {
                                for p in event.paths {
                                    if ignore.iter().any(|i| p.starts_with(i)) {
                                        continue;
                                    }
                                    pending.insert(p, (Instant::now(), None));
                                }
                            }
                        }
                        Ok(Err(e)) => log::warn!("file monitor error: {e}"),
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }

                    let now = Instant::now();
                    let due: Vec<PathBuf> =
                        pending.iter().filter(|(_, (t, _))| now.duration_since(*t) >= SETTLE).map(|(p, _)| p.clone()).collect();
                    for p in due {
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        let meta = match std::fs::metadata(&p) {
                            Ok(m) if m.is_file() => m,
                            _ => {
                                pending.remove(&p);
                                continue;
                            }
                        };
                        let size = meta.len();
                        if let Some(entry) = pending.get_mut(&p)
                            && entry.1 != Some(size)
                        {
                            // Still growing (or first look): wait another period.
                            *entry = (now, Some(size));
                            continue;
                        }
                        pending.remove(&p);
                        if is_temp(&p) || opts.is_excluded(&p) {
                            continue;
                        }
                        let mtime = meta.modified().ok();
                        if last_scanned.get(&p) == Some(&(size, mtime)) {
                            continue;
                        }
                        if last_scanned.len() > 50_000 {
                            last_scanned.clear();
                        }
                        last_scanned.insert(p.clone(), (size, mtime));
                        let verdict = engine.scan_file_with_cancel(&p, &opts, &|| stop_flag.load(Ordering::Relaxed));
                        on_result(verdict);
                    }
                }
            })
            .map_err(|e| Error::Other(format!("cannot start monitor thread: {e}")))?;

        Ok(RealtimeMonitor { watcher: Some(watcher), stop, worker: Some(worker), watched })
    }

    /// Folders actually being watched.
    pub fn watched(&self) -> &[PathBuf] {
        &self.watched
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Dropping the watcher closes the event channel.
        self.watcher.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for RealtimeMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Verdict;
    use std::sync::Mutex;

    #[test]
    fn temp_names() {
        assert!(is_temp(Path::new("/d/file.zip.crdownload")));
        assert!(is_temp(Path::new("/d/~$report.docx")));
        assert!(!is_temp(Path::new("/d/report.docx")));
    }

    #[test]
    fn detects_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(Engine::with_builtin());
        let results: Arc<Mutex<Vec<FileVerdict>>> = Arc::new(Mutex::new(Vec::new()));
        let r2 = results.clone();
        let mon = RealtimeMonitor::start(
            engine,
            &[dir.path().to_path_buf()],
            ScanOptions::default(),
            vec![],
            Arc::new(move |v| r2.lock().unwrap().push(v)),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let eicar: Vec<u8> = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".bytes().rev().collect();
        std::fs::write(dir.path().join("download.com"), eicar).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if results.lock().unwrap().iter().any(|v| v.verdict == Verdict::Malicious) {
                break;
            }
            assert!(Instant::now() < deadline, "real-time monitor did not report the file");
            std::thread::sleep(Duration::from_millis(100));
        }
        mon.stop();
    }
}
