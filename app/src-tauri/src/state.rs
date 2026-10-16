//! Application state and its persistence.

use crate::model::{ScanRecord, Stats, ThreatEntry, UpdateCheck};
use crate::network::NetworkProtection;
use crate::realtime::Realtime;
use crate::scan::RunningScan;
use crate::settings::Settings;
use seccom_engine::quarantine::Quarantine;
use seccom_engine::util::now_unix;
use seccom_engine::{Engine, SignatureDb};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::Duration;

const MAX_HISTORY: usize = 100;
const MAX_THREATS_PER_RECORD: usize = 1000;

/// Engine shared with the Android background service (JNI).
pub static GLOBAL_ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();

/// Files and folders used by the application.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    /// Read-only databases shipped inside the application bundle.
    pub db_bundled: Option<PathBuf>,
    #[cfg_attr(not(feature = "online-update"), allow(dead_code))]
    pub db_root: PathBuf,
    pub db_current: PathBuf,
    pub db_user: PathBuf,
    pub quarantine: PathBuf,
    pub settings: PathBuf,
    pub history: PathBuf,
    pub stats: PathBuf,
    pub threats: PathBuf,
    pub cache: PathBuf,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub apps_report: PathBuf,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub pending_threats: PathBuf,
    pub network_intel: PathBuf,
}

impl Paths {
    pub fn new(data: PathBuf) -> Self {
        let db_root = data.join("db");
        Paths {
            db_bundled: None,
            db_current: db_root.join("current"),
            db_user: db_root.join("user"),
            db_root,
            quarantine: data.join("quarantine"),
            settings: data.join("settings.json"),
            history: data.join("history.json"),
            stats: data.join("stats.json"),
            threats: data.join("threats.json"),
            cache: data.join("scan-cache.bin"),
            apps_report: data.join("apps-report.json"),
            pending_threats: data.join("pending_threats.jsonl"),
            network_intel: data.join("network/feodo-ipblocklist.txt"),
            data,
        }
    }

    pub fn db_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(bundled) = &self.db_bundled {
            dirs.push(bundled.clone());
        }
        dirs.push(self.db_current.clone());
        dirs.push(self.db_user.clone());
        dirs.extend(crate::platform::system_signature_dirs());
        dirs
    }
}

pub fn load_json<T: DeserializeOwned + Default>(path: &Path) -> T {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log::warn!("{} is corrupted ({e}); using defaults", path.display());
            T::default()
        }),
        Err(_) => T::default(),
    }
}

/// Writes JSON atomically (temporary file + rename).
pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Loads the installed + user signature databases (built-ins always included).
pub fn load_signature_db(paths: &Paths) -> SignatureDb {
    match SignatureDb::load_dirs(&paths.db_dirs()) {
        Ok(db) => db,
        Err(e) => {
            log::error!("signature database failed to load: {e}; using built-in signatures");
            SignatureDb::builtin()
        }
    }
}

pub struct AppState {
    pub paths: Paths,
    pub engine: Arc<Engine>,
    db_ready: Mutex<bool>,
    db_ready_cv: Condvar,
    pub settings: RwLock<Settings>,
    pub stats: Mutex<Stats>,
    pub history: Mutex<Vec<ScanRecord>>,
    pub threats: Mutex<Vec<ThreatEntry>>,
    pub quarantine: Quarantine,
    pub scan: Mutex<Option<RunningScan>>,
    pub realtime: Realtime,
    pub network: NetworkProtection,
    pub update_lock: Mutex<()>,
    #[cfg_attr(not(feature = "online-update"), allow(dead_code))]
    pub last_update_check: Mutex<Option<UpdateCheck>>,
    /// Files the user restored from quarantine during this session (path → SHA-256).
    /// Real-time protection leaves them alone; a manual scan still reports them.
    restored: Mutex<HashMap<PathBuf, String>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Result<Self, String> {
        let paths = Paths::new(data_dir);
        for d in [&paths.data, &paths.db_current, &paths.db_user] {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let settings: Settings = load_json::<Settings>(&paths.settings).sanitize();
        let mut stats: Stats = load_json(&paths.stats);
        if stats.installed_at == 0 {
            stats.installed_at = now_unix();
        }
        let quarantine = Quarantine::open(&paths.quarantine).map_err(|e| e.to_string())?;
        let engine = Arc::new(Engine::with_builtin());
        let _ = GLOBAL_ENGINE.set(engine.clone());
        Ok(AppState {
            history: Mutex::new(load_json(&paths.history)),
            threats: Mutex::new(load_json(&paths.threats)),
            settings: RwLock::new(settings),
            stats: Mutex::new(stats),
            quarantine,
            engine,
            db_ready: Mutex::new(false),
            db_ready_cv: Condvar::new(),
            scan: Mutex::new(None),
            realtime: Realtime::default(),
            network: NetworkProtection::default(),
            update_lock: Mutex::new(()),
            last_update_check: Mutex::new(None),
            restored: Mutex::new(HashMap::new()),
            paths,
        })
    }

    // ------------------------------------------------------------ database

    /// (Re)loads the signature database and wakes waiting scans.
    pub fn reload_db(&self) {
        let db = load_signature_db(&self.paths);
        self.engine.set_db(db);
        let mut ready = self.db_ready.lock().unwrap_or_else(|e| e.into_inner());
        *ready = true;
        self.db_ready_cv.notify_all();
    }

    pub fn is_db_ready(&self) -> bool {
        *self.db_ready.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits until the full database has been loaded (max `timeout`).
    pub fn wait_db_ready(&self, timeout: Duration) {
        let guard = self.db_ready.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.db_ready_cv.wait_timeout_while(guard, timeout, |ready| !*ready);
    }

    // ------------------------------------------------------------ settings

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn save_settings(&self, s: Settings) -> Result<Settings, String> {
        let s = s.sanitize();
        save_json(&self.paths.settings, &s)?;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = s.clone();
        Ok(s)
    }

    pub fn scan_options(&self) -> seccom_engine::ScanOptions {
        self.settings().scan_options(&crate::platform::default_exclusions(&self.paths))
    }

    // --------------------------------------------------------------- stats

    pub fn update_stats(&self, f: impl FnOnce(&mut Stats)) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
        if let Err(e) = save_json(&self.paths.stats, &*s) {
            log::warn!("cannot save stats: {e}");
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    // ------------------------------------------------------------- history

    pub fn push_history(&self, mut record: ScanRecord) {
        record.threats.truncate(MAX_THREATS_PER_RECORD);
        record.roots.truncate(50);
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        h.insert(0, record);
        h.truncate(MAX_HISTORY);
        if let Err(e) = save_json(&self.paths.history, &*h) {
            log::warn!("cannot save history: {e}");
        }
    }

    pub fn history(&self) -> Vec<ScanRecord> {
        self.history.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn clear_history(&self) -> Result<(), String> {
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        h.clear();
        save_json(&self.paths.history, &*h)
    }

    // ------------------------------------------------------------- threats

    /// Adds (or replaces, for the same path) an active threat.
    pub fn add_threat(&self, entry: ThreatEntry) {
        let mut t = self.threats.lock().unwrap_or_else(|e| e.into_inner());
        t.retain(|x| x.verdict.path != entry.verdict.path || x.package_name != entry.package_name);
        t.insert(0, entry);
        t.truncate(5000);
        if let Err(e) = save_json(&self.paths.threats, &*t) {
            log::warn!("cannot save threats: {e}");
        }
    }

    /// Remembers that the user restored `path` (content `sha256`) from quarantine.
    pub fn mark_restored(&self, path: &Path, sha256: &str) {
        let mut r = self.restored.lock().unwrap_or_else(|e| e.into_inner());
        if r.len() > 1000 {
            r.clear();
        }
        r.insert(path.to_path_buf(), sha256.to_ascii_lowercase());
    }

    /// True when `path` still holds the exact file the user restored from quarantine.
    pub fn is_restored(&self, path: &str, sha256: Option<&str>) -> bool {
        let Some(sha) = sha256 else { return false };
        let r = self.restored.lock().unwrap_or_else(|e| e.into_inner());
        r.get(Path::new(path)).is_some_and(|h| h.eq_ignore_ascii_case(sha))
    }

    /// Active threats, most dangerous first and newest first within a verdict.
    pub fn threats(&self) -> Vec<ThreatEntry> {
        let mut list = self.threats.lock().unwrap_or_else(|e| e.into_inner()).clone();
        list.sort_by(|a, b| {
            b.verdict.verdict.cmp(&a.verdict.verdict).then(b.verdict.score.cmp(&a.verdict.score)).then(b.detected_at.cmp(&a.detected_at))
        });
        list
    }

    pub fn take_threat(&self, id: &str) -> Option<ThreatEntry> {
        let t = self.threats.lock().unwrap_or_else(|e| e.into_inner());
        t.iter().find(|x| x.id == id).cloned()
    }

    pub fn remove_threats(&self, ids: &[String]) {
        let mut t = self.threats.lock().unwrap_or_else(|e| e.into_inner());
        t.retain(|x| !ids.contains(&x.id));
        if let Err(e) = save_json(&self.paths.threats, &*t) {
            log::warn!("cannot save threats: {e}");
        }
    }

    /// Removes threats whose file no longer exists (deleted outside the app).
    pub fn prune_threats(&self) {
        let mut t = self.threats.lock().unwrap_or_else(|e| e.into_inner());
        let before = t.len();
        t.retain(|x| x.package_name.is_some() || Path::new(&x.verdict.path).exists());
        if t.len() != before {
            let _ = save_json(&self.paths.threats, &*t);
        }
    }

    /// Imports detections recorded by the Android background service.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn import_pending_threats(&self) {
        let pending = &self.paths.pending_threats;
        if !pending.exists() {
            return;
        }
        let work = pending.with_extension("processing");
        if std::fs::rename(pending, &work).is_err() {
            return;
        }
        if let Ok(text) = std::fs::read_to_string(&work) {
            let settings = self.settings();
            for line in text.lines() {
                if let Ok(entry) = serde_json::from_str::<ThreatEntry>(line)
                    && !settings.is_allowed(entry.verdict.sha256.as_deref())
                {
                    self.update_stats(|s| s.threats_found += 1);
                    self.add_threat(entry);
                }
            }
        }
        let _ = std::fs::remove_file(&work);
    }
}

/// Creates a threat entry for a verdict.
pub fn threat_entry(verdict: seccom_engine::FileVerdict, source: &str) -> ThreatEntry {
    ThreatEntry {
        id: uuid::Uuid::new_v4().simple().to_string(),
        verdict,
        source: source.to_string(),
        detected_at: now_unix(),
        package_name: None,
        app_label: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> (AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!("seccom-state-test-{}", uuid::Uuid::new_v4().simple()));
        let state = AppState::new(dir.clone()).expect("state");
        (state, dir)
    }

    #[test]
    fn restored_files_match_path_and_content() {
        let (state, dir) = temp_state();
        let path = dir.join("Downloads").join("file.bin");
        assert!(!state.is_restored(&path.to_string_lossy(), Some("abc")));
        state.mark_restored(&path, "ABC");
        assert!(state.is_restored(&path.to_string_lossy(), Some("abc")));
        // Different content at the same path is checked normally again.
        assert!(!state.is_restored(&path.to_string_lossy(), Some("def")));
        assert!(!state.is_restored(&path.to_string_lossy(), None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn threats_are_sorted_by_danger_then_age() {
        use seccom_engine::{FileVerdict, Verdict};
        let (state, dir) = temp_state();
        let entry = |id: &str, verdict: Verdict, score: u32, at: u64| ThreatEntry {
            id: id.into(),
            verdict: FileVerdict { path: format!("/x/{id}"), verdict, score, ..Default::default() },
            source: "scan".into(),
            detected_at: at,
            package_name: None,
            app_label: None,
        };
        state.add_threat(entry("old-suspicious", Verdict::Suspicious, 45, 100));
        state.add_threat(entry("old-malicious", Verdict::Malicious, 0, 100));
        state.add_threat(entry("new-suspicious", Verdict::Suspicious, 45, 200));
        state.add_threat(entry("new-malicious", Verdict::Malicious, 0, 200));
        let ids: Vec<String> = state.threats().into_iter().map(|t| t.id).collect();
        assert_eq!(ids, ["new-malicious", "old-malicious", "new-suspicious", "old-suspicious"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
