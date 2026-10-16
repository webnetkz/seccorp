//! On-demand scans: quick, full, custom and (Android) installed apps.

use crate::i18n::t;
use crate::model::{ScanProgressEvent, ScanRecord, ScanState, ThreatEntry};
use crate::notify::notify;
use crate::platform;
use crate::state::{AppState, threat_entry};
use seccom_engine::cache::ScanCache;
use seccom_engine::util::now_unix;
use seccom_engine::{ScanControl, ScanEvent, ScanSummary};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime};

pub struct RunningScan {
    pub id: String,
    pub kind: String,
    pub control: Arc<ScanControl>,
    pub threats: Arc<Mutex<Vec<ThreatEntry>>>,
}

fn normalize_kind(kind: &str) -> Result<&'static str, String> {
    Ok(match kind {
        "quick" => "quick",
        "full" => "full",
        "custom" => "custom",
        "apps" if cfg!(target_os = "android") => "apps",
        other => return Err(format!("unknown scan type: {other}")),
    })
}

/// Error returned when macOS privacy protection would interrupt the scan with
/// consent prompts; the UI then offers to grant Full Disk Access or to scan
/// without the protected folders.
pub const FDA_REQUIRED: &str = "fda_required";

/// Starts a scan in the background and returns its id. Background scans (tray,
/// schedule) never ask: without Full Disk Access they skip protected folders.
#[cfg(desktop)]
pub fn start<R: Runtime>(app: &AppHandle<R>, kind: &str, paths: Vec<String>, origin: &str) -> Result<String, String> {
    start_with(app, kind, paths, origin, origin != "user")
}

/// Like [`start`]; `allow_limited` lets the scan run without the folders macOS
/// keeps private until Full Disk Access is granted (otherwise [`FDA_REQUIRED`]).
pub fn start_with<R: Runtime>(
    app: &AppHandle<R>,
    kind: &str,
    paths: Vec<String>,
    origin: &str,
    allow_limited: bool,
) -> Result<String, String> {
    let kind = normalize_kind(kind)?;
    if kind == "custom" && paths.is_empty() {
        return Err("no paths selected".into());
    }
    let mut locked = platform::locked_dirs(app);
    if !locked.is_empty() {
        let needed = match kind {
            "custom" => {
                let roots: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
                platform::reaches_locked(&roots, &locked, true)
            }
            _ => true,
        };
        if !needed {
            locked.clear();
        } else if !allow_limited {
            return Err(FDA_REQUIRED.into());
        }
    }
    let state = app.state::<AppState>();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let control = Arc::new(ScanControl::new());
    let threats = Arc::new(Mutex::new(Vec::new()));
    {
        let mut slot = state.scan.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err("busy".into());
        }
        *slot = Some(RunningScan { id: id.clone(), kind: kind.to_string(), control: control.clone(), threats: threats.clone() });
    }
    let job = ScanJob { id: id.clone(), kind, custom: paths, control, found: threats, origin: origin.to_string(), locked };
    let app2 = app.clone();
    let spawned = std::thread::Builder::new().name("seccom-scan".into()).spawn(move || run(app2, job));
    if let Err(e) = spawned {
        *state.scan.lock().unwrap_or_else(|e| e.into_inner()) = None;
        return Err(e.to_string());
    }
    Ok(id)
}

fn with_running<R: Runtime>(app: &AppHandle<R>, f: impl FnOnce(&RunningScan)) -> Result<(), String> {
    let state = app.state::<AppState>();
    let slot = state.scan.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some(s) => {
            f(s);
            Ok(())
        }
        None => Err("no scan is running".into()),
    }
}

pub fn pause<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    with_running(app, |s| s.control.pause())
}

pub fn resume<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    with_running(app, |s| s.control.resume())
}

pub fn cancel<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    with_running(app, |s| s.control.cancel())
}

pub fn current_state<R: Runtime>(app: &AppHandle<R>) -> ScanState {
    let state = app.state::<AppState>();
    let slot = state.scan.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_ref() {
        Some(s) => ScanState {
            running: true,
            scan_id: Some(s.id.clone()),
            kind: Some(s.kind.clone()),
            progress: Some(s.control.progress()),
            threats: s.threats.lock().map(|t| t.clone()).unwrap_or_default(),
        },
        None => ScanState { running: false, scan_id: None, kind: None, progress: None, threats: Vec::new() },
    }
}

/// Everything a background scan needs.
struct ScanJob {
    id: String,
    kind: &'static str,
    custom: Vec<String>,
    control: Arc<ScanControl>,
    found: Arc<Mutex<Vec<ThreatEntry>>>,
    origin: String,
    /// Privacy-protected folders to skip (macOS without Full Disk Access).
    locked: Vec<PathBuf>,
}

fn run<R: Runtime>(app: AppHandle<R>, job: ScanJob) {
    let ScanJob { id, kind, custom, control, found, origin, locked } = job;
    let state = app.state::<AppState>();
    let started_at = now_unix();

    // Progress ticker.
    let done = Arc::new(AtomicBool::new(false));
    let ticker = {
        let app = app.clone();
        let control = control.clone();
        let done = done.clone();
        let id = id.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let _ = app.emit(
                    "scan://progress",
                    ScanProgressEvent { scan_id: id.clone(), kind: kind.to_string(), progress: control.progress() },
                );
                std::thread::sleep(Duration::from_millis(250));
            }
        })
    };

    state.wait_db_ready(Duration::from_secs(180));
    let settings = state.settings();
    let roots: Vec<PathBuf> = match kind {
        "quick" => platform::quick_scan_targets(&app, &state),
        "full" => platform::full_scan_roots(&app, &state),
        "custom" => custom.iter().map(PathBuf::from).filter(|p| p.exists()).collect(),
        _ => Vec::new(),
    };

    let mut opts = state.scan_options();
    if kind == "custom" {
        // Explicitly selected roots (including /Volumes/<drive>) must remain
        // scannable even when their parent is excluded from a whole-disk scan.
        // User-defined exclusions still win.
        let platform_exclusions = platform::default_exclusions(&state.paths);
        opts.exclusions.retain(|rule| {
            settings.exclusions.contains(rule)
                || !platform_exclusions.contains(rule)
                || !roots.iter().any(|root| root.starts_with(PathBuf::from(rule)))
        });
    }
    // Skip privacy-protected folders instead of triggering a prompt for each one.
    let limited = !locked.is_empty();
    opts.exclusions.extend(locked.iter().map(|p| p.to_string_lossy().into_owned()));

    let cache = opts.use_cache.then(|| {
        let key = format!("{}|{}", state.engine.db().fingerprint(), opts.detection_fingerprint());
        ScanCache::open(&state.paths.cache, &key)
    });

    let on_event = |event: ScanEvent| {
        if let ScanEvent::Threat(v) = event {
            if settings.is_allowed(v.sha256.as_deref()) {
                return;
            }
            let entry = threat_entry(v, "scan");
            if let Ok(mut f) = found.lock() {
                f.push(entry.clone());
            }
            state.add_threat(entry.clone());
            let _ = app.emit("scan://threat", &entry);
        }
    };

    let mut summary = if roots.is_empty() {
        ScanSummary { id: id.clone(), started_at, ..Default::default() }
    } else {
        state.engine.scan_paths(&roots, &opts, &control, cache.as_ref(), &on_event)
    };

    #[cfg(target_os = "android")]
    {
        let include_apps = kind == "apps" || (matches!(kind, "quick" | "full") && settings.scan_installed_apps);
        if include_apps && !control.is_cancelled() {
            let app_threats = platform::android::scan_installed_apps(&app, &state, &opts, &control, &found);
            summary.threats.extend(app_threats);
        }
    }

    if let Some(c) = &cache
        && let Err(e) = c.save()
    {
        log::warn!("cannot save scan cache: {e}");
    }
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let final_progress = control.progress();
    let _ =
        app.emit("scan://progress", ScanProgressEvent { scan_id: id.clone(), kind: kind.to_string(), progress: final_progress.clone() });

    summary.threats.retain(|v| !settings.is_allowed(v.sha256.as_deref()));
    let cancelled = control.is_cancelled();
    let record = ScanRecord {
        id: id.clone(),
        kind: kind.to_string(),
        started_at,
        finished_at: now_unix().max(started_at),
        files_scanned: final_progress.files_scanned,
        files_cached: final_progress.files_cached,
        files_skipped: final_progress.files_skipped,
        bytes_scanned: final_progress.bytes_scanned,
        errors: final_progress.errors,
        cancelled,
        threat_count: summary.threats.len() as u64,
        threats: summary.threats,
        // Normalized by the engine: no duplicates or nested folders.
        roots: summary.roots,
        limited,
    };
    state.push_history(record.clone());
    let now = now_unix();
    state.update_stats(|s| {
        s.files_scanned += record.files_scanned;
        s.threats_found += record.threat_count;
        if !cancelled {
            s.scans_completed += 1;
            s.last_scan_at = Some(now);
            if kind == "full" {
                s.last_full_scan_at = Some(now);
            }
        }
    });
    *state.scan.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let _ = app.emit("scan://finished", &record);
    let _ = app.emit("status://changed", ());

    let lang = crate::i18n::lang(&state);
    let limited_note = if record.limited { format!("\n{}", t(lang, "scan_limited")) } else { String::new() };
    if record.threat_count > 0 {
        let body = t(lang, "scan_threats").replace("{n}", &record.threat_count.to_string());
        notify(&app, t(lang, "scan_done"), &format!("{body}{limited_note}"));
    } else if origin != "user" && !cancelled {
        notify(&app, t(lang, "scan_done"), &format!("{}{limited_note}", t(lang, "scan_clean")));
    }
}
