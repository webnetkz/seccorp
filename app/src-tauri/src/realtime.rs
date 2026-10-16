//! Real-time protection.
//!
//! * Desktop and iOS: the engine's file-system monitor watches folders while
//!   the app runs (desktop keeps running in the tray).
//! * Android: a foreground service (Kotlin) scans new downloads and newly
//!   installed apps through JNI, even when the UI is closed.

use crate::i18n::t;
use crate::model::{RealtimeEvent, RealtimeStatus};
use crate::notify::notify;
use crate::platform;
use crate::state::{AppState, threat_entry};
use seccom_engine::Verdict;
use seccom_engine::realtime::RealtimeMonitor;
use seccom_engine::util::now_unix;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, Runtime};

const MAX_EVENTS: usize = 200;

#[derive(Default)]
pub struct Realtime {
    monitor: Mutex<Option<RealtimeMonitor>>,
    events: Mutex<VecDeque<RealtimeEvent>>,
    scanned: AtomicU64,
    error: Mutex<Option<String>>,
    /// Privacy-protected folders are left out (macOS without Full Disk Access).
    limited: AtomicBool,
}

pub fn supported() -> bool {
    true
}

impl Realtime {
    pub fn events(&self) -> Vec<RealtimeEvent> {
        self.events.lock().map(|e| e.iter().cloned().collect()).unwrap_or_default()
    }

    fn push_event(&self, e: RealtimeEvent) {
        if let Ok(mut q) = self.events.lock() {
            q.push_front(e);
            q.truncate(MAX_EVENTS);
        }
    }

    pub fn is_running(&self) -> bool {
        self.monitor.lock().map(|m| m.is_some()).unwrap_or(false)
    }

    fn watched(&self) -> Vec<String> {
        self.monitor
            .lock()
            .ok()
            .and_then(|m| m.as_ref().map(|m| m.watched().iter().map(|p| p.to_string_lossy().into_owned()).collect()))
            .unwrap_or_default()
    }
}

/// Current real-time protection status.
pub fn status<R: Runtime>(app: &AppHandle<R>) -> RealtimeStatus {
    let state = app.state::<AppState>();
    let settings = state.settings();
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        let running = app.seccom_device().protection_status().map(|s| s.running).unwrap_or(false);
        let watched = if running {
            platform::default_watch_paths(app, &state).iter().map(|p| p.to_string_lossy().into_owned()).collect()
        } else {
            Vec::new()
        };
        return RealtimeStatus {
            supported: true,
            enabled: settings.realtime_enabled,
            running,
            watched,
            scanned: state.realtime.scanned.load(Ordering::Relaxed),
            error: state.realtime.error.lock().ok().and_then(|e| e.clone()),
            limited: false,
        };
    }
    #[allow(unreachable_code)]
    RealtimeStatus {
        supported: supported(),
        enabled: settings.realtime_enabled,
        running: state.realtime.is_running(),
        watched: state.realtime.watched(),
        scanned: state.realtime.scanned.load(Ordering::Relaxed),
        error: state.realtime.error.lock().ok().and_then(|e| e.clone()),
        limited: state.realtime.limited.load(Ordering::Relaxed),
    }
}

/// Starts or restarts protection according to the settings.
pub fn apply<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    stop(app);
    let settings = state.settings();
    if !settings.realtime_enabled {
        let _ = app.emit("status://changed", ());
        return;
    }

    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seccom_device::{ProtectionConfig, SeccomDeviceExt};
        let lang = crate::i18n::lang(&state);
        let cfg = ProtectionConfig {
            watch_downloads: settings.watch_downloads,
            scan_installs: settings.scan_new_apps,
            data_dir: state.paths.data.to_string_lossy().into_owned(),
            title: t(lang, "android_status_title").into(),
            text: t(lang, "android_status_text").into(),
        };
        let result = app.seccom_device().start_protection(cfg);
        *state.realtime.error.lock().unwrap_or_else(|e| e.into_inner()) = result.err().map(|e| e.to_string());
        let _ = app.emit("status://changed", ());
        return;
    }

    #[allow(unreachable_code)]
    {
        let mut paths: Vec<PathBuf> = if settings.realtime_paths.is_empty() {
            platform::default_watch_paths(app, &state)
        } else {
            settings.realtime_paths.iter().map(PathBuf::from).collect()
        };
        let opts = state.scan_options();
        let mut ignore = vec![state.paths.data.clone()];
        // Without Full Disk Access, reading new files in Desktop, Documents,
        // Downloads etc. would make macOS ask again and again: leave them out.
        let locked = platform::locked_dirs(app);
        state.realtime.limited.store(!locked.is_empty(), Ordering::Relaxed);
        paths.retain(|p| !locked.iter().any(|l| p.starts_with(l)));
        ignore.extend(locked);
        let handle = app.clone();
        let callback = Arc::new(move |v: seccom_engine::FileVerdict| on_result(&handle, v));
        match RealtimeMonitor::start(state.engine.clone(), &paths, opts, ignore, callback) {
            Ok(m) => {
                *state.realtime.monitor.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
                *state.realtime.error.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
            Err(e) => {
                log::warn!("real-time protection could not start: {e}");
                *state.realtime.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
            }
        }
        let _ = app.emit("status://changed", ());
        crate::tray::refresh(app);
    }
}

pub fn stop<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<AppState>();
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        if !state.settings().realtime_enabled {
            let _ = app.seccom_device().stop_protection();
        }
    }
    let monitor = state.realtime.monitor.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(m) = monitor {
        m.stop();
    }
}

fn on_result<R: Runtime>(app: &AppHandle<R>, v: seccom_engine::FileVerdict) {
    let state = app.state::<AppState>();
    state.realtime.scanned.fetch_add(1, Ordering::Relaxed);
    let settings = state.settings();
    if v.is_threat() && (settings.is_allowed(v.sha256.as_deref()) || state.is_restored(&v.path, v.sha256.as_deref())) {
        return;
    }
    let mut action = "none".to_string();
    if v.is_threat() {
        let name = v.threat_name().unwrap_or("Unknown").to_string();
        let lang = crate::i18n::lang(&state);
        let file = std::path::Path::new(&v.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        state.update_stats(|s| s.threats_found += 1);
        if settings.auto_quarantine && v.verdict == Verdict::Malicious {
            match state.quarantine.add(std::path::Path::new(&v.path), &name) {
                Ok(_) => {
                    action = "quarantined".into();
                    state.update_stats(|s| s.threats_neutralized += 1);
                    notify(app, t(lang, "threat_title"), &format!("{file} — {name}\n{}", t(lang, "threat_quarantined")));
                }
                Err(e) => {
                    log::warn!("auto-quarantine failed for {}: {e}", v.path);
                    action = "failed".into();
                }
            }
        }
        if action != "quarantined" {
            state.add_threat(threat_entry(v.clone(), "realtime"));
            notify(app, t(lang, "threat_title"), &format!("{file} — {name}\n{}", t(lang, "threat_action_needed")));
        }
        let _ = app.emit("status://changed", ());
    }
    let event = RealtimeEvent {
        time: now_unix(),
        path: v.path.clone(),
        verdict: v.verdict,
        threat_name: v.threat_name().map(str::to_string),
        action,
    };
    state.realtime.push_event(event.clone());
    let _ = app.emit("realtime://event", &event);
}
