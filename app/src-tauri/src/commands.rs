//! Commands invoked by the user interface.

use crate::model::*;
use crate::platform;
use crate::settings::Settings;
use crate::state::{AppState, threat_entry};
use seccom_engine::quarantine::QuarantineItem;
use seccom_engine::util::now_unix;
use seccom_engine::{DbInfo, FileVerdict};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Emitter, Manager};

type CmdResult<T> = Result<T, String>;

/// Runs blocking work off the main thread.
async fn blocking<T: Send + 'static>(app: AppHandle, f: impl FnOnce(AppHandle) -> CmdResult<T> + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(move || f(app)).await.map_err(|e| e.to_string())?
}

// ------------------------------------------------------------------ general

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    let state = app.state::<AppState>();
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        engine_version: seccom_engine::ENGINE_VERSION.into(),
        platform: platform::platform_name().into(),
        arch: std::env::consts::ARCH.into(),
        features: platform::features(),
        update_configured: crate::updater::configured(&state),
        update_mode: crate::updater::mode(&state).into(),
        data_dir: state.paths.data.to_string_lossy().into_owned(),
    }
}

#[tauri::command]
pub async fn get_dashboard(app: AppHandle) -> CmdResult<Dashboard> {
    blocking(app, |app| Ok(dashboard(&app))).await
}

pub fn dashboard(app: &AppHandle) -> Dashboard {
    let state = app.state::<AppState>();
    #[cfg(target_os = "android")]
    state.import_pending_threats();
    state.prune_threats();
    let realtime = crate::realtime::status(app);
    let network = crate::network::status(app);
    let db = state.engine.db_info();
    let stats = state.stats();
    let active_threats = state.threats().len();
    let quarantine = state.quarantine.list().unwrap_or_default();
    let now = now_unix();

    let mut issues = Vec::new();
    if active_threats > 0 {
        issues.push("threats".to_string());
    }
    if realtime.supported && !realtime.enabled {
        issues.push("realtime_off".into());
    } else if realtime.enabled && !realtime.running {
        issues.push("realtime_error".into());
    }
    if network.supported && !network.enabled {
        issues.push("network_off".into());
    } else if !network.alerts.is_empty() {
        issues.push("network_alert".into());
    } else if network.enabled && !network.running {
        issues.push("network_error".into());
    }
    match stats.last_scan_at {
        None => issues.push("never_scanned".into()),
        Some(t) if now.saturating_sub(t) > 14 * 86_400 => issues.push("no_recent_scan".into()),
        _ => {}
    }
    if crate::updater::configured(&state) && db.released > 0 && now.saturating_sub(db.released) > 7 * 86_400 {
        issues.push("db_outdated".into());
    }
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        if let Ok(a) = app.seccom_device().get_storage_access() {
            if !a.granted {
                issues.push("storage_access".into());
            }
        }
    }
    if platform::needs_full_disk_access(app) {
        issues.push("full_disk_access".into());
    }
    let status = if active_threats > 0 {
        "danger"
    } else if issues.iter().any(|i| i != "full_disk_access" && i != "never_scanned") {
        "attention"
    } else {
        "protected"
    };
    Dashboard {
        status: status.into(),
        issues,
        realtime,
        network,
        db,
        db_ready: state.is_db_ready(),
        stats,
        active_threats,
        quarantine_count: quarantine.len(),
        quarantine_bytes: quarantine.iter().map(|q| q.size).sum(),
        last_scan: state.history().into_iter().next(),
        scan_running: state.scan.lock().map(|s| s.is_some()).unwrap_or(false),
    }
}

#[tauri::command]
pub fn get_settings(app: AppHandle) -> Settings {
    app.state::<AppState>().settings()
}

#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: Settings) -> CmdResult<Settings> {
    blocking(app, move |app| apply_settings(&app, settings)).await
}

pub fn apply_settings(app: &AppHandle, new: Settings) -> CmdResult<Settings> {
    let state = app.state::<AppState>();
    let old = state.settings();
    let mut new = new.sanitize();
    let sched_changed = {
        let (a, b) = (&old.schedule, &new.schedule);
        a.enabled != b.enabled || a.frequency != b.frequency || a.weekday != b.weekday || a.hour != b.hour || a.minute != b.minute
    };
    if sched_changed {
        // Do not fire immediately for a slot that already passed.
        new.schedule.last_run = now_unix();
    }
    let saved = state.save_settings(new)?;

    let realtime_changed = old.realtime_enabled != saved.realtime_enabled
        || old.realtime_paths != saved.realtime_paths
        || old.watch_downloads != saved.watch_downloads
        || old.scan_new_apps != saved.scan_new_apps
        || old.exclusions != saved.exclusions
        || old.heuristics != saved.heuristics
        || old.scan_archives != saved.scan_archives
        || old.max_file_size_mb != saved.max_file_size_mb;
    if realtime_changed {
        crate::realtime::apply(app);
    }
    let network_changed = old.network_monitor_enabled != saved.network_monitor_enabled
        || old.network_threat_intel != saved.network_threat_intel
        || old.network_spyware_heuristics != saved.network_spyware_heuristics;
    if network_changed {
        crate::network::apply(app);
    }
    if old.language != saved.language {
        crate::tray::refresh(app);
    }
    #[cfg(desktop)]
    if old.launch_at_login != saved.launch_at_login {
        use tauri_plugin_autostart::ManagerExt;
        let r = if saved.launch_at_login { app.autolaunch().enable() } else { app.autolaunch().disable() };
        if let Err(e) = r {
            log::warn!("autostart change failed: {e}");
        }
    }
    let _ = app.emit("status://changed", ());
    Ok(saved)
}

#[tauri::command]
pub fn next_scheduled_scan(app: AppHandle) -> Option<u64> {
    #[cfg(desktop)]
    {
        return crate::scheduler::next_run(&app.state::<AppState>().settings().schedule);
    }
    #[allow(unreachable_code)]
    {
        let _ = app;
        None
    }
}

// ----------------------------------------------------------------- scanning

/// Starts a scan. On macOS without Full Disk Access it fails with
/// `fda_required` unless `limited` allows skipping the protected folders.
#[tauri::command]
pub fn start_scan(app: AppHandle, kind: String, paths: Vec<String>, limited: Option<bool>) -> CmdResult<String> {
    crate::scan::start_with(&app, &kind, paths, "user", limited.unwrap_or(false))
}

#[tauri::command]
pub fn pause_scan(app: AppHandle) -> CmdResult<()> {
    crate::scan::pause(&app)
}

#[tauri::command]
pub fn resume_scan(app: AppHandle) -> CmdResult<()> {
    crate::scan::resume(&app)
}

#[tauri::command]
pub fn cancel_scan(app: AppHandle) -> CmdResult<()> {
    crate::scan::cancel(&app)
}

#[tauri::command]
pub fn get_scan_state(app: AppHandle) -> ScanState {
    crate::scan::current_state(&app)
}

/// Scans one file immediately (picked or shared by the user).
#[tauri::command]
pub async fn scan_file_now(app: AppHandle, path: String) -> CmdResult<FileVerdict> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        state.wait_db_ready(std::time::Duration::from_secs(60));
        let p = PathBuf::from(&path);
        if !p.is_file() {
            return Err("file not found".into());
        }
        let v = state.engine.scan_file(&p, &state.scan_options());
        state.update_stats(|s| s.files_scanned += 1);
        if v.is_threat() && !state.settings().is_allowed(v.sha256.as_deref()) {
            state.update_stats(|s| s.threats_found += 1);
            state.add_threat(threat_entry(v.clone(), "scan"));
            let _ = app.emit("status://changed", ());
        }
        Ok(v)
    })
    .await
}

// ------------------------------------------------------------------ threats

#[tauri::command]
pub async fn list_threats(app: AppHandle) -> CmdResult<Vec<ThreatEntry>> {
    blocking(app, |app| {
        let state = app.state::<AppState>();
        #[cfg(target_os = "android")]
        state.import_pending_threats();
        state.prune_threats();
        Ok(state.threats())
    })
    .await
}

/// Applies `action` ("quarantine", "delete", "ignore", "allow", "uninstall")
/// to the given threats.
#[tauri::command]
pub async fn resolve_threats(app: AppHandle, ids: Vec<String>, action: String) -> CmdResult<Vec<ActionResult>> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let mut results = Vec::new();
        let mut done = Vec::new();
        for id in ids {
            let Some(t) = state.take_threat(&id) else {
                results.push(ActionResult { id, ok: false, error: Some("not found".into()), path: None });
                continue;
            };
            let path = Path::new(&t.verdict.path);
            let outcome: Result<(), String> = match action.as_str() {
                "quarantine" => {
                    if t.package_name.is_some() {
                        Err("installed apps must be uninstalled".into())
                    } else {
                        #[cfg(target_os = "windows")]
                        let added = state.quarantine.add_with_remove_fallback(
                            path,
                            t.verdict.threat_name().unwrap_or("Unknown"),
                            |source, sha256, removal_error| {
                                if removal_error.kind() != std::io::ErrorKind::PermissionDenied
                                    && removal_error.raw_os_error() != Some(5)
                                {
                                    return Err(seccom_engine::Error::Quarantine(format!(
                                        "could not isolate the original file after retrying; close any app using it and try again: {removal_error}"
                                    )));
                                }
                                crate::elevation::remove_with_uac(source, sha256).map_err(|error| {
                                    seccom_engine::Error::Quarantine(format!(
                                        "could not isolate the original file with Administrator permission: {error}"
                                    ))
                                })
                            },
                        );
                        #[cfg(not(target_os = "windows"))]
                        let added = state.quarantine.add(path, t.verdict.threat_name().unwrap_or("Unknown"));

                        added
                            .map(|_| state.update_stats(|s| s.threats_neutralized += 1))
                            .map_err(|e| e.to_string())
                    }
                }
                "delete" => {
                    if t.package_name.is_some() {
                        Err("installed apps must be uninstalled".into())
                    } else {
                        std::fs::remove_file(path).map(|_| state.update_stats(|s| s.threats_neutralized += 1)).map_err(|e| e.to_string())
                    }
                }
                "ignore" => Ok(()),
                "allow" => {
                    let mut s = state.settings();
                    if let Some(h) = &t.verdict.sha256
                        && !s.allowed_hashes.contains(h)
                    {
                        s.allowed_hashes.push(h.clone());
                    }
                    state.save_settings(s).map(|_| ())
                }
                "uninstall" => uninstall(&app, t.package_name.as_deref()),
                other => Err(format!("unknown action {other}")),
            };
            match outcome {
                Ok(()) => {
                    done.push(id.clone());
                    results.push(ActionResult { id, ok: true, error: None, path: None });
                }
                Err(e) => results.push(ActionResult { id, ok: false, error: Some(e), path: None }),
            }
        }
        state.remove_threats(&done);
        let _ = app.emit("status://changed", ());
        Ok(results)
    })
    .await
}

fn uninstall(app: &AppHandle, package: Option<&str>) -> Result<(), String> {
    let Some(pkg) = package else { return Err("not an installed app".into()) };
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_seccom_device::{PackageRequest, SeccomDeviceExt};
        return app.seccom_device().uninstall_app(PackageRequest { package_name: pkg.to_string() }).map_err(|e| e.to_string());
    }
    #[allow(unreachable_code)]
    {
        let _ = (app, pkg);
        Err("not supported on this platform".into())
    }
}

// --------------------------------------------------------------- quarantine

#[tauri::command]
pub async fn list_quarantine(app: AppHandle) -> CmdResult<Vec<QuarantineItem>> {
    blocking(app, |app| app.state::<AppState>().quarantine.list().map_err(|e| e.to_string())).await
}

#[tauri::command]
pub async fn restore_quarantine(app: AppHandle, ids: Vec<String>, allow: bool) -> CmdResult<Vec<ActionResult>> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let mut results = Vec::new();
        for id in ids {
            let item = state.quarantine.get(&id).ok();
            // Tell real-time protection *before* the file reappears, otherwise it
            // would be quarantined again right away.
            if let Some(item) = &item {
                if allow {
                    let mut s = state.settings();
                    if !s.allowed_hashes.contains(&item.sha256) {
                        s.allowed_hashes.push(item.sha256.clone());
                        let _ = state.save_settings(s);
                    }
                } else {
                    state.mark_restored(std::path::Path::new(&item.original_path), &item.sha256);
                }
            }
            match state.quarantine.restore(&id, None) {
                Ok(p) => {
                    if let (Some(item), false) = (&item, allow) {
                        // The file may have been restored under a new name.
                        state.mark_restored(&p, &item.sha256);
                    }
                    results.push(ActionResult { id, ok: true, error: None, path: Some(p.to_string_lossy().into_owned()) })
                }
                Err(e) => results.push(ActionResult { id, ok: false, error: Some(e.to_string()), path: None }),
            }
        }
        let _ = app.emit("status://changed", ());
        Ok(results)
    })
    .await
}

#[tauri::command]
pub async fn delete_quarantine(app: AppHandle, ids: Vec<String>) -> CmdResult<Vec<ActionResult>> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let results = ids
            .into_iter()
            .map(|id| match state.quarantine.delete(&id) {
                Ok(()) => ActionResult { id, ok: true, error: None, path: None },
                Err(e) => ActionResult { id, ok: false, error: Some(e.to_string()), path: None },
            })
            .collect();
        let _ = app.emit("status://changed", ());
        Ok(results)
    })
    .await
}

// ------------------------------------------------------------------ history

#[tauri::command]
pub fn get_history(app: AppHandle) -> Vec<ScanRecord> {
    app.state::<AppState>().history()
}

#[tauri::command]
pub fn clear_history(app: AppHandle) -> CmdResult<()> {
    app.state::<AppState>().clear_history()
}

/// Writes a scan report. Without `path` the report is saved into the
/// Documents (iOS) / Download (Android) / Downloads (desktop) folder.
#[tauri::command]
pub async fn export_report(app: AppHandle, id: String, format: String, path: Option<String>) -> CmdResult<String> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let record = state.history().into_iter().find(|r| r.id == id).ok_or("scan not found")?;
        let lang = crate::i18n::lang(&state);
        let (content, ext) = match format.as_str() {
            "html" => (crate::report::html(&record, lang), "html"),
            _ => (serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?, "json"),
        };
        let target = match path {
            Some(p) => PathBuf::from(p),
            None => default_export_dir(&app).join(format!("seccorp-report-{}.{ext}", &record.id[..8.min(record.id.len())])),
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&target, content).map_err(|e| e.to_string())?;
        Ok(target.to_string_lossy().into_owned())
    })
    .await
}

fn default_export_dir(app: &AppHandle) -> PathBuf {
    if cfg!(target_os = "android") {
        return PathBuf::from("/storage/emulated/0/Download");
    }
    if cfg!(target_os = "ios") {
        return app.path().document_dir().unwrap_or_else(|_| app.state::<AppState>().paths.data.clone());
    }
    app.path().download_dir().unwrap_or_else(|_| app.state::<AppState>().paths.data.clone())
}

// ---------------------------------------------------------------- real time

#[tauri::command]
pub async fn get_realtime_status(app: AppHandle) -> CmdResult<RealtimeStatus> {
    blocking(app, |app| Ok(crate::realtime::status(&app))).await
}

// ---------------------------------------------------------- network guard

#[tauri::command]
pub async fn get_network_status(app: AppHandle) -> CmdResult<NetworkStatus> {
    blocking(app, |app| Ok(crate::network::status(&app))).await
}

#[tauri::command]
pub async fn scan_network_now(app: AppHandle) -> CmdResult<NetworkStatus> {
    blocking(app, |app| crate::network::scan_now(&app)).await
}

#[tauri::command]
pub async fn set_network_protection(app: AppHandle, enabled: bool) -> CmdResult<NetworkStatus> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let mut settings = state.settings();
        settings.network_monitor_enabled = enabled;
        state.save_settings(settings)?;
        crate::network::apply(&app);
        let _ = app.emit("status://changed", ());
        Ok(crate::network::status(&app))
    })
    .await
}

#[tauri::command]
pub fn dismiss_network_alert(app: AppHandle, id: String) -> NetworkStatus {
    crate::network::dismiss_alert(&app, &id)
}

#[tauri::command]
pub async fn set_realtime(app: AppHandle, enabled: bool) -> CmdResult<RealtimeStatus> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        let mut s = state.settings();
        s.realtime_enabled = enabled;
        state.save_settings(s)?;
        crate::realtime::apply(&app);
        Ok(crate::realtime::status(&app))
    })
    .await
}

#[tauri::command]
pub fn get_realtime_events(app: AppHandle) -> Vec<RealtimeEvent> {
    app.state::<AppState>().realtime.events()
}

#[tauri::command]
pub fn get_default_watch_paths(app: AppHandle) -> Vec<String> {
    let state = app.state::<AppState>();
    platform::default_watch_paths(&app, &state).into_iter().map(|p| p.to_string_lossy().into_owned()).collect()
}

// --------------------------------------------------------------- signatures

#[tauri::command]
pub fn get_db_info(app: AppHandle) -> DbInfo {
    app.state::<AppState>().engine.db_info()
}

#[tauri::command]
pub async fn check_updates(app: AppHandle) -> CmdResult<UpdateCheck> {
    blocking(app, |app| crate::updater::check(&app)).await
}

#[tauri::command]
pub async fn apply_update(app: AppHandle) -> CmdResult<DbInfo> {
    blocking(app, |app| crate::updater::apply(&app)).await
}

const IMPORT_EXTENSIONS: &[&str] = &[
    "yar", "yara", "hdb", "hsb", "hdu", "hsu", "ndb", "ndu", "fp", "sfp", "ign", "ign2", "cvd", "cld", "cud", "txt", "csv", "sha256",
    "md5", "sha1", "hashes", "lst",
];

#[tauri::command]
pub async fn import_signatures(app: AppHandle, paths: Vec<String>) -> CmdResult<DbInfo> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        for p in &paths {
            let src = Path::new(p);
            let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).ok_or("invalid file")?;
            let ext = seccom_engine::util::extension(&name);
            if !IMPORT_EXTENSIONS.contains(&ext.as_str()) {
                return Err(format!("unsupported signature file: {name}"));
            }
            let safe: String = name.chars().map(|c| if c.is_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
            std::fs::copy(src, state.paths.db_user.join(safe)).map_err(|e| e.to_string())?;
        }
        state.reload_db();
        let info = state.engine.db_info();
        let _ = app.emit("db://reloaded", &info);
        Ok(info)
    })
    .await
}

#[tauri::command]
pub fn list_user_signatures(app: AppHandle) -> Vec<UserSignatureFile> {
    let state = app.state::<AppState>();
    let mut v: Vec<UserSignatureFile> = std::fs::read_dir(&state.paths.db_user)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let m = e.metadata().ok()?;
                    m.is_file().then(|| UserSignatureFile {
                        name: e.file_name().to_string_lossy().into_owned(),
                        size: m.len(),
                        modified: m
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

#[tauri::command]
pub async fn remove_user_signature(app: AppHandle, name: String) -> CmdResult<DbInfo> {
    blocking(app, move |app| {
        let state = app.state::<AppState>();
        if name.contains('/') || name.contains('\\') || name.starts_with('.') {
            return Err("invalid name".into());
        }
        std::fs::remove_file(state.paths.db_user.join(&name)).map_err(|e| e.to_string())?;
        state.reload_db();
        let info = state.engine.db_info();
        let _ = app.emit("db://reloaded", &info);
        Ok(info)
    })
    .await
}

#[tauri::command]
pub async fn reload_signatures(app: AppHandle) -> CmdResult<DbInfo> {
    blocking(app, |app| {
        let state = app.state::<AppState>();
        state.reload_db();
        let info = state.engine.db_info();
        let _ = app.emit("db://reloaded", &info);
        Ok(info)
    })
    .await
}

// ----------------------------------------------------------------- platform

#[tauri::command]
pub async fn list_startup_items(app: AppHandle) -> CmdResult<Vec<StartupItem>> {
    blocking(app, |_| Ok(platform::startup_items())).await
}

#[tauri::command]
pub fn browse_roots(app: AppHandle) -> Vec<DirEntry> {
    platform::browse_roots(&app)
}

#[tauri::command]
pub async fn list_dir(app: AppHandle, path: String) -> CmdResult<DirListing> {
    blocking(app, move |_| platform::list_dir(&path)).await
}

#[tauri::command]
pub fn needs_full_disk_access(app: AppHandle) -> bool {
    platform::needs_full_disk_access(&app)
}

#[tauri::command]
pub fn open_privacy_settings() -> CmdResult<()> {
    platform::open_privacy_settings()
}

/// Relaunches SecCorp (macOS applies a new Full Disk Access grant only after a restart).
#[tauri::command]
pub fn restart_app(app: AppHandle) {
    // Free the single-instance lock first so the new process does not hand over
    // to this one while it is still shutting down.
    #[cfg(desktop)]
    tauri_plugin_single_instance::destroy(&app);
    app.restart();
}

#[tauri::command]
pub fn reveal_path(app: AppHandle, path: String) -> CmdResult<()> {
    #[cfg(desktop)]
    {
        use tauri_plugin_opener::OpenerExt;
        return app.opener().reveal_item_in_dir(&path).map_err(|e| e.to_string());
    }
    #[allow(unreachable_code)]
    {
        let _ = (app, path);
        Err("not supported on this platform".into())
    }
}

#[tauri::command]
pub async fn get_device_security(app: AppHandle) -> CmdResult<tauri_plugin_seccom_device::DeviceSecurity> {
    blocking(app, |app| {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        app.seccom_device().device_security().map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn get_storage_access(app: AppHandle) -> CmdResult<tauri_plugin_seccom_device::StorageAccess> {
    blocking(app, |app| {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        app.seccom_device().get_storage_access().map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn request_storage_access(app: AppHandle) -> CmdResult<()> {
    blocking(app, |app| {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        app.seccom_device().request_storage_access().map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn pick_file_native(app: AppHandle) -> CmdResult<tauri_plugin_seccom_device::PickedFile> {
    blocking(app, |app| {
        use tauri_plugin_seccom_device::SeccomDeviceExt;
        app.seccom_device().pick_file().map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub fn get_app_report(app: AppHandle) -> Vec<AppReport> {
    #[cfg(target_os = "android")]
    {
        return platform::android::load_app_report(&app.state::<AppState>().paths);
    }
    #[allow(unreachable_code)]
    {
        let _ = app;
        Vec::new()
    }
}

#[tauri::command]
pub async fn uninstall_app(app: AppHandle, package_name: String) -> CmdResult<()> {
    blocking(app, move |app| uninstall(&app, Some(&package_name))).await
}

#[tauri::command]
pub async fn open_app_settings(app: AppHandle, package_name: String) -> CmdResult<()> {
    blocking(app, move |app| {
        #[cfg(target_os = "android")]
        {
            use tauri_plugin_seccom_device::{PackageRequest, SeccomDeviceExt};
            return app.seccom_device().open_app_settings(PackageRequest { package_name }).map_err(|e| e.to_string());
        }
        #[allow(unreachable_code)]
        {
            let _ = (app, package_name);
            Err("not supported on this platform".into())
        }
    })
    .await
}
