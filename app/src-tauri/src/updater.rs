//! Signature database updates.
//!
//! SecCorp prefers its Ed25519-signed feed when one is configured. Desktop
//! builds can otherwise use an installed FreshClam to maintain the official
//! ClamAV databases that the engine discovers in the standard system paths.

use crate::model::{UpdateCheck, UpdateProgress};
use crate::state::AppState;
use seccom_engine::util::now_unix;
use tauri::{AppHandle, Emitter, Manager, Runtime};

/// Hex-encoded Ed25519 public key that signs database bundles.
pub const UPDATE_PUBKEY: Option<&str> = option_env!("SECCOM_UPDATE_PUBKEY");

#[cfg(feature = "online-update")]
const MAX_INDEX: u64 = 1 << 20;
#[cfg(feature = "online-update")]
const MAX_BUNDLE: u64 = 2 << 30;

fn signed_configured(state: &AppState) -> bool {
    UPDATE_PUBKEY.is_some_and(|k| !k.trim().is_empty()) && cfg!(feature = "online-update") && !state.settings().update_url.is_empty()
}

#[cfg(desktop)]
fn bundled_freshclam_executable() -> Option<std::path::PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let executable = std::env::current_exe().ok()?.parent()?.join("clamav").join("freshclam.exe");
    executable.is_file().then_some(executable)
}

#[cfg(desktop)]
fn freshclam_executable() -> Option<std::path::PathBuf> {
    if let Some(executable) = bundled_freshclam_executable() {
        return Some(executable);
    }
    let executable = if cfg!(windows) { "freshclam.exe" } else { "freshclam" };
    let mut candidates = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).map(|dir| dir.join(executable)).collect::<Vec<_>>())
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        candidates.extend(["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam"].into_iter().map(Into::into));
    } else if cfg!(target_os = "linux") {
        candidates.extend(["/usr/bin/freshclam", "/usr/local/bin/freshclam"].into_iter().map(Into::into));
    } else if cfg!(windows)
        && let Some(program_files) = std::env::var_os("ProgramFiles")
    {
        candidates.push(std::path::PathBuf::from(program_files).join("ClamAV").join("freshclam.exe"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

#[cfg(not(desktop))]
fn freshclam_executable() -> Option<std::path::PathBuf> {
    None
}

pub fn mode(state: &AppState) -> &'static str {
    if signed_configured(state) {
        "signed"
    } else if freshclam_executable().is_some() {
        "freshclam"
    } else {
        "none"
    }
}

pub fn configured(state: &AppState) -> bool {
    mode(state) != "none"
}

fn emit<R: Runtime>(app: &AppHandle<R>, stage: &str, downloaded: u64, total: u64, message: Option<String>) {
    let _ = app.emit("update://progress", UpdateProgress { stage: stage.into(), downloaded, total, message });
}

#[cfg(feature = "online-update")]
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(600)))
        .user_agent(concat!("SecCorp/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

#[cfg(feature = "online-update")]
fn fetch_index(url: &str) -> Result<seccom_engine::update::UpdateIndex, String> {
    if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
        return Err("update URL must use HTTPS".into());
    }
    let mut resp = agent().get(url).call().map_err(|e| format!("cannot download update.json: {e}"))?;
    let text = resp.body_mut().with_config().limit(MAX_INDEX).read_to_string().map_err(|e| format!("cannot read update.json: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid update.json: {e}"))
}

/// Checks whether a newer database is available.
pub fn check<R: Runtime>(app: &AppHandle<R>) -> Result<UpdateCheck, String> {
    let state = app.state::<AppState>();
    let current = state.engine.db_info().version;
    if !configured(&state) {
        return Ok(UpdateCheck {
            configured: false,
            available: false,
            current,
            latest: None,
            released: None,
            size: None,
            notes: None,
            checked_at: now_unix(),
        });
    }
    #[cfg(feature = "online-update")]
    if signed_configured(&state) {
        let url = state.settings().update_url;
        let index = fetch_index(&url)?;
        let available = current.starts_with("builtin-")
            || current.starts_with("clamav-")
            || seccom_engine::update::compare_versions(&index.version, &current) == std::cmp::Ordering::Greater;
        let check = UpdateCheck {
            configured: true,
            available,
            current,
            latest: Some(index.version),
            released: Some(index.released),
            size: Some(index.size),
            notes: index.notes,
            checked_at: now_unix(),
        };
        *state.last_update_check.lock().unwrap_or_else(|e| e.into_inner()) = Some(check.clone());
        return Ok(check);
    }

    if freshclam_executable().is_some() {
        let _guard = state.update_lock.try_lock().map_err(|_| "an update is already running".to_string())?;
        let info = refresh_freshclam(app, &state)?;
        let check = UpdateCheck {
            configured: true,
            available: false,
            current: info.version.clone(),
            latest: Some(info.version),
            released: (info.released > 0).then_some(info.released),
            size: None,
            notes: Some("ClamAV FreshClam".into()),
            checked_at: now_unix(),
        };
        *state.last_update_check.lock().unwrap_or_else(|e| e.into_inner()) = Some(check.clone());
        return Ok(check);
    }

    unreachable!()
}

/// Downloads, verifies and installs the latest database.
pub fn apply<R: Runtime>(app: &AppHandle<R>) -> Result<seccom_engine::DbInfo, String> {
    let state = app.state::<AppState>();
    if !configured(&state) {
        return Err("updates are not configured in this build".into());
    }
    let _guard = state.update_lock.try_lock().map_err(|_| "an update is already running".to_string())?;
    let result = if signed_configured(&state) { apply_inner(app, &state) } else { refresh_freshclam(app, &state) };
    match &result {
        Ok(_) => emit(app, "done", 0, 0, None),
        Err(e) => emit(app, "error", 0, 0, Some(e.clone())),
    }
    result
}

fn refresh_freshclam<R: Runtime>(app: &AppHandle<R>, state: &AppState) -> Result<seccom_engine::DbInfo, String> {
    let executable = freshclam_executable().ok_or_else(|| "FreshClam is not installed".to_string())?;
    emit(app, "checking", 0, 0, None);
    let bundled = bundled_freshclam_executable().as_deref() == Some(executable.as_path());
    let mut command = std::process::Command::new(&executable);
    command.args(["--stdout", "--quiet", "--no-warnings"]);
    if bundled {
        // Keep Store updates inside SecCorp's writable app-data directory.
        // FreshClam verifies Cisco's signed databases before it writes them.
        std::fs::create_dir_all(&state.paths.db_freshclam).map_err(|e| format!("cannot create database directory: {e}"))?;
        let config = state.paths.data.join("freshclam.conf");
        std::fs::write(&config, "DatabaseMirror database.clamav.net\n")
            .map_err(|e| format!("cannot write FreshClam configuration: {e}"))?;
        let certs = executable.parent().unwrap_or_else(|| std::path::Path::new(".")).join("certs");
        command
            .arg(format!("--config-file={}", config.display()))
            .arg(format!("--datadir={}", state.paths.db_freshclam.display()))
            .arg(format!("--cvdcertsdir={}", certs.display()));
    }
    let output = command.output().map_err(|e| format!("cannot start {}: {e}", executable.display()))?;
    if !output.status.success() {
        let mut message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if message.is_empty() {
            message = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
        if message.len() > 4000 {
            message.truncate(4000);
        }
        return Err(if message.is_empty() { format!("FreshClam exited with {}", output.status) } else { message });
    }
    emit(app, "verifying", 0, 0, None);
    state.reload_db();
    let info = state.engine.db_info();
    let no_supported_signatures = bundled && !info.sources.iter().any(|source| source.kind == "clamav-cvd" && source.signatures > 0);
    let _ = app.emit("db://reloaded", &info);
    let _ = app.emit("status://changed", ());
    if no_supported_signatures {
        return Err("FreshClam updated its database, but SecCorp could not load any supported ClamAV signatures. Some ClamAV formats are not supported by this engine.".into());
    }
    Ok(info)
}

#[cfg(feature = "online-update")]
fn apply_inner<R: Runtime>(app: &AppHandle<R>, state: &AppState) -> Result<seccom_engine::DbInfo, String> {
    use std::io::Read;
    emit(app, "checking", 0, 0, None);
    let url = state.settings().update_url;
    let index = fetch_index(&url)?;
    if let Some(min) = &index.min_engine
        && seccom_engine::update::compare_versions(seccom_engine::ENGINE_VERSION, min) == std::cmp::Ordering::Less
    {
        return Err(format!("this database requires a newer SecCorp version ({min})"));
    }
    let current = state.engine.db_info().version;
    let current_cmp = (!current.starts_with("builtin-") && !current.starts_with("clamav-")).then_some(current.as_str());
    if let Some(cur) = current_cmp
        && seccom_engine::update::compare_versions(&index.version, cur) != std::cmp::Ordering::Greater
    {
        return Ok(state.engine.db_info());
    }
    if index.size > MAX_BUNDLE {
        return Err("update bundle is too large".into());
    }
    let key = seccom_engine::update::parse_public_key(UPDATE_PUBKEY.unwrap_or_default()).map_err(|e| e.to_string())?;
    let bundle_url = seccom_engine::update::resolve_bundle_url(&url, &index.url);
    let mut resp = agent().get(&bundle_url).call().map_err(|e| format!("download failed: {e}"))?;
    let mut reader = resp.body_mut().with_config().limit(index.size + 1).reader();
    let mut bundle = Vec::with_capacity(index.size as usize);
    let mut buf = vec![0u8; 256 * 1024];
    let mut last_emit = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("download failed: {e}"))?;
        if n == 0 {
            break;
        }
        bundle.extend_from_slice(&buf[..n]);
        if bundle.len() as u64 > index.size {
            return Err("download is larger than announced".into());
        }
        if bundle.len() as u64 - last_emit >= 512 * 1024 {
            last_emit = bundle.len() as u64;
            emit(app, "downloading", last_emit, index.size, None);
        }
    }
    emit(app, "verifying", bundle.len() as u64, index.size, None);
    seccom_engine::update::verify_bundle(&bundle, &index, &key).map_err(|e| e.to_string())?;
    emit(app, "installing", bundle.len() as u64, index.size, None);
    seccom_engine::update::install_bundle(&bundle, &state.paths.db_root, current_cmp).map_err(|e| e.to_string())?;
    state.reload_db();
    let info = state.engine.db_info();
    let _ = app.emit("db://reloaded", &info);
    let _ = app.emit("status://changed", ());
    let lang = crate::i18n::lang(state);
    crate::notify::notify(app, crate::i18n::t(lang, "db_updated"), &info.version);
    Ok(info)
}

#[cfg(not(feature = "online-update"))]
fn apply_inner<R: Runtime>(_app: &AppHandle<R>, _state: &AppState) -> Result<seccom_engine::DbInfo, String> {
    Err("online updates are disabled in this build".into())
}

/// Background auto-update loop (every 6 hours).
pub fn spawn_auto_update<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let _ = std::thread::Builder::new().name("seccom-updater".into()).spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        loop {
            let state = app.state::<AppState>();
            if state.settings().auto_update && configured(&state) {
                if mode(&state) == "freshclam" {
                    if let Err(e) = apply(&app) {
                        log::warn!("automatic FreshClam update failed: {e}");
                    }
                } else {
                    match check(&app) {
                        Ok(c) if c.available => {
                            if let Err(e) = apply(&app) {
                                log::warn!("automatic update failed: {e}");
                            }
                        }
                        Ok(_) => {}
                        Err(e) => log::info!("update check failed: {e}"),
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(6 * 3600));
        }
    });
}
