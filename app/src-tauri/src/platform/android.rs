//! Android specifics: shared storage locations, installed-app scanning and
//! the JNI bridge used by the background protection service.

use crate::model::{AppReport, StartupItem, ThreatEntry};
use crate::state::{AppState, Paths, load_json, save_json, threat_entry};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jstring};
use seccom_engine::analyzers::apk;
use seccom_engine::util::now_unix;
use seccom_engine::{Engine, FileVerdict, ScanControl, ScanOptions, Verdict};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{AppHandle, Emitter, Runtime};
use tauri_plugin_seccom_device::{ListAppsRequest, SeccomDeviceExt};

/// Shared storage of the primary user.
fn storage() -> PathBuf {
    PathBuf::from("/storage/emulated/0")
}

/// App stores that review submitted apps.
const TRUSTED_INSTALLERS: &[&str] = &[
    "com.android.vending",
    "com.google.android.feedback",
    "com.sec.android.app.samsungapps",
    "com.huawei.appmarket",
    "com.xiaomi.market",
    "com.heytap.market",
    "com.oppo.market",
    "com.vivo.appstore",
    "com.amazon.venezia",
    "ru.vk.store",
];

pub fn quick_dirs(_home: Option<&Path>) -> Vec<PathBuf> {
    let s = storage();
    vec![
        s.join("Download"),
        s.join("Documents"),
        s.join("Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"),
        s.join("Android/media/org.telegram.messenger/Telegram/Telegram Documents"),
        s.join("Telegram/Telegram Documents"),
        s.join("Bluetooth"),
    ]
}

pub fn full_roots(_home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = vec![storage()];
    // Removable SD cards are mounted as /storage/XXXX-XXXX.
    if let Ok(rd) = std::fs::read_dir("/storage") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name != "emulated" && name != "self" && e.path().is_dir() {
                roots.push(e.path());
            }
        }
    }
    roots
}

pub fn watch_dirs(_home: Option<&Path>) -> Vec<PathBuf> {
    vec![storage().join("Download")]
}

pub fn exclusions() -> Vec<String> {
    vec![storage().join("Android/data").to_string_lossy().into_owned(), storage().join("Android/obb").to_string_lossy().into_owned()]
}

pub fn browse_roots(home: Option<&Path>) -> Vec<PathBuf> {
    full_roots(home)
}

pub fn startup_items() -> Vec<StartupItem> {
    Vec::new()
}

pub fn signature_dirs() -> Vec<PathBuf> {
    Vec::new()
}

/// Scans installed apps; returns the verdicts of risky ones. Also writes the
/// report shown on the "Apps" screen.
pub fn scan_installed_apps<R: Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    opts: &ScanOptions,
    control: &ScanControl,
    found: &Arc<Mutex<Vec<ThreatEntry>>>,
) -> Vec<FileVerdict> {
    let apps = match app.seccom_device().list_installed_apps(ListAppsRequest { include_system: false, with_icons: true }) {
        Ok(a) => a.apps,
        Err(e) => {
            log::warn!("cannot list installed apps: {e}");
            return Vec::new();
        }
    };
    let settings = state.settings();
    let mut reports = Vec::with_capacity(apps.len());
    let mut threats = Vec::new();
    for a in apps {
        if control.is_cancelled() {
            break;
        }
        control.wait_if_paused();
        let mut verdict = state.engine.scan_file(Path::new(&a.source_dir), opts);
        for split in &a.split_source_dirs {
            let v = state.engine.scan_file(Path::new(split), opts);
            if v.verdict > verdict.verdict {
                verdict = v;
            }
        }
        let risk = std::fs::read(&a.source_dir).ok().and_then(|bytes| apk::inspect(&bytes));
        let trusted = TRUSTED_INSTALLERS.contains(&a.installer.as_str());
        let mut reasons = risk.as_ref().map(|r| r.reasons.clone()).unwrap_or_default();
        let mut score = risk.as_ref().map(|r| r.score).unwrap_or(0);
        if !trusted && !a.is_system {
            reasons.push("unknown_source".into());
            score += 10;
        }
        if verdict.is_threat() && !settings.is_allowed(verdict.sha256.as_deref()) {
            let mut entry = threat_entry(verdict.clone(), "apps");
            entry.package_name = Some(a.package_name.clone());
            entry.app_label = Some(a.label.clone());
            if let Ok(mut f) = found.lock() {
                f.push(entry.clone());
            }
            state.add_threat(entry.clone());
            let _ = app.emit("scan://threat", &entry);
            threats.push(verdict.clone());
        }
        reports.push(AppReport {
            package_name: a.package_name,
            label: a.label,
            version_name: a.version_name,
            installer: a.installer,
            trusted_source: trusted,
            is_system: a.is_system,
            icon: a.icon,
            verdict: verdict.verdict,
            threat_name: verdict.threat_name().map(str::to_string),
            risk_score: score.min(100),
            risk_reasons: reasons,
            permissions_count: a.permissions.len(),
            last_update_time: a.last_update_time,
        });
    }
    reports.sort_by(|x, y| y.verdict.cmp(&x.verdict).then(y.risk_score.cmp(&x.risk_score)).then(x.label.cmp(&y.label)));
    if let Err(e) = save_json(&state.paths.apps_report, &reports) {
        log::warn!("cannot save apps report: {e}");
    }
    threats
}

pub fn load_app_report(paths: &Paths) -> Vec<AppReport> {
    load_json(&paths.apps_report)
}

// ---------------------------------------------------------------------------
// JNI bridge for the background service (com.webnetkz.seccom.device.NativeBridge)
// ---------------------------------------------------------------------------

struct ServiceContext {
    engine: Arc<Engine>,
    paths: Paths,
    opts: ScanOptions,
    allowed: Vec<String>,
}

static SERVICE: OnceLock<ServiceContext> = OnceLock::new();

fn service_init(data_dir: &str) {
    SERVICE.get_or_init(|| {
        let paths = Paths::new(PathBuf::from(data_dir));
        let engine = crate::state::GLOBAL_ENGINE.get().cloned().unwrap_or_else(|| {
            // The UI is not running: load the database ourselves.
            Arc::new(Engine::new(crate::state::load_signature_db(&paths)))
        });
        let settings: crate::settings::Settings = load_json(&paths.settings);
        let opts = settings.scan_options(&crate::platform::default_exclusions(&paths));
        ServiceContext { engine, opts, allowed: settings.allowed_hashes.clone(), paths }
    });
}

fn service_scan(path: &str, source: &str) -> String {
    let Some(ctx) = SERVICE.get() else { return "{}".into() };
    let v = ctx.engine.scan_file(Path::new(path), &ctx.opts);
    let allowed = v.sha256.as_deref().is_some_and(|h| ctx.allowed.iter().any(|a| a.eq_ignore_ascii_case(h)));
    let threat = v.is_threat() && !allowed;
    if threat {
        let mut entry = threat_entry(v.clone(), "service");
        if let Some(pkg) = source.strip_prefix("install:") {
            entry.package_name = Some(pkg.to_string());
        }
        entry.detected_at = now_unix();
        if let Ok(line) = serde_json::to_string(&entry) {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&ctx.paths.pending_threats) {
                let _ = writeln!(f, "{line}");
            }
        }
    }
    serde_json::json!({
        "threat": threat,
        "name": v.threat_name().unwrap_or(""),
        "verdict": match v.verdict { Verdict::Clean => "clean", Verdict::Suspicious => "suspicious", Verdict::Malicious => "malicious" },
        "path": v.path,
    })
    .to_string()
}

/// `NativeBridge.nativeInit(dataDir: String): Boolean`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_webnetkz_seccom_device_NativeBridge_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    let dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    match std::panic::catch_unwind(|| service_init(&dir)) {
        Ok(()) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

/// `NativeBridge.nativeScanFile(path: String, source: String): String`
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_webnetkz_seccom_device_NativeBridge_nativeScanFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    source: JString,
) -> jstring {
    let path: String = env.get_string(&path).map(Into::into).unwrap_or_default();
    let source: String = env.get_string(&source).map(Into::into).unwrap_or_default();
    let result = std::panic::catch_unwind(|| service_scan(&path, &source)).unwrap_or_else(|_| "{}".into());
    env.new_string(result).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}
