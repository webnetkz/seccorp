//! SecCorp application (Tauri 2): wires the scanning engine to the UI and to
//! each platform (Windows, macOS, Android, iOS).

mod commands;
mod i18n;
#[cfg(desktop)]
mod media;
mod model;
mod network;
mod notify;
mod platform;
mod realtime;
mod report;
mod scan;
#[cfg(desktop)]
mod scheduler;
mod settings;
mod state;
mod tray;
mod updater;

use state::AppState;
use tauri::{Emitter, Manager};

/// Prefer the Store package's bundled WebView2 runtime when one is present.
/// This must run before Tauri creates the Windows webview.
#[cfg(target_os = "windows")]
fn configure_bundled_webview2_runtime() {
    use std::os::windows::ffi::OsStrExt;

    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(app_dir) = executable.parent() else {
        return;
    };
    let runtime_dir = app_dir.join("WebView2Runtime");
    if !runtime_dir.join("msedgewebview2.exe").is_file() {
        return;
    }

    let name: Vec<u16> = "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER".encode_utf16().chain(Some(0)).collect();
    let value: Vec<u16> = runtime_dir.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        windows_sys::Win32::System::Environment::SetEnvironmentVariableW(name.as_ptr(), value.as_ptr());
    }
}

/// Arguments passed when the app starts at login (start hidden in the tray).
#[cfg(desktop)]
const AUTOSTART_ARG: &str = "--minimized";

fn init_logging() {
    // Tauri plugins log through the `log` facade; keep the default logger quiet
    // in release builds.
    #[cfg(debug_assertions)]
    {
        struct Stderr;
        impl log::Log for Stderr {
            fn enabled(&self, m: &log::Metadata) -> bool {
                m.level() <= log::Level::Info
            }
            fn log(&self, r: &log::Record) {
                if self.enabled(r.metadata()) {
                    eprintln!("[{}] {}: {}", r.level(), r.target(), r.args());
                }
            }
            fn flush(&self) {}
        }
        static LOGGER: Stderr = Stderr;
        let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Info));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "windows")]
    configure_bundled_webview2_runtime();
    init_logging();
    #[cfg_attr(mobile, allow(unused_mut))]
    let mut builder = tauri::Builder::default();

    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                tray::show_main_window(app);
            }))
            .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec![AUTOSTART_ARG])));
    }

    builder
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_seccom_device::init())
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::get_dashboard,
            commands::get_settings,
            commands::save_settings,
            commands::next_scheduled_scan,
            commands::start_scan,
            commands::pause_scan,
            commands::resume_scan,
            commands::cancel_scan,
            commands::get_scan_state,
            commands::scan_file_now,
            commands::list_threats,
            commands::resolve_threats,
            commands::list_quarantine,
            commands::restore_quarantine,
            commands::delete_quarantine,
            commands::get_history,
            commands::clear_history,
            commands::export_report,
            commands::get_realtime_status,
            commands::set_realtime,
            commands::get_realtime_events,
            commands::get_network_status,
            commands::scan_network_now,
            commands::set_network_protection,
            commands::dismiss_network_alert,
            commands::get_default_watch_paths,
            commands::get_db_info,
            commands::check_updates,
            commands::apply_update,
            commands::import_signatures,
            commands::list_user_signatures,
            commands::remove_user_signature,
            commands::reload_signatures,
            commands::list_startup_items,
            commands::browse_roots,
            commands::list_dir,
            commands::needs_full_disk_access,
            commands::open_privacy_settings,
            commands::restart_app,
            commands::reveal_path,
            commands::get_device_security,
            commands::get_storage_access,
            commands::request_storage_access,
            commands::pick_file_native,
            commands::get_app_report,
            commands::uninstall_app,
            commands::open_app_settings,
        ])
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let mut state = AppState::new(data_dir).map_err(Box::<dyn std::error::Error>::from)?;
            let bundled_db = app.path().resource_dir()?.join("databases/bundled");
            if bundled_db.exists() {
                state.paths.db_bundled = Some(bundled_db);
            }
            app.manage(state);
            let handle = app.handle().clone();

            // Load the full signature database without blocking the UI, then
            // start protection.
            std::thread::Builder::new().name("seccom-init".into()).spawn({
                let handle = handle.clone();
                move || {
                    let state = handle.state::<AppState>();
                    state.reload_db();
                    let _ = handle.emit("db://reloaded", state.engine.db_info());
                    realtime::apply(&handle);
                    network::apply(&handle);
                }
            })?;
            updater::spawn_auto_update(&handle);

            #[cfg(desktop)]
            {
                if !cfg!(feature = "mac-app-store") {
                    tray::create(&handle)?;
                    scheduler::spawn(&handle);
                    media::spawn(&handle);
                }
                let state = handle.state::<AppState>();
                let settings = state.settings();
                if !cfg!(feature = "mac-app-store") {
                    use tauri_plugin_autostart::ManagerExt;
                    let enabled = handle.autolaunch().is_enabled().unwrap_or(false);
                    if enabled != settings.launch_at_login {
                        let _ = if settings.launch_at_login { handle.autolaunch().enable() } else { handle.autolaunch().disable() };
                    }
                }
                let minimized = std::env::args().any(|a| a == AUTOSTART_ARG) && settings.start_minimized;
                if let Some(w) = handle.get_webview_window("main") {
                    if minimized {
                        let _ = w.hide();
                    } else {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let state = app.state::<AppState>();
                if !cfg!(feature = "mac-app-store") && state.settings().close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            #[cfg(mobile)]
            let _ = (window, event);
        })
        .build(tauri::generate_context!())
        .expect("error while building SecCorp")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                tray::show_main_window(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
