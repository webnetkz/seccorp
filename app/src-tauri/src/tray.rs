//! System tray icon and menu (desktop).

#[cfg(desktop)]
mod imp {
    use crate::i18n::t;
    use crate::state::AppState;
    use std::sync::Mutex;
    use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::{AppHandle, Manager, Runtime};

    pub struct TrayItems<R: Runtime> {
        open: MenuItem<R>,
        quick: MenuItem<R>,
        realtime: CheckMenuItem<R>,
        quit: MenuItem<R>,
    }

    pub struct TrayState<R: Runtime>(pub Mutex<Option<TrayItems<R>>>);

    pub fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
        }
    }

    pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
        let state = app.state::<AppState>();
        let lang = crate::i18n::lang(&state);
        let realtime_on = state.settings().realtime_enabled;
        let open = MenuItem::with_id(app, "open", t(lang, "tray_open"), true, None::<&str>)?;
        let quick = MenuItem::with_id(app, "quick", t(lang, "tray_quick_scan"), true, None::<&str>)?;
        let realtime = CheckMenuItem::with_id(app, "realtime", t(lang, "tray_realtime"), true, realtime_on, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", t(lang, "tray_quit"), true, None::<&str>)?;
        let sep1 = PredefinedMenuItem::separator(app)?;
        let sep2 = PredefinedMenuItem::separator(app)?;
        let menu = Menu::with_items(app, &[&open, &quick, &sep1, &realtime, &sep2, &quit])?;

        let mut builder = TrayIconBuilder::with_id("main")
            .tooltip(t(lang, "tray_tooltip"))
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "open" => show_main_window(app),
                "quick" => {
                    show_main_window(app);
                    let _ = crate::scan::start(app, "quick", Vec::new(), "tray");
                }
                "realtime" => {
                    let state = app.state::<AppState>();
                    let mut s = state.settings();
                    s.realtime_enabled = !s.realtime_enabled;
                    if state.save_settings(s).is_ok() {
                        crate::realtime::apply(app);
                    }
                    refresh(app);
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                    show_main_window(tray.app_handle());
                }
            });
        if let Some(icon) = app.default_window_icon() {
            builder = builder.icon(icon.clone());
        }
        builder.build(app)?;
        app.manage(TrayState(Mutex::new(Some(TrayItems { open, quick, realtime, quit }))));
        Ok(())
    }

    /// Updates labels and the real-time check mark.
    pub fn refresh<R: Runtime>(app: &AppHandle<R>) {
        let Some(tray) = app.try_state::<TrayState<R>>() else { return };
        let state = app.state::<AppState>();
        let lang = crate::i18n::lang(&state);
        if let Ok(guard) = tray.0.lock()
            && let Some(items) = guard.as_ref()
        {
            let _ = items.open.set_text(t(lang, "tray_open"));
            let _ = items.quick.set_text(t(lang, "tray_quick_scan"));
            let _ = items.realtime.set_text(t(lang, "tray_realtime"));
            let _ = items.realtime.set_checked(state.settings().realtime_enabled);
            let _ = items.quit.set_text(t(lang, "tray_quit"));
        }
    }
}

#[cfg(desktop)]
pub use imp::{create, refresh, show_main_window};

#[cfg(mobile)]
pub fn refresh<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) {}
