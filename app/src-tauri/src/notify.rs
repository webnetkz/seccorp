//! System notifications.

use crate::state::AppState;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_notification::NotificationExt;

/// Shows a notification when the user enabled them.
pub fn notify<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    let Some(state) = app.try_state::<AppState>() else { return };
    if !state.settings().notifications {
        return;
    }
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        log::warn!("notification failed: {e}");
    }
}
