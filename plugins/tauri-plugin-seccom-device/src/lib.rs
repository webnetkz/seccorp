//! SecCorp device integration plugin.
//!
//! * Android (Kotlin): "All files access", installed apps, uninstall/settings
//!   intents, device security posture, file picker that copies into the
//!   sandbox, and a foreground service that scans new downloads and newly
//!   installed apps through a JNI bridge into the Rust engine.
//! * iOS (Swift): device security posture (passcode, biometrics).
//! * Desktop: not needed; calls return `Unsupported`.

use tauri::{
    Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::SeccomDevice;
#[cfg(mobile)]
use mobile::SeccomDevice;

/// Access to the device APIs from Rust: `app.seccom_device()`.
pub trait SeccomDeviceExt<R: Runtime> {
    fn seccom_device(&self) -> &SeccomDevice<R>;
}

impl<R: Runtime, T: Manager<R>> crate::SeccomDeviceExt<R> for T {
    fn seccom_device(&self) -> &SeccomDevice<R> {
        self.state::<SeccomDevice<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("seccom-device")
        .invoke_handler(tauri::generate_handler![
            commands::get_storage_access,
            commands::request_storage_access,
            commands::list_installed_apps,
            commands::uninstall_app,
            commands::open_app_settings,
            commands::device_security,
            commands::start_protection,
            commands::stop_protection,
            commands::protection_status,
            commands::pick_file,
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let device = mobile::init(app, api)?;
            #[cfg(desktop)]
            let device = desktop::init(app, api)?;
            app.manage(device);
            Ok(())
        })
        .build()
}
