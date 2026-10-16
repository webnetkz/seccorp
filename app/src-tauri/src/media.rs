//! Detects storage volumes mounted while the desktop application is running.
//! The UI asks before scanning; no removable drive is read automatically.

#![cfg(desktop)]

use crate::model::RemovableMedia;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Runtime};

fn snapshot() -> BTreeSet<PathBuf> {
    crate::platform::removable_media().into_iter().collect()
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// Starts a small mount-point watcher. Existing volumes form the baseline;
/// only media attached later generates an event.
pub fn spawn<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let mut previous = snapshot();
    if let Err(e) = std::thread::Builder::new().name("seccorp-media".into()).spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let current = snapshot();
            for path in current.difference(&previous) {
                if !path.exists() {
                    continue;
                }
                let media = RemovableMedia { name: display_name(path), path: path.to_string_lossy().into_owned() };
                crate::tray::show_main_window(&app);
                let _ = app.emit("media://inserted", media);
            }
            previous = current;
        }
    }) {
        log::warn!("cannot start removable-media monitor: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_readable_media_name() {
        assert_eq!(display_name(Path::new("/Volumes/USB DRIVE")), "USB DRIVE");
        assert_eq!(display_name(Path::new("E:\\")), "E:\\");
    }
}
