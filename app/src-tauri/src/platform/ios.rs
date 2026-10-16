//! iOS specifics.
//!
//! Apps are sandboxed: only files inside the app container can be checked.
//! Users bring files in through the document picker, "Open in…" / share
//! actions (they land in `Documents/Inbox`) or by copying them into the app
//! folder that the Files app exposes ("On My iPhone › SecCorp").

use crate::model::StartupItem;
use std::path::{Path, PathBuf};

fn container(home: Option<&Path>) -> Option<PathBuf> {
    home.map(Path::to_path_buf).or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

pub fn quick_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let Some(c) = container(home) else { return Vec::new() };
    vec![c.join("Documents"), c.join("tmp"), c.join("Library/Caches")]
}

pub fn full_roots(home: Option<&Path>) -> Vec<PathBuf> {
    quick_dirs(home)
}

pub fn watch_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    container(home).map(|c| vec![c.join("Documents")]).unwrap_or_default()
}

pub fn exclusions() -> Vec<String> {
    Vec::new()
}

pub fn browse_roots(home: Option<&Path>) -> Vec<PathBuf> {
    watch_dirs(home)
}

pub fn startup_items() -> Vec<StartupItem> {
    Vec::new()
}

pub fn signature_dirs() -> Vec<PathBuf> {
    Vec::new()
}
