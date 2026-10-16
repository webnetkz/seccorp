//! Linux specifics (development builds; not one of the four release targets).

use crate::model::StartupItem;
use std::path::{Path, PathBuf};

pub fn quick_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
        v.push(h.join(".config/autostart"));
    }
    v.push(PathBuf::from("/tmp"));
    v
}

pub fn full_roots(_home: Option<&Path>) -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

pub fn watch_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
    }
    v
}

pub fn exclusions() -> Vec<String> {
    ["/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/cache", "/tmp/.X11-unix"].iter().map(|s| s.to_string()).collect()
}

pub fn browse_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = home.map(|h| vec![h.to_path_buf()]).unwrap_or_default();
    v.push(PathBuf::from("/"));
    v
}

pub fn removable_media() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for parent in [PathBuf::from("/media"), PathBuf::from("/run/media"), PathBuf::from("/mnt")] {
        let Ok(users) = std::fs::read_dir(&parent) else { continue };
        for user in users.flatten() {
            let p = user.path();
            if !p.is_dir() {
                continue;
            }
            // /media and /run/media commonly contain a per-user directory;
            // /mnt commonly contains the mounted volume directly.
            let nested: Vec<PathBuf> =
                std::fs::read_dir(&p).map(|rd| rd.flatten().map(|e| e.path()).filter(|x| x.is_dir()).collect()).unwrap_or_default();
            if nested.is_empty() || parent == PathBuf::from("/mnt") {
                roots.push(p);
            } else {
                roots.extend(nested);
            }
        }
    }
    roots
}

pub fn signature_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("/var/lib/clamav"), PathBuf::from("/var/lib/clamav-unofficial-sigs")]
}

pub fn startup_items() -> Vec<StartupItem> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return Vec::new() };
    let dir = home.join(".config/autostart");
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            let exec = text.lines().find_map(|l| l.strip_prefix("Exec="))?.to_string();
            let name = text
                .lines()
                .find_map(|l| l.strip_prefix("Name="))
                .map(str::to_string)
                .unwrap_or_else(|| e.file_name().to_string_lossy().into_owned());
            Some(StartupItem {
                name,
                path: super::executable_from_command(&exec),
                command: exec,
                location: dir.to_string_lossy().into_owned(),
            })
        })
        .collect()
}
