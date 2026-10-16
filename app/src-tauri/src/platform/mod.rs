//! Platform-specific knowledge: where to look, what to watch, what to skip.

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(desktop)]
mod processes;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "android")]
use android as os;
#[cfg(target_os = "ios")]
use ios as os;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(target_os = "windows")]
use windows as os;

use crate::model::{DirEntry, DirListing, Features, StartupItem};
use crate::state::{AppState, Paths};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, Runtime};

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "linux"
    }
}

pub fn features() -> Features {
    let desktop = cfg!(desktop);
    let android = cfg!(target_os = "android");
    let ios = cfg!(target_os = "ios");
    Features {
        realtime: true,
        processes: desktop,
        startup_items: cfg!(any(target_os = "windows", target_os = "macos", target_os = "linux")),
        installed_apps: android,
        device_check: android || ios,
        tray: desktop,
        autostart: desktop,
        schedule: desktop,
        folder_picker: desktop,
        folder_browser: android,
        full_scan: !ios,
        storage_permission: android,
        full_disk_access: cfg!(target_os = "macos"),
        removable_media: desktop,
        network_protection: desktop,
    }
}

fn home<R: Runtime>(app: &AppHandle<R>) -> Option<PathBuf> {
    app.path().home_dir().ok().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

fn dedup_existing(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths.into_iter().filter(|p| p.exists()).filter(|p| seen.insert(p.clone())).collect()
}

/// Folders and files checked by a quick scan.
pub fn quick_scan_targets<R: Runtime>(app: &AppHandle<R>, state: &AppState) -> Vec<PathBuf> {
    let _ = state;
    #[cfg_attr(mobile, allow(unused_mut))]
    let mut targets = os::quick_dirs(home(app).as_deref());
    #[cfg(desktop)]
    {
        targets.extend(processes::running_executables());
        targets.extend(startup_items().into_iter().filter_map(|i| i.path.map(PathBuf::from)));
    }
    dedup_existing(targets)
}

/// Roots of a full scan.
pub fn full_scan_roots<R: Runtime>(app: &AppHandle<R>, _state: &AppState) -> Vec<PathBuf> {
    let mut roots = os::full_roots(home(app).as_deref());
    if roots.is_empty() {
        roots = os::quick_dirs(home(app).as_deref());
    }
    dedup_existing(roots)
}

/// Folders protected in real time by default.
pub fn default_watch_paths<R: Runtime>(app: &AppHandle<R>, _state: &AppState) -> Vec<PathBuf> {
    dedup_existing(os::watch_dirs(home(app).as_deref()))
}

/// Paths never scanned (virtual file systems, our own data).
pub fn default_exclusions(paths: &Paths) -> Vec<String> {
    let mut v = os::exclusions();
    v.push(paths.data.to_string_lossy().into_owned());
    v
}

/// Programs started automatically with the system.
pub fn startup_items() -> Vec<StartupItem> {
    os::startup_items()
}

/// Currently mounted removable/external media. The media monitor compares
/// snapshots and prompts only for volumes that appear after startup.
#[cfg(desktop)]
pub fn removable_media() -> Vec<PathBuf> {
    dedup_existing(os::removable_media())
}

/// Compatible signature databases maintained by another local scanner.
/// Missing directories are ignored by the database loader.
pub fn system_signature_dirs() -> Vec<PathBuf> {
    os::signature_dirs()
}

/// macOS: true when Full Disk Access seems to be missing.
pub fn needs_full_disk_access<R: Runtime>(app: &AppHandle<R>) -> bool {
    #[cfg(target_os = "macos")]
    {
        return macos::needs_full_disk_access(home(app).as_deref());
    }
    #[allow(unreachable_code)]
    {
        let _ = app;
        false
    }
}

/// Privacy-protected folders SecCorp cannot read without asking: on macOS
/// without Full Disk Access these are skipped instead of triggering a consent
/// prompt per folder. Empty when access is granted and on other platforms.
pub fn locked_dirs<R: Runtime>(app: &AppHandle<R>) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = home(app);
        if macos::needs_full_disk_access(home.as_deref()) {
            return macos::protected_dirs(home.as_deref());
        }
        return Vec::new();
    }
    #[allow(unreachable_code)]
    {
        let _ = app;
        Vec::new()
    }
}

/// True when a scan of `roots` would walk into one of the `locked` folders.
/// With `strict`, a root that *is* a locked folder (or lies inside one) does not
/// count: the user picked it in the system file dialog, which grants access.
pub fn reaches_locked(roots: &[PathBuf], locked: &[PathBuf], strict: bool) -> bool {
    roots.iter().any(|r| locked.iter().any(|l| l.starts_with(r) && !(strict && l == r)))
}

/// Opens the OS privacy settings relevant for scanning.
pub fn open_privacy_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        return macos::open_full_disk_access_settings();
    }
    #[allow(unreachable_code)]
    Err("not supported on this platform".into())
}

/// Starting points for the in-app folder browser.
pub fn browse_roots<R: Runtime>(app: &AppHandle<R>) -> Vec<DirEntry> {
    let mut roots: Vec<PathBuf> = os::browse_roots(home(app).as_deref());
    roots.retain(|p| p.exists());
    roots
        .into_iter()
        .map(|p| DirEntry {
            name: p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string_lossy().into_owned()),
            path: p.to_string_lossy().into_owned(),
            is_dir: true,
            size: 0,
        })
        .collect()
}

/// Lists a directory for the in-app folder browser.
pub fn list_dir(path: &str) -> Result<DirListing, String> {
    let p = Path::new(path);
    let rd = std::fs::read_dir(p).map_err(|e| e.to_string())?;
    let mut entries: Vec<DirEntry> = rd
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            Some(DirEntry {
                name,
                path: e.path().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: if meta.is_file() { meta.len() } else { 0 },
            })
        })
        .collect();
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    entries.truncate(2000);
    Ok(DirListing { path: p.to_string_lossy().into_owned(), parent: p.parent().map(|x| x.to_string_lossy().into_owned()), entries })
}

/// Extracts the executable path from a command line (Windows/macOS autostart).
#[allow(dead_code)]
pub fn executable_from_command(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let path = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else if let Some(i) = cmd.to_ascii_lowercase().find(".exe") {
        cmd[..i + 4].to_string()
    } else {
        cmd.split_whitespace().next().unwrap_or("").to_string()
    };
    let expanded = expand_env(&path);
    (!expanded.is_empty()).then_some(expanded)
}

/// Expands `%VAR%` references.
#[allow(dead_code)]
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_folders_are_detected() {
        let locked = vec![PathBuf::from("/Users/a/Desktop"), PathBuf::from("/Users/a/Library/Containers")];
        let p = |s: &str| vec![PathBuf::from(s)];
        // Quick/full scans: any overlap counts.
        assert!(reaches_locked(&p("/"), &locked, false));
        assert!(reaches_locked(&p("/Users/a/Desktop"), &locked, false));
        assert!(!reaches_locked(&p("/Users/a/Projects"), &locked, false));
        // Custom scans: a folder picked in the system dialog is allowed by macOS.
        assert!(!reaches_locked(&p("/Users/a/Desktop"), &locked, true));
        assert!(!reaches_locked(&p("/Users/a/Desktop/work"), &locked, true));
        assert!(reaches_locked(&p("/Users/a"), &locked, true));
        assert!(!reaches_locked(&p("/Users/ab"), &locked, true));
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            executable_from_command("\"C:\\Program Files\\App\\app.exe\" --tray").as_deref(),
            Some("C:\\Program Files\\App\\app.exe")
        );
        assert_eq!(executable_from_command("C:\\Tools\\tool.EXE /min").as_deref(), Some("C:\\Tools\\tool.EXE"));
        assert_eq!(executable_from_command("/usr/local/bin/agent --x").as_deref(), Some("/usr/local/bin/agent"));
        // SAFETY: test-only, single-threaded access to this variable.
        unsafe { std::env::set_var("SECCOM_TEST_DIR", "D:\\x") };
        assert_eq!(expand_env("%SECCOM_TEST_DIR%\\a.exe"), "D:\\x\\a.exe");
        assert_eq!(expand_env("%UNDEFINED_SECCOM%\\a"), "%UNDEFINED_SECCOM%\\a");
    }
}
