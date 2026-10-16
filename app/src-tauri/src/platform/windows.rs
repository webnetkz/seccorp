//! Windows specifics.

use crate::model::StartupItem;
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

fn startup_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(appdata) = env_path("APPDATA") {
        v.push(appdata.join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Some(pd) = env_path("PROGRAMDATA") {
        v.push(pd.join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    v
}

pub fn quick_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
        v.push(h.join("Documents"));
    }
    if let Some(t) = env_path("TEMP") {
        v.push(t);
    }
    if let Some(public) = env_path("PUBLIC") {
        v.push(public.join("Downloads"));
        v.push(public.join("Desktop"));
    }
    v.extend(startup_folders());
    v
}

/// All fixed (non-removable, non-network) drives.
pub fn full_roots(_home: Option<&Path>) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_FIXED: u32 = 3;
    let mut roots = Vec::new();
    // SAFETY: plain Win32 calls with valid, NUL-terminated arguments.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{letter}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 string.
        if unsafe { GetDriveTypeW(wide.as_ptr()) } == DRIVE_FIXED {
            roots.push(PathBuf::from(root));
        }
    }
    roots
}

pub fn watch_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
        v.push(h.join("Documents"));
    }
    v.extend(startup_folders());
    v
}

pub fn exclusions() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(sys) = env_path("SystemDrive") {
        let d = sys.to_string_lossy().to_string();
        for f in ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "System Volume Information", "$Recycle.Bin\\S-1-5-18"] {
            v.push(format!("{d}\\{f}"));
        }
    }
    v
}

pub fn browse_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = home.map(|h| vec![h.to_path_buf()]).unwrap_or_default();
    v.extend(full_roots(home));
    v
}

pub fn removable_media() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_CDROM: u32 = 5;
    let mask = unsafe { GetLogicalDrives() };
    let system = env_path("SystemDrive").map(|p| p.to_string_lossy().to_ascii_uppercase());
    let mut roots = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        if system.as_deref().is_some_and(|s| root.to_ascii_uppercase().starts_with(s)) {
            continue;
        }
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if matches!(kind, DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM) {
            roots.push(PathBuf::from(root));
        }
    }
    roots
}

pub fn signature_dirs() -> Vec<PathBuf> {
    env_path("PROGRAMDATA").map(|p| vec![p.join("ClamAV\\database")]).unwrap_or_default()
}

pub fn startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    let keys = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ];
    for (hive, hive_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
        let root = RegKey::predef(hive);
        for key in keys {
            let Ok(k) = root.open_subkey_with_flags(key, KEY_READ) else { continue };
            for (name, value) in k.enum_values().flatten() {
                let command = value.to_string();
                items.push(StartupItem {
                    path: super::executable_from_command(&command),
                    name,
                    command,
                    location: format!("{hive_name}\\{key}"),
                });
            }
        }
    }
    for folder in startup_folders() {
        let Ok(rd) = std::fs::read_dir(&folder) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                items.push(StartupItem {
                    name: e.file_name().to_string_lossy().into_owned(),
                    command: p.to_string_lossy().into_owned(),
                    path: Some(p.to_string_lossy().into_owned()),
                    location: folder.to_string_lossy().into_owned(),
                });
            }
        }
    }
    items
}
