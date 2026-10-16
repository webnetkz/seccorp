//! macOS specifics.

use crate::model::StartupItem;
use std::path::{Path, PathBuf};

fn launch_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Library/LaunchAgents"));
    }
    v.push(PathBuf::from("/Library/LaunchAgents"));
    v.push(PathBuf::from("/Library/LaunchDaemons"));
    v
}

pub fn quick_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
        v.push(h.join("Documents"));
    }
    v.extend(launch_dirs(home));
    v.push(PathBuf::from("/Users/Shared"));
    v.push(PathBuf::from("/private/tmp"));
    v
}

/// The whole startup disk. `/System` is a sealed, signed volume and
/// `/System/Volumes/Data` is reachable again through firmlinks, so it is
/// excluded (see [`exclusions`]).
pub fn full_roots(_home: Option<&Path>) -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

pub fn watch_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = home {
        v.push(h.join("Downloads"));
        v.push(h.join("Desktop"));
        v.push(h.join("Documents"));
    }
    v.extend(launch_dirs(home));
    v
}

pub fn exclusions() -> Vec<String> {
    ["/System", "/dev", "/Volumes", "/private/var/vm", "/cores", "/private/var/db/uuidtext"].iter().map(|s| s.to_string()).collect()
}

pub fn browse_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/")];
    v.extend(home.map(|h| vec![h.to_path_buf()]).unwrap_or_default());
    v.push(PathBuf::from("/Applications"));
    v.push(PathBuf::from("/Volumes"));
    v
}

pub fn removable_media() -> Vec<PathBuf> {
    std::fs::read_dir("/Volumes").map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()).unwrap_or_default()
}

pub fn signature_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("/opt/homebrew/var/lib/clamav"), PathBuf::from("/usr/local/var/lib/clamav")]
}

/// True when SecCorp has Full Disk Access.
///
/// Probes files that only Full Disk Access can read. Without it such reads fail
/// silently (EPERM) instead of showing a consent prompt, so the check itself
/// never bothers the user. macOS applies a new grant only after the app is
/// restarted, which this check reflects.
pub fn has_full_disk_access(home: Option<&Path>) -> bool {
    use std::io::ErrorKind;
    let mut files = vec![PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db")];
    if let Some(h) = home {
        files.push(h.join("Library/Application Support/com.apple.TCC/TCC.db"));
    }
    for f in &files {
        match std::fs::File::open(f) {
            Ok(_) => return true,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return false,
            Err(_) => {}
        }
    }
    if let Some(h) = home {
        for dir in ["Library/Safari", "Library/Mail", "Library/Messages"] {
            match std::fs::read_dir(h.join(dir)) {
                Ok(_) => return true,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => return false,
                Err(_) => {}
            }
        }
    }
    // Nothing to probe (unusual system): assume access rather than nag.
    true
}

pub fn needs_full_disk_access(home: Option<&Path>) -> bool {
    !has_full_disk_access(home)
}

/// Locations macOS guards with privacy consent (TCC). Without Full Disk Access
/// reading them either shows a prompt for every protected area (Desktop,
/// Documents, Downloads, iCloud Drive, other apps' data) or fails silently, so
/// scans skip them until access is granted.
pub fn protected_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let Some(h) = home else { return Vec::new() };
    [
        "Desktop",
        "Documents",
        "Downloads",
        "Library/Mobile Documents",
        "Library/CloudStorage",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Daemon Containers",
        "Library/Application Support/AddressBook",
        "Library/Application Support/CallHistoryDB",
        "Library/Application Support/CallHistoryTransactions",
        "Library/Application Support/com.apple.TCC",
        "Library/Application Support/FileProvider",
        "Library/Application Support/Knowledge",
        "Library/Application Support/MobileSync",
        "Library/Autosave Information",
        "Library/Biome",
        "Library/Calendars",
        "Library/Cookies",
        "Library/HomeKit",
        "Library/IdentityServices",
        "Library/Mail",
        "Library/Messages",
        "Library/Metadata/CoreSpotlight",
        "Library/PersonalizationPortrait",
        "Library/Reminders",
        "Library/Safari",
        "Library/Suggestions",
        "Pictures/Photos Library.photoslibrary",
    ]
    .iter()
    .map(|r| h.join(r))
    .collect()
}

pub fn open_full_disk_access_settings() -> Result<(), String> {
    std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn startup_items() -> Vec<StartupItem> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut items = Vec::new();
    for dir in launch_dirs(home.as_deref()) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("plist") {
                continue;
            }
            let Ok(value) = plist::Value::from_file(&p) else { continue };
            let Some(dict) = value.as_dictionary() else { continue };
            let label = dict
                .get("Label")
                .and_then(|v| v.as_string())
                .map(str::to_string)
                .unwrap_or_else(|| e.file_name().to_string_lossy().into_owned());
            let program = dict.get("Program").and_then(|v| v.as_string()).map(str::to_string).or_else(|| {
                dict.get("ProgramArguments")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_string())
                    .map(str::to_string)
            });
            let command = dict
                .get("ProgramArguments")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_string()).collect::<Vec<_>>().join(" "))
                .or_else(|| program.clone())
                .unwrap_or_default();
            items.push(StartupItem {
                name: label,
                command,
                path: program.or_else(|| Some(p.to_string_lossy().into_owned())),
                location: dir.to_string_lossy().into_owned(),
            });
        }
    }
    items
}
