//! Data transfer objects shared with the user interface (camelCase JSON).

use seccom_engine::{DbInfo, FileVerdict, ScanProgress};
use serde::{Deserialize, Serialize};

/// Capabilities of the current build/platform; the UI adapts to them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    /// Real-time protection of folders (desktop, Android service, iOS inbox).
    pub realtime: bool,
    /// Running processes are checked during a quick scan.
    pub processes: bool,
    /// Autostart entries can be listed.
    pub startup_items: bool,
    /// Installed apps can be scanned (Android).
    pub installed_apps: bool,
    /// Device security checklist (mobile).
    pub device_check: bool,
    pub tray: bool,
    pub autostart: bool,
    pub schedule: bool,
    /// Native folder picker available (desktop).
    pub folder_picker: bool,
    /// In-app folder browser is used instead (Android).
    pub folder_browser: bool,
    pub full_scan: bool,
    /// Shared storage needs an explicit grant (Android).
    pub storage_permission: bool,
    /// Full Disk Access hint (macOS).
    pub full_disk_access: bool,
    /// Desktop can detect newly mounted removable media.
    pub removable_media: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub engine_version: String,
    pub platform: String,
    pub arch: String,
    pub features: Features,
    pub update_configured: bool,
    /// "signed" for a SecCorp feed, "freshclam" for official ClamAV updates,
    /// or "none" when only manual imports are available.
    pub update_mode: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Stats {
    pub files_scanned: u64,
    pub threats_found: u64,
    pub threats_neutralized: u64,
    pub scans_completed: u64,
    pub realtime_scanned: u64,
    pub last_scan_at: Option<u64>,
    pub last_full_scan_at: Option<u64>,
    pub installed_at: u64,
}

/// A detected threat waiting for a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatEntry {
    pub id: String,
    pub verdict: FileVerdict,
    /// "scan", "realtime", "service" (Android background service) or "apps".
    pub source: String,
    pub detected_at: u64,
    /// Android package name for app threats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanRecord {
    pub id: String,
    pub kind: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub files_scanned: u64,
    pub files_cached: u64,
    pub files_skipped: u64,
    pub bytes_scanned: u64,
    pub errors: u64,
    pub cancelled: bool,
    pub threat_count: u64,
    pub threats: Vec<FileVerdict>,
    pub roots: Vec<String>,
    /// macOS without Full Disk Access: privacy-protected folders were skipped.
    pub limited: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressEvent {
    pub scan_id: String,
    pub kind: String,
    #[serde(flatten)]
    pub progress: ScanProgress,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanState {
    pub running: bool,
    pub scan_id: Option<String>,
    pub kind: Option<String>,
    pub progress: Option<ScanProgress>,
    pub threats: Vec<ThreatEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeEvent {
    pub time: u64,
    pub path: String,
    pub verdict: seccom_engine::Verdict,
    pub threat_name: Option<String>,
    /// "none", "quarantined", "failed".
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeStatus {
    pub supported: bool,
    pub enabled: bool,
    pub running: bool,
    pub watched: Vec<String>,
    pub scanned: u64,
    pub error: Option<String>,
    /// macOS without Full Disk Access: privacy-protected folders are not monitored.
    pub limited: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    /// "protected", "attention" or "danger".
    pub status: String,
    /// Issue codes translated by the UI.
    pub issues: Vec<String>,
    pub realtime: RealtimeStatus,
    pub db: DbInfo,
    pub db_ready: bool,
    pub stats: Stats,
    pub active_threats: usize,
    pub quarantine_count: usize,
    pub quarantine_bytes: u64,
    pub last_scan: Option<ScanRecord>,
    pub scan_running: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    pub id: String,
    pub ok: bool,
    pub error: Option<String>,
    /// For restore: new location of the file.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupItem {
    pub name: String,
    pub command: String,
    pub path: Option<String>,
    pub location: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<DirEntry>,
}

/// A storage volume that appeared while the application was running.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemovableMedia {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSignatureFile {
    pub name: String,
    pub size: u64,
    pub modified: u64,
}

/// Result of checking an installed Android app.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppReport {
    pub package_name: String,
    pub label: String,
    pub version_name: String,
    pub installer: String,
    pub trusted_source: bool,
    pub is_system: bool,
    pub icon: Option<String>,
    pub verdict: seccom_engine::Verdict,
    pub threat_name: Option<String>,
    pub risk_score: u32,
    pub risk_reasons: Vec<String>,
    pub permissions_count: usize,
    pub last_update_time: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheck {
    pub configured: bool,
    pub available: bool,
    pub current: String,
    pub latest: Option<String>,
    pub released: Option<u64>,
    pub size: Option<u64>,
    pub notes: Option<String>,
    pub checked_at: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgress {
    /// "checking", "downloading", "verifying", "installing", "done", "error".
    pub stage: String,
    pub downloaded: u64,
    pub total: u64,
    pub message: Option<String>,
}
