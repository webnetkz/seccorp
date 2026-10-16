use serde::{Deserialize, Serialize};

/// Access to shared storage (Android "All files access").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageAccess {
    pub granted: bool,
    /// True on Android 11+ where the special "All files access" setting is used.
    #[serde(default)]
    pub all_files_access: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAppsRequest {
    pub include_system: bool,
    pub with_icons: bool,
}

/// An installed Android application.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InstalledApp {
    pub package_name: String,
    pub label: String,
    pub version_name: String,
    /// Path of the base APK (readable by any app).
    pub source_dir: String,
    pub split_source_dirs: Vec<String>,
    pub is_system: bool,
    /// Package name of the installer (e.g. `com.android.vending`), empty if unknown.
    pub installer: String,
    pub first_install_time: i64,
    pub last_update_time: i64,
    pub permissions: Vec<String>,
    /// 48x48 PNG icon, base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApps {
    pub apps: Vec<InstalledApp>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRequest {
    pub package_name: String,
}

/// Device security posture.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceSecurity {
    pub platform: String,
    pub os_version: String,
    pub model: String,
    pub manufacturer: String,
    pub sdk_int: Option<i32>,
    /// Android security patch level (YYYY-MM-DD).
    pub security_patch: Option<String>,
    /// Screen lock (PIN/pattern/password/passcode) is configured.
    pub screen_lock: Option<bool>,
    pub biometrics: Option<bool>,
    pub biometry_type: Option<String>,
    pub developer_options: Option<bool>,
    pub usb_debugging: Option<bool>,
    pub storage_encrypted: Option<bool>,
    pub notifications_allowed: Option<bool>,
}

/// Configuration of the Android background protection service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionConfig {
    pub watch_downloads: bool,
    pub scan_installs: bool,
    /// Application data directory shared with the Rust engine.
    pub data_dir: String,
    /// Localised texts for the persistent notification.
    pub title: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionStatus {
    pub running: bool,
}

/// A file picked by the user and copied into the app sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PickedFile {
    pub cancelled: bool,
    pub path: Option<String>,
    pub name: Option<String>,
}
