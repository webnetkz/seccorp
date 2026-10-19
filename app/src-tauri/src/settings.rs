//! User settings (persisted as JSON in the app data directory).

use seccom_engine::{HeuristicLevel, ScanOptions};
use serde::{Deserialize, Serialize};

/// The signed database feed used by Android Store builds. Build-time values
/// still take precedence, which keeps development and enterprise feeds
/// configurable.
pub const ANDROID_UPDATE_URL: &str = "https://raw.githubusercontent.com/webnetkz/seccorp/codex/microsoft-store-1.0.0/updates/update.json";

fn default_update_url() -> String {
    option_env!("SECCOM_UPDATE_URL")
        .filter(|url| !url.trim().is_empty())
        .unwrap_or(if cfg!(target_os = "android") { ANDROID_UPDATE_URL } else { "" })
        .to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Schedule {
    pub enabled: bool,
    /// "quick" or "full".
    pub kind: String,
    /// "daily" or "weekly".
    pub frequency: String,
    /// 0 = Monday … 6 = Sunday (weekly schedules).
    pub weekday: u8,
    pub hour: u8,
    pub minute: u8,
    /// UNIX time of the last scheduled run.
    pub last_run: u64,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule { enabled: false, kind: "quick".into(), frequency: "weekly".into(), weekday: 2, hour: 12, minute: 0, last_run: 0 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// "auto", "ru" or "en".
    pub language: String,
    /// "system", "dark" or "light".
    pub theme: String,
    pub realtime_enabled: bool,
    /// Inspect active sockets in the background (desktop only).
    pub network_monitor_enabled: bool,
    /// Match remote IP addresses against the locally downloaded C2 list.
    pub network_threat_intel: bool,
    /// Correlate unusual connections with process location and persistence.
    pub network_spyware_heuristics: bool,
    /// Folders watched in real time (empty = platform defaults).
    pub realtime_paths: Vec<String>,
    pub auto_quarantine: bool,
    pub notifications: bool,
    pub heuristics: HeuristicLevel,
    pub scan_archives: bool,
    pub max_file_size_mb: u64,
    pub exclusions: Vec<String>,
    pub use_cache: bool,
    /// SHA-256 of files the user explicitly allowed.
    pub allowed_hashes: Vec<String>,
    pub schedule: Schedule,
    pub launch_at_login: bool,
    pub start_minimized: bool,
    pub close_to_tray: bool,
    /// URL of `update.json`.
    pub update_url: String,
    pub auto_update: bool,
    /// Android: include installed apps in quick/full scans.
    pub scan_installed_apps: bool,
    /// Android background service: scan newly installed apps.
    pub scan_new_apps: bool,
    /// Android background service: scan finished downloads.
    pub watch_downloads: bool,
    pub onboarding_done: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let mac_store = cfg!(all(target_os = "macos", feature = "mac-app-store"));
        Settings {
            language: "auto".into(),
            theme: "system".into(),
            realtime_enabled: cfg!(any(desktop, target_os = "android")) && !mac_store,
            network_monitor_enabled: cfg!(desktop) && !mac_store,
            network_threat_intel: cfg!(desktop) && !mac_store,
            network_spyware_heuristics: cfg!(desktop) && !mac_store,
            realtime_paths: Vec::new(),
            auto_quarantine: true,
            notifications: true,
            heuristics: HeuristicLevel::Normal,
            scan_archives: true,
            max_file_size_mb: if cfg!(mobile) { 256 } else { 512 },
            exclusions: Vec::new(),
            use_cache: true,
            allowed_hashes: Vec::new(),
            schedule: Schedule::default(),
            launch_at_login: false,
            start_minimized: true,
            close_to_tray: cfg!(desktop) && !mac_store,
            update_url: default_update_url(),
            auto_update: true,
            scan_installed_apps: true,
            scan_new_apps: true,
            watch_downloads: true,
            onboarding_done: false,
        }
    }
}

impl Settings {
    /// Engine options derived from the settings plus platform exclusions.
    pub fn scan_options(&self, extra_exclusions: &[String]) -> ScanOptions {
        let mut o = if cfg!(mobile) { ScanOptions::mobile() } else { ScanOptions::default() };
        o.heuristics = self.heuristics;
        o.scan_archives = self.scan_archives;
        o.max_file_size = self.max_file_size_mb.clamp(1, 16 * 1024) * 1024 * 1024;
        o.use_cache = self.use_cache;
        o.exclusions = self.exclusions.clone();
        o.exclusions.extend(extra_exclusions.iter().cloned());
        o
    }

    pub fn is_allowed(&self, sha256: Option<&str>) -> bool {
        sha256.is_some_and(|h| self.allowed_hashes.iter().any(|a| a.eq_ignore_ascii_case(h)))
    }

    /// Clamps values coming from the UI.
    pub fn sanitize(mut self) -> Self {
        if !matches!(self.language.as_str(), "auto" | "ru" | "en") {
            self.language = "auto".into();
        }
        if !matches!(self.theme.as_str(), "system" | "dark" | "light") {
            self.theme = "system".into();
        }
        self.schedule.hour = self.schedule.hour.min(23);
        self.schedule.minute = self.schedule.minute.min(59);
        self.schedule.weekday = self.schedule.weekday.min(6);
        if !matches!(self.schedule.kind.as_str(), "quick" | "full") {
            self.schedule.kind = "quick".into();
        }
        if !matches!(self.schedule.frequency.as_str(), "daily" | "weekly") {
            self.schedule.frequency = "weekly".into();
        }
        self.max_file_size_mb = self.max_file_size_mb.clamp(1, 16 * 1024);
        self.exclusions.retain(|e| !e.trim().is_empty());
        self.exclusions.dedup();
        self.realtime_paths.retain(|p| !p.trim().is_empty());
        self.realtime_paths.dedup();
        self.update_url = self.update_url.trim().to_string();
        // Migrate settings written by older Android builds where the field was
        // persisted as an empty string and online updates were unavailable.
        if self.update_url.is_empty() {
            self.update_url = default_update_url();
        }
        self
    }
}
