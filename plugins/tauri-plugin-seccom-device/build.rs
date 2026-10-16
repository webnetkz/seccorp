const COMMANDS: &[&str] = &[
    "get_storage_access",
    "request_storage_access",
    "list_installed_apps",
    "uninstall_app",
    "open_app_settings",
    "device_security",
    "start_protection",
    "stop_protection",
    "protection_status",
    "pick_file",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).android_path("android").ios_path("ios").build();
}
