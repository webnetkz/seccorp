use tauri::{AppHandle, Runtime, command};

use crate::Result;
use crate::SeccomDeviceExt;
use crate::models::*;

#[command]
pub(crate) async fn get_storage_access<R: Runtime>(app: AppHandle<R>) -> Result<StorageAccess> {
    app.seccom_device().get_storage_access()
}

#[command]
pub(crate) async fn request_storage_access<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.seccom_device().request_storage_access()
}

#[command]
pub(crate) async fn list_installed_apps<R: Runtime>(app: AppHandle<R>, payload: ListAppsRequest) -> Result<InstalledApps> {
    app.seccom_device().list_installed_apps(payload)
}

#[command]
pub(crate) async fn uninstall_app<R: Runtime>(app: AppHandle<R>, payload: PackageRequest) -> Result<()> {
    app.seccom_device().uninstall_app(payload)
}

#[command]
pub(crate) async fn open_app_settings<R: Runtime>(app: AppHandle<R>, payload: PackageRequest) -> Result<()> {
    app.seccom_device().open_app_settings(payload)
}

#[command]
pub(crate) async fn device_security<R: Runtime>(app: AppHandle<R>) -> Result<DeviceSecurity> {
    app.seccom_device().device_security()
}

#[command]
pub(crate) async fn start_protection<R: Runtime>(app: AppHandle<R>, payload: ProtectionConfig) -> Result<()> {
    app.seccom_device().start_protection(payload)
}

#[command]
pub(crate) async fn stop_protection<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.seccom_device().stop_protection()
}

#[command]
pub(crate) async fn protection_status<R: Runtime>(app: AppHandle<R>) -> Result<ProtectionStatus> {
    app.seccom_device().protection_status()
}

#[command]
pub(crate) async fn pick_file<R: Runtime>(app: AppHandle<R>) -> Result<PickedFile> {
    app.seccom_device().pick_file()
}
