use serde::de::DeserializeOwned;
use tauri::{AppHandle, Runtime, plugin::PluginApi};

use crate::models::*;
use crate::{Error, Result};

pub fn init<R: Runtime, C: DeserializeOwned>(app: &AppHandle<R>, _api: PluginApi<R, C>) -> crate::Result<SeccomDevice<R>> {
    Ok(SeccomDevice(app.clone()))
}

/// Desktop builds use the engine directly; device-specific calls are not available.
pub struct SeccomDevice<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

impl<R: Runtime> SeccomDevice<R> {
    pub fn get_storage_access(&self) -> Result<StorageAccess> {
        Ok(StorageAccess { granted: true, all_files_access: false })
    }

    pub fn request_storage_access(&self) -> Result<()> {
        Ok(())
    }

    pub fn list_installed_apps(&self, _req: ListAppsRequest) -> Result<InstalledApps> {
        Err(Error::Unsupported)
    }

    pub fn uninstall_app(&self, _req: PackageRequest) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub fn open_app_settings(&self, _req: PackageRequest) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub fn device_security(&self) -> Result<DeviceSecurity> {
        Ok(DeviceSecurity { platform: std::env::consts::OS.to_string(), ..Default::default() })
    }

    pub fn start_protection(&self, _config: ProtectionConfig) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub fn stop_protection(&self) -> Result<()> {
        Ok(())
    }

    pub fn protection_status(&self) -> Result<ProtectionStatus> {
        Ok(ProtectionStatus { running: false })
    }

    pub fn pick_file(&self) -> Result<PickedFile> {
        Err(Error::Unsupported)
    }
}
