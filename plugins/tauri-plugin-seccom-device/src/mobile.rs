use serde::de::DeserializeOwned;
use tauri::{
    AppHandle, Runtime,
    plugin::{PluginApi, PluginHandle},
};

#[cfg(target_os = "ios")]
use crate::Error;
use crate::Result;
use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_seccom_device);

/// Registers the Kotlin / Swift plugin classes.
pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<SeccomDevice<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("com.webnetkz.seccom.device", "DevicePlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_seccom_device)?;
    Ok(SeccomDevice(handle))
}

/// Access to the native device APIs.
pub struct SeccomDevice<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> SeccomDevice<R> {
    pub fn device_security(&self) -> Result<DeviceSecurity> {
        self.0.run_mobile_plugin("deviceSecurity", ()).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn get_storage_access(&self) -> Result<StorageAccess> {
        self.0.run_mobile_plugin("getStorageAccess", ()).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn request_storage_access(&self) -> Result<()> {
        self.0.run_mobile_plugin("requestStorageAccess", ()).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn list_installed_apps(&self, req: ListAppsRequest) -> Result<InstalledApps> {
        self.0.run_mobile_plugin("listInstalledApps", req).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn uninstall_app(&self, req: PackageRequest) -> Result<()> {
        self.0.run_mobile_plugin("uninstallApp", req).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn open_app_settings(&self, req: PackageRequest) -> Result<()> {
        self.0.run_mobile_plugin("openAppSettings", req).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn start_protection(&self, config: ProtectionConfig) -> Result<()> {
        self.0.run_mobile_plugin("startProtection", config).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn stop_protection(&self) -> Result<()> {
        self.0.run_mobile_plugin("stopProtection", ()).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn protection_status(&self) -> Result<ProtectionStatus> {
        self.0.run_mobile_plugin("protectionStatus", ()).map_err(Into::into)
    }

    #[cfg(target_os = "android")]
    pub fn pick_file(&self) -> Result<PickedFile> {
        self.0.run_mobile_plugin("pickFile", ()).map_err(Into::into)
    }

    // iOS: the app sandbox makes these concepts inapplicable.

    #[cfg(target_os = "ios")]
    pub fn get_storage_access(&self) -> Result<StorageAccess> {
        Ok(StorageAccess { granted: true, all_files_access: false })
    }

    #[cfg(target_os = "ios")]
    pub fn request_storage_access(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "ios")]
    pub fn list_installed_apps(&self, _req: ListAppsRequest) -> Result<InstalledApps> {
        Err(Error::Unsupported)
    }

    #[cfg(target_os = "ios")]
    pub fn uninstall_app(&self, _req: PackageRequest) -> Result<()> {
        Err(Error::Unsupported)
    }

    #[cfg(target_os = "ios")]
    pub fn open_app_settings(&self, _req: PackageRequest) -> Result<()> {
        Err(Error::Unsupported)
    }

    #[cfg(target_os = "ios")]
    pub fn start_protection(&self, _config: ProtectionConfig) -> Result<()> {
        Err(Error::Unsupported)
    }

    #[cfg(target_os = "ios")]
    pub fn stop_protection(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "ios")]
    pub fn protection_status(&self) -> Result<ProtectionStatus> {
        Ok(ProtectionStatus { running: false })
    }

    #[cfg(target_os = "ios")]
    pub fn pick_file(&self) -> Result<PickedFile> {
        Err(Error::Unsupported)
    }
}
