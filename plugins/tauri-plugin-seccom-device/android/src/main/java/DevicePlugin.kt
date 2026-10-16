package com.webnetkz.seccom.device

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.OpenableColumns
import android.provider.Settings
import android.util.Base64
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.ByteArrayOutputStream
import java.io.File

@InvokeArg
class ListAppsArgs {
    var includeSystem: Boolean = false
    var withIcons: Boolean = true
}

@InvokeArg
class PackageArgs {
    lateinit var packageName: String
}

@InvokeArg
class ProtectionArgs {
    var watchDownloads: Boolean = true
    var scanInstalls: Boolean = true
    var dataDir: String? = null
    var title: String? = null
    var text: String? = null
}

@TauriPlugin
class DevicePlugin(private val activity: Activity) : Plugin(activity) {

    companion object {
        private const val TAG = "SecComDevice"
        private const val STORAGE_REQUEST = 4711
        private const val ICON_SIZE = 48
    }

    // ---------------------------------------------------------------- storage

    @Command
    fun getStorageAccess(invoke: Invoke) {
        val ret = JSObject()
        ret.put("granted", hasStorageAccess(activity))
        ret.put("allFilesAccess", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        invoke.resolve(ret)
    }

    @Command
    fun requestStorageAccess(invoke: Invoke) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                try {
                    val intent = Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + activity.packageName)
                    )
                    activity.startActivity(intent)
                } catch (e: Exception) {
                    // Some vendors do not implement the per-app screen.
                    activity.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                }
            } else {
                ActivityCompat.requestPermissions(
                    activity,
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    STORAGE_REQUEST
                )
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Cannot open storage settings")
        }
    }

    // ------------------------------------------------------------------- apps

    @Command
    fun listInstalledApps(invoke: Invoke) {
        val args = invoke.parseArgs(ListAppsArgs::class.java)
        Thread {
            try {
                val pm = activity.packageManager
                val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33) {
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                }
                val apps = JSArray()
                for (p in packages) {
                    val ai: ApplicationInfo = p.applicationInfo ?: continue
                    val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                        (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                    if (isSystem && !args.includeSystem) continue
                    if (p.packageName == activity.packageName) continue
                    val o = JSObject()
                    o.put("packageName", p.packageName)
                    o.put("label", pm.getApplicationLabel(ai).toString())
                    o.put("versionName", p.versionName ?: "")
                    o.put("sourceDir", ai.sourceDir ?: "")
                    val splits = JSArray()
                    ai.splitSourceDirs?.forEach { splits.put(it) }
                    o.put("splitSourceDirs", splits)
                    o.put("isSystem", isSystem)
                    o.put("installer", installerOf(pm, p.packageName) ?: "")
                    o.put("firstInstallTime", p.firstInstallTime)
                    o.put("lastUpdateTime", p.lastUpdateTime)
                    val perms = JSArray()
                    p.requestedPermissions?.forEach { perms.put(it) }
                    o.put("permissions", perms)
                    if (args.withIcons) {
                        iconBase64(pm, ai)?.let { o.put("icon", it) }
                    }
                    apps.put(o)
                }
                val ret = JSObject()
                ret.put("apps", apps)
                invoke.resolve(ret)
            } catch (e: Exception) {
                Log.e(TAG, "listInstalledApps failed", e)
                invoke.reject(e.message ?: "Cannot list installed apps")
            }
        }.start()
    }

    @Command
    fun uninstallApp(invoke: Invoke) {
        val args = invoke.parseArgs(PackageArgs::class.java)
        try {
            val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:" + args.packageName))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Cannot start uninstall")
        }
    }

    @Command
    fun openAppSettings(invoke: Invoke) {
        val args = invoke.parseArgs(PackageArgs::class.java)
        try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + args.packageName))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Cannot open app settings")
        }
    }

    // --------------------------------------------------------------- security

    @Command
    fun deviceSecurity(invoke: Invoke) {
        val cr = activity.contentResolver
        val ret = JSObject()
        ret.put("platform", "android")
        ret.put("osVersion", Build.VERSION.RELEASE ?: "")
        ret.put("sdkInt", Build.VERSION.SDK_INT)
        ret.put("model", Build.MODEL ?: "")
        ret.put("manufacturer", Build.MANUFACTURER ?: "")
        ret.put("securityPatch", Build.VERSION.SECURITY_PATCH ?: "")
        try {
            val km = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            ret.put("screenLock", km.isDeviceSecure)
        } catch (e: Exception) {
            Log.w(TAG, "keyguard state unavailable", e)
        }
        ret.put("developerOptions", Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
        ret.put("usbDebugging", Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1)
        try {
            val dpm = activity.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val status = dpm.storageEncryptionStatus
            ret.put(
                "storageEncrypted",
                status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
                    status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
                    status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
            )
        } catch (e: Exception) {
            Log.w(TAG, "encryption state unavailable", e)
        }
        ret.put("notificationsAllowed", NotificationManagerCompat.from(activity).areNotificationsEnabled())
        invoke.resolve(ret)
    }

    // ------------------------------------------------------------- protection

    @Command
    fun startProtection(invoke: Invoke) {
        val args = invoke.parseArgs(ProtectionArgs::class.java)
        try {
            val prefs = activity.getSharedPreferences(ProtectionService.PREFS, Context.MODE_PRIVATE)
            prefs.edit()
                .putBoolean(ProtectionService.KEY_ENABLED, true)
                .putBoolean(ProtectionService.KEY_WATCH_DOWNLOADS, args.watchDownloads)
                .putBoolean(ProtectionService.KEY_SCAN_INSTALLS, args.scanInstalls)
                .putString(ProtectionService.KEY_DATA_DIR, args.dataDir ?: activity.filesDir.absolutePath)
                .putString(ProtectionService.KEY_TITLE, args.title ?: "")
                .putString(ProtectionService.KEY_TEXT, args.text ?: "")
                .apply()
            val intent = Intent(activity, ProtectionService::class.java)
            ContextCompat.startForegroundService(activity, intent)
            invoke.resolve()
        } catch (e: Exception) {
            Log.e(TAG, "startProtection failed", e)
            invoke.reject(e.message ?: "Cannot start protection service")
        }
    }

    @Command
    fun stopProtection(invoke: Invoke) {
        try {
            activity.getSharedPreferences(ProtectionService.PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(ProtectionService.KEY_ENABLED, false).apply()
            activity.stopService(Intent(activity, ProtectionService::class.java))
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Cannot stop protection service")
        }
    }

    @Command
    fun protectionStatus(invoke: Invoke) {
        val ret = JSObject()
        ret.put("running", ProtectionService.running)
        invoke.resolve(ret)
    }

    // ------------------------------------------------------------ file picker

    @Command
    fun pickFile(invoke: Invoke) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        startActivityForResult(invoke, intent, "onFilePicked")
    }

    @ActivityCallback
    fun onFilePicked(invoke: Invoke, result: ActivityResult) {
        val uri = result.data?.data
        if (result.resultCode != Activity.RESULT_OK || uri == null) {
            val ret = JSObject()
            ret.put("cancelled", true)
            invoke.resolve(ret)
            return
        }
        Thread {
            try {
                val name = displayName(uri) ?: "file"
                val dir = File(activity.cacheDir, "scan-imports")
                dir.mkdirs()
                val safe = name.replace(Regex("[^A-Za-z0-9._ -]"), "_").take(120)
                val dest = File(dir, System.currentTimeMillis().toString() + "_" + safe)
                activity.contentResolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                } ?: throw IllegalStateException("Cannot open the selected file")
                val ret = JSObject()
                ret.put("cancelled", false)
                ret.put("path", dest.absolutePath)
                ret.put("name", name)
                invoke.resolve(ret)
            } catch (e: Exception) {
                invoke.reject(e.message ?: "Cannot read the selected file")
            }
        }.start()
    }

    // ---------------------------------------------------------------- helpers

    private fun displayName(uri: Uri): String? {
        activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) return c.getString(idx)
            }
        }
        return uri.lastPathSegment
    }

    private fun installerOf(pm: PackageManager, pkg: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkg).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkg)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun iconBase64(pm: PackageManager, ai: ApplicationInfo): String? {
        return try {
            val drawable = pm.getApplicationIcon(ai)
            val bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, ICON_SIZE, ICON_SIZE)
            drawable.draw(canvas)
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            bitmap.recycle()
            Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }
}

/** True when the app can read shared storage created by other apps. */
fun hasStorageAccess(context: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Environment.isExternalStorageManager()
    } else {
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED
    }
}
