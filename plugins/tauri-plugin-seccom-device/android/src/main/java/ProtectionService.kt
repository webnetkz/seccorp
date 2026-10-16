package com.webnetkz.seccom.device

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Foreground service providing real-time protection on Android:
 *  - scans every newly installed or updated app (its APK);
 *  - scans files that finish downloading into the Download folder.
 * Scanning happens in the Rust engine through [NativeBridge].
 */
class ProtectionService : Service() {

    companion object {
        const val PREFS = "seccom_device"
        const val KEY_ENABLED = "protection_enabled"
        const val KEY_WATCH_DOWNLOADS = "watch_downloads"
        const val KEY_SCAN_INSTALLS = "scan_installs"
        const val KEY_DATA_DIR = "data_dir"
        const val KEY_TITLE = "notification_title"
        const val KEY_TEXT = "notification_text"

        private const val TAG = "SecComProtection"
        private const val CHANNEL_STATUS = "seccom_status"
        private const val CHANNEL_ALERTS = "seccom_alerts"
        private const val NOTIFICATION_ID = 7101
        private val TEMP_SUFFIXES = listOf(".crdownload", ".part", ".partial", ".download", ".tmp", ".pending")

        @Volatile
        var running = false
            private set
    }

    private var observer: FileObserver? = null
    private var packageReceiver: BroadcastReceiver? = null
    private var executor: ExecutorService? = null
    private var alertId = 8000

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannels()
        executor = Executors.newSingleThreadExecutor()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val notification = buildStatusNotification(prefs.getString(KEY_TITLE, "") ?: "", prefs.getString(KEY_TEXT, "") ?: "")
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "cannot enter foreground", e)
            stopSelf()
            return START_NOT_STICKY
        }
        running = true

        val dataDir = prefs.getString(KEY_DATA_DIR, null) ?: filesDir.absolutePath
        executor?.execute { NativeBridge.ensureInit(dataDir) }

        if (prefs.getBoolean(KEY_SCAN_INSTALLS, true) && packageReceiver == null) {
            registerPackageReceiver()
        }
        if (prefs.getBoolean(KEY_WATCH_DOWNLOADS, true) && observer == null) {
            startDownloadsObserver()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        observer?.stopWatching()
        observer = null
        packageReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (_: Exception) {
            }
        }
        packageReceiver = null
        executor?.shutdownNow()
        executor = null
        super.onDestroy()
    }

    // ---------------------------------------------------------------- sources

    private fun registerPackageReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false) &&
                    intent.action == Intent.ACTION_PACKAGE_ADDED
                ) {
                    return // a PACKAGE_REPLACED broadcast follows
                }
                val pkg = intent.data?.schemeSpecificPart ?: return
                if (pkg == packageName) return
                executor?.execute { scanPackage(pkg) }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
        packageReceiver = receiver
    }

    @Suppress("DEPRECATION")
    private fun startDownloadsObserver() {
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists()) return
        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO
        val obs = if (Build.VERSION.SDK_INT >= 29) {
            object : FileObserver(dir, mask) {
                override fun onEvent(event: Int, path: String?) = onDownloadEvent(dir, path)
            }
        } else {
            object : FileObserver(dir.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) = onDownloadEvent(dir, path)
            }
        }
        obs.startWatching()
        observer = obs
    }

    private fun onDownloadEvent(dir: File, name: String?) {
        if (name.isNullOrEmpty()) return
        val lower = name.lowercase()
        if (TEMP_SUFFIXES.any { lower.endsWith(it) } || name.startsWith(".")) return
        val file = File(dir, name)
        executor?.execute {
            // Give the downloader a moment to finish renaming/flushing.
            Thread.sleep(500)
            if (file.isFile) handleResult(NativeBridge.scanFile(file.absolutePath, "download"), null)
        }
    }

    private fun scanPackage(pkg: String) {
        try {
            val info = if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(pkg, 0)
            }
            val label = packageManager.getApplicationLabel(info).toString()
            val apk = info.sourceDir ?: return
            handleResult(NativeBridge.scanFile(apk, "install:$pkg"), Pair(pkg, label))
        } catch (e: Exception) {
            Log.w(TAG, "cannot scan package $pkg", e)
        }
    }

    // ---------------------------------------------------------- notifications

    private fun handleResult(json: String, app: Pair<String, String>?) {
        try {
            val r = JSONObject(json)
            if (!r.optBoolean("threat", false)) return
            val threat = r.optString("name", "Threat")
            val path = r.optString("path", "")
            val title = getString(R.string.seccom_threat_title)
            val target = app?.second ?: File(path).name
            postAlert(title, "$target — $threat", app?.first)
        } catch (e: Exception) {
            Log.w(TAG, "bad scan result", e)
        }
    }

    private fun postAlert(title: String, text: String, packageToUninstall: String?) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val builder = NotificationCompat.Builder(this, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_seccom_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
        launchIntent()?.let { builder.setContentIntent(it) }
        if (packageToUninstall != null) {
            val uninstall = Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageToUninstall"))
            uninstall.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val pi = PendingIntent.getActivity(
                this, alertId, uninstall,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(0, getString(R.string.seccom_action_uninstall), pi)
        }
        try {
            nm.notify(alertId++, builder.build())
        } catch (e: SecurityException) {
            Log.w(TAG, "notification permission missing", e)
        }
    }

    private fun launchIntent(): PendingIntent? {
        val intent = packageManager.getLaunchIntentForPackage(packageName) ?: return null
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(this, 1, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun buildStatusNotification(title: String, text: String): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_seccom_shield)
            .setContentTitle(title.ifEmpty { getString(R.string.seccom_status_title) })
            .setContentText(text.ifEmpty { getString(R.string.seccom_status_text) })
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
        launchIntent()?.let { builder.setContentIntent(it) }
        return builder.build()
    }

    private fun createChannels() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, getString(R.string.seccom_channel_status), NotificationManager.IMPORTANCE_LOW)
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, getString(R.string.seccom_channel_alerts), NotificationManager.IMPORTANCE_HIGH)
        )
    }
}
