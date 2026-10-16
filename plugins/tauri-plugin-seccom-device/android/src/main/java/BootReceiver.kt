package com.webnetkz.seccom.device

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

/** Restarts real-time protection after a reboot or an app update. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val prefs = context.getSharedPreferences(ProtectionService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(ProtectionService.KEY_ENABLED, false)) return
        try {
            ContextCompat.startForegroundService(context, Intent(context, ProtectionService::class.java))
        } catch (e: Exception) {
            Log.w("SecComBoot", "cannot restart protection", e)
        }
    }
}
