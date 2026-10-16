package com.webnetkz.seccom.device

import android.util.Log

/**
 * JNI bridge into the Rust scanning engine (implemented in the app library,
 * see `app/src-tauri/src/platform/android.rs`).
 */
object NativeBridge {
    private const val TAG = "SecComNative"
    private const val LIBRARY = "seccom_app_lib"

    @Volatile
    private var loaded = false

    @Synchronized
    private fun load(): Boolean {
        if (!loaded) {
            try {
                System.loadLibrary(LIBRARY)
                loaded = true
            } catch (e: Throwable) {
                Log.e(TAG, "cannot load $LIBRARY", e)
            }
        }
        return loaded
    }

    @JvmStatic
    private external fun nativeInit(dataDir: String): Boolean

    @JvmStatic
    private external fun nativeScanFile(path: String, source: String): String

    /** Loads the signature database (no-op when the app already did). */
    fun ensureInit(dataDir: String): Boolean {
        return try {
            load() && nativeInit(dataDir)
        } catch (e: Throwable) {
            Log.e(TAG, "native init failed", e)
            false
        }
    }

    /** Scans a file; returns a JSON object `{threat, name, verdict, path}`. */
    fun scanFile(path: String, source: String): String {
        return try {
            if (load()) nativeScanFile(path, source) else "{}"
        } catch (e: Throwable) {
            Log.e(TAG, "native scan failed", e)
            "{}"
        }
    }
}
