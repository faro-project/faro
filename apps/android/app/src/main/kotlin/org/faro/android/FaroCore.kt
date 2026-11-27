package org.faro.android

import android.content.Context
import org.faro.core.FaroAndroid
import java.io.File

/**
 * The one [FaroAndroid] (the Rust core) of this process. [MonitorService] drives it; the activities
 * and receivers use the same instance. Creating it reads the state directory, so call [get] from a
 * worker thread.
 */
object FaroCore {
    private var instance: FaroAndroid? = null

    @Synchronized
    fun get(context: Context): FaroAndroid {
        instance?.let { return it }
        val app = context.applicationContext
        // Keys and the outbox live in app-private storage that is excluded from backups.
        val dir = File(app.noBackupFilesDir, "faro").apply { mkdirs() }
        val platform = AndroidPlatformBridge(app)
        // The packaged image model (if the APK has one) goes where the core looks for it before the
        // core opens; the core treats a model missing or changed from here on as tamper.
        val modelPackaged = ModelAssets.install(app, dir)
        return FaroAndroid(dir.absolutePath, platform, modelPackaged).also { instance = it }
    }
}
