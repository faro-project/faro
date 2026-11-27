package org.faro.android

import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import org.faro.core.AndroidTamper
import kotlin.concurrent.thread

/** Starts the monitor again after a reboot and after Faro itself is updated. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> MonitorService.start(context)
        }
    }
}

/**
 * Faro is a device administrator only so that its removal is never silent: Android lets an admin app
 * be uninstalled only after it has been deactivated, and both steps tell the member's allies.
 */
class FaroDeviceAdminReceiver : DeviceAdminReceiver() {
    /** The member opened "deactivate": tell the allies now, then let the system show our warning. */
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        reportAndWait(context, AndroidTamper.DeviceAdminDisableRequested, BOUND_MS)
        return context.getString(R.string.admin_disable_warning)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        val pending = goAsync()
        val app = context.applicationContext
        thread(name = "faro-admin-disabled") {
            try {
                report(app, AndroidTamper.DeviceAdminDisableRequested)
            } finally {
                pending.finish()
            }
        }
    }

    /** Reports on another thread (the core may use the network) and waits at most [ms]. */
    private fun reportAndWait(context: Context, signal: AndroidTamper, ms: Long) {
        val app = context.applicationContext
        val t = thread(name = "faro-admin-report") { report(app, signal) }
        try {
            t.join(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun report(app: Context, signal: AndroidTamper) {
        try {
            FaroCore.get(app).reportTamperNow(signal)
        } catch (e: Exception) {
            Log.w("FaroAdmin", "could not report: ${e.javaClass.simpleName}")
        }
    }

    private companion object {
        // A broadcast must finish within about 10 s; the core's own budget is about 5 s.
        const val BOUND_MS = 5_500L
    }
}
