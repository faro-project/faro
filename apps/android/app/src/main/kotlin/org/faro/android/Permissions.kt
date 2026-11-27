package org.faro.android

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.PowerManager
import android.provider.Settings
import android.text.TextUtils
import androidx.core.app.NotificationManagerCompat

/** What Faro is currently allowed to do, read from the system. */
object Permissions {
    fun adminComponent(context: Context) = ComponentName(context, FaroDeviceAdminReceiver::class.java)

    fun accessibilityComponent(context: Context) = ComponentName(context, FaroAccessibilityService::class.java)

    fun state(context: Context): SetupState = SetupState(
        notifications = NotificationManagerCompat.from(context).areNotificationsEnabled(),
        accessibility = isAccessibilityEnabled(context),
        deviceAdmin = context.getSystemService(DevicePolicyManager::class.java)
            .isAdminActive(adminComponent(context)),
        batteryExempt = isBatteryExempt(context),
    )

    fun isBatteryExempt(context: Context): Boolean =
        context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName)

    /** Switched on in Settings (it may still be a moment from being connected). */
    fun isAccessibilityEnabled(context: Context): Boolean {
        if (FaroAccessibilityService.instance != null) return true
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        val mine = accessibilityComponent(context)
        val splitter = TextUtils.SimpleStringSplitter(':').apply { setString(enabled) }
        while (splitter.hasNext()) {
            if (ComponentName.unflattenFromString(splitter.next()) == mine) return true
        }
        return false
    }
}
