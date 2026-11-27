package org.faro.android

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle

/**
 * The guided setup after enrollment: one missing permission at a time, with what it is for. Each step
 * only turns something on; nothing here can turn monitoring off.
 */
class SetupActivity : Activity() {
    private lateinit var screen: Screen

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        screen = Screen(this)
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    override fun onRequestPermissionsResult(code: Int, permissions: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(code, permissions, results)
        render()
    }

    private fun render() {
        val state = Permissions.state(this)
        val step = state.nextStep()
        screen.clear()
        if (step == null) {
            MonitorService.start(this)
            screen.title(getString(R.string.setup_done_title))
            screen.body(getString(R.string.setup_done_body))
            screen.button(getString(R.string.setup_done_button)) {
                startActivity(Intent(this, StatusActivity::class.java))
                finish()
            }
            return
        }
        val total = SetupStep.entries.size
        val done = total - listOf(state.notifications, state.accessibility, state.deviceAdmin, state.batteryExempt)
            .count { !it }
        screen.small(getString(R.string.setup_progress, done, total))
        when (step) {
            SetupStep.NOTIFICATIONS -> {
                screen.title(getString(R.string.setup_notifications_title))
                screen.body(getString(R.string.setup_notifications_body))
                screen.button(getString(R.string.setup_notifications_button)) { askNotifications() }
                screen.button(getString(R.string.setup_notifications_settings)) {
                    SetupActions.openNotificationSettings(this)
                }
            }
            SetupStep.ACCESSIBILITY -> {
                screen.title(getString(R.string.setup_accessibility_title))
                screen.body(getString(R.string.setup_accessibility_body))
                screen.button(getString(R.string.setup_accessibility_settings)) { SetupActions.openAccessibility(this) }
                screen.button(getString(R.string.setup_accessibility_app_info)) { SetupActions.openAppInfo(this) }
            }
            SetupStep.DEVICE_ADMIN -> {
                screen.title(getString(R.string.setup_admin_title))
                screen.body(getString(R.string.setup_admin_body))
                screen.button(getString(R.string.setup_admin_button)) { SetupActions.requestAdmin(this) }
            }
            SetupStep.BATTERY -> {
                screen.title(getString(R.string.setup_battery_title))
                screen.body(getString(R.string.setup_battery_body))
                screen.button(getString(R.string.setup_battery_button)) { SetupActions.requestBattery(this) }
            }
        }
    }

    private fun askNotifications() {
        val canAsk = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            (shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) || !askedBefore())
        if (canAsk) {
            markAsked()
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        } else {
            // Refused for good (or switched off in Settings): only Settings can turn it on.
            SetupActions.openNotificationSettings(this)
        }
    }

    private fun askedBefore() = getPreferences(Context.MODE_PRIVATE).getBoolean("asked_notifications", false)

    private fun markAsked() = getPreferences(Context.MODE_PRIVATE).edit().putBoolean("asked_notifications", true).apply()

    companion object {
        private const val REQUEST_NOTIFICATIONS = 1

        fun intent(context: Context): Intent = Intent(context, SetupActivity::class.java)
    }
}
