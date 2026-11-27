package org.faro.android

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import org.faro.core.AndroidPlatform
import org.faro.core.AndroidTamper
import org.faro.core.BrowserTab
import org.faro.core.CaptureException
import org.faro.core.CapturedFrame
import org.faro.core.ForegroundApp
import org.faro.core.PermissionState
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * What the Rust core asks of the phone. Every call arrives on a Rust worker thread, never the main
 * thread, so blocking on the accessibility service is fine.
 */
class AndroidPlatformBridge(private val context: Context) : AndroidPlatform {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    private val tamper = TamperQueue<AndroidTamper>()
    private val startedAt = SystemClock.elapsedRealtime()
    private var missingSince = 0L

    // A frame's array is zeroed shortly after it has been handed over (the generated code copies it
    // into Rust memory before the call returns), so no pixels linger on the Kotlin heap.
    private val zeroer = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "faro-zero").apply { isDaemon = true }
    }

    override fun captureScreen(): CapturedFrame {
        val service = FaroAccessibilityService.instance ?: throw CaptureException.PermissionDenied()
        if (keyguard.isKeyguardLocked) throw CaptureException.Unavailable("screen locked")
        return when (val outcome = service.capture()) {
            is CaptureOutcome.Frame -> {
                zeroer.schedule({ outcome.rgba.fill(0) }, ZERO_AFTER_MS, TimeUnit.MILLISECONDS)
                CapturedFrame(outcome.width.toUInt(), outcome.height.toUInt(), outcome.rgba)
            }
            is CaptureOutcome.Secure -> {
                // The system's own UI may be secure (credential prompts); anything else is not allowed to be.
                if (SecureWindowPolicy.isSystemExempt(outcome.pkg)) {
                    throw CaptureException.Unavailable("system window")
                }
                throw CaptureException.SecureWindow(outcome.pkg)
            }
            CaptureOutcome.Denied -> throw CaptureException.PermissionDenied()
            is CaptureOutcome.Unavailable -> throw CaptureException.Unavailable(outcome.reason)
        }
    }

    override fun permissionState(): PermissionState = when {
        FaroAccessibilityService.instance != null -> PermissionState.GRANTED
        // Switched on in Settings but not connected yet (just booted or restarted).
        Permissions.isAccessibilityEnabled(context) -> PermissionState.NOT_DETERMINED
        else -> PermissionState.DENIED
    }

    override fun foregroundApp(): ForegroundApp? {
        val service = FaroAccessibilityService.instance ?: return null
        val pkg = service.foregroundPackage() ?: return null
        return ForegroundApp(pkg, service.labelFor(pkg))
    }

    override fun browser(): BrowserTab? {
        val tab = FaroAccessibilityService.instance?.browserTab() ?: return null
        return BrowserTab(tab.browserPackage, tab.origin, tab.incognito)
    }

    override fun idleSecs(): ULong {
        val service = FaroAccessibilityService.instance ?: return 0uL
        return (service.idleMillis() / 1000).coerceAtLeast(0).toULong()
    }

    override fun isLocked(): Boolean = keyguard.isKeyguardLocked

    override fun displayAsleep(): Boolean = !power.isInteractive

    override fun pollTamper(): List<AndroidTamper> {
        val now = SystemClock.elapsedRealtime()
        // Right after a boot or an update the service takes a moment to connect: don't call that tamper.
        val connected = FaroAccessibilityService.instance != null
        if (connected) {
            missingSince = 0L
        } else if (missingSince == 0L) {
            missingSince = maxOf(now, startedAt)
        }
        val off = !connected && now - missingSince >= ACCESSIBILITY_GRACE_MS
        tamper.level("accessibility", off, AndroidTamper.AccessibilityDisabled)

        val batteryOptimised = !Permissions.isBatteryExempt(context)
        tamper.level("battery", batteryOptimised, AndroidTamper.BatteryOptimizationOn)

        val adb = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        tamper.level("usb", adb, AndroidTamper.UsbDebuggingOn)

        return tamper.drain()
    }

    override fun showNotice(text: String) {
        NoticeStore.show(context, text)
    }

    private companion object {
        const val ZERO_AFTER_MS = 2_000L
        const val ACCESSIBILITY_GRACE_MS = 20_000L
    }
}
