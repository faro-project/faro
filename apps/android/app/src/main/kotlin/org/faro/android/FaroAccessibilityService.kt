package org.faro.android

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Faro's eyes: screenshots on demand, the app in front, and the address bar of a known browser.
 *
 * Everything here is called by [AndroidPlatformBridge] from the Rust core's worker threads, never
 * from the main thread. Nothing that is read (a URL, a title, a pixel) is ever logged or stored.
 */
class FaroAccessibilityService : AccessibilityService() {
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "faro-capture").apply { isDaemon = true } }
    private val labels = HashMap<String, String?>()

    @Volatile private var trackedPackage: String? = null
    @Volatile private var lastInteractionAt = SystemClock.elapsedRealtime()
    private var lastCaptureAt = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        lastInteractionAt = SystemClock.elapsedRealtime()
        instance = this
        // Start the monitor when the member switches this service on, if the system lets us.
        MonitorService.start(applicationContext)
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        if (instance === this) instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onInterrupt() = Unit

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                event.packageName?.toString()?.let { trackedPackage = it }
            }
            // Something the person did (not the screen changing by itself).
            AccessibilityEvent.TYPE_VIEW_CLICKED,
            AccessibilityEvent.TYPE_VIEW_SCROLLED,
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED,
            AccessibilityEvent.TYPE_TOUCH_INTERACTION_START,
            -> lastInteractionAt = SystemClock.elapsedRealtime()
        }
    }

    fun idleMillis(): Long = SystemClock.elapsedRealtime() - lastInteractionAt

    /** One screenshot, scaled and packed. Blocks up to a few seconds; call from a worker thread. */
    @Synchronized
    fun capture(): CaptureOutcome {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (!power.isInteractive) return CaptureOutcome.Unavailable("display off")

        // The system allows about one screenshot per 333 ms; wait out the rest of the gap.
        val wait = lastCaptureAt + MIN_INTERVAL_MS - SystemClock.elapsedRealtime()
        if (wait > 0) {
            try {
                Thread.sleep(wait)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return CaptureOutcome.Unavailable("interrupted")
            }
        }
        lastCaptureAt = SystemClock.elapsedRealtime()

        val latch = CountDownLatch(1)
        var outcome: CaptureOutcome = CaptureOutcome.Unavailable("no answer")
        try {
            takeScreenshot(
                Display.DEFAULT_DISPLAY,
                executor,
                object : TakeScreenshotCallback {
                    override fun onSuccess(screenshot: ScreenshotResult) {
                        outcome = try {
                            process(screenshot)
                        } catch (e: Exception) {
                            Log.w(TAG, "screenshot processing failed: ${e.javaClass.simpleName}")
                            CaptureOutcome.Unavailable("processing failed")
                        } catch (_: OutOfMemoryError) {
                            CaptureOutcome.Unavailable("out of memory")
                        }
                        latch.countDown()
                    }

                    override fun onFailure(errorCode: Int) {
                        outcome = failure(errorCode)
                        latch.countDown()
                    }
                },
            )
        } catch (e: Exception) {
            return CaptureOutcome.Unavailable("takeScreenshot failed: ${e.javaClass.simpleName}")
        }
        if (!latch.await(CAPTURE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            return CaptureOutcome.Unavailable("timed out")
        }
        return outcome
    }

    private fun failure(code: Int): CaptureOutcome = when (code) {
        ERROR_TAKE_SCREENSHOT_SECURE_WINDOW -> CaptureOutcome.Secure(foregroundPackage() ?: UNKNOWN_PACKAGE)
        ERROR_TAKE_SCREENSHOT_NO_ACCESSIBILITY_ACCESS -> CaptureOutcome.Denied
        ERROR_TAKE_SCREENSHOT_INTERVAL_TIME_SHORT -> CaptureOutcome.Unavailable("rate limited")
        else -> CaptureOutcome.Unavailable("screenshot error $code")
    }

    /**
     * HardwareBuffer to a software bitmap, scaled so the longest side is at most 768, to tightly
     * packed RGBA8888. Every bitmap is recycled and the buffer closed; the intermediate array is
     * zeroed. No pixel is written anywhere.
     */
    private fun process(shot: ScreenshotResult): CaptureOutcome {
        val buffer = shot.hardwareBuffer
        try {
            val hardware = Bitmap.wrapHardwareBuffer(buffer, shot.colorSpace)
                ?: return CaptureOutcome.Unavailable("could not read the screenshot")
            val software = hardware.copy(Bitmap.Config.ARGB_8888, false)
            hardware.recycle()
            if (software == null) return CaptureOutcome.Unavailable("could not copy the screenshot")

            val (w, h) = FrameMath.targetSize(software.width, software.height)
            val scaled = if (w == software.width && h == software.height) {
                software
            } else {
                val s = Bitmap.createScaledBitmap(software, w, h, true)
                software.recycle()
                s
            }
            val rgba = pack(scaled)
            scaled.recycle()

            // Before Android 14 there is no secure-window error: the window is drawn black.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE && FrameMath.looksBlank(rgba, w, h)) {
                rgba.fill(0)
                return CaptureOutcome.Secure(foregroundPackage() ?: UNKNOWN_PACKAGE)
            }
            return CaptureOutcome.Frame(w, h, rgba)
        } finally {
            buffer.close()
        }
    }

    /** The bitmap's pixels, `width * height * 4` bytes with no row padding. */
    private fun pack(bitmap: Bitmap): ByteArray {
        val w = bitmap.width
        val h = bitmap.height
        val raw = ByteBuffer.allocate(bitmap.byteCount)
        bitmap.copyPixelsToBuffer(raw)
        val src = raw.array()
        val tight = w * 4
        if (bitmap.rowBytes == tight && src.size == tight * h) return src
        val out = ByteArray(tight * h)
        for (row in 0 until h) System.arraycopy(src, row * bitmap.rowBytes, out, row * tight, tight)
        src.fill(0)
        return out
    }

    /** The package of the app window the person is using, or null. */
    fun foregroundPackage(): String? {
        activeAppRoot()?.let { root ->
            try {
                root.packageName?.toString()?.let { return it }
            } finally {
                root.recycleCompat()
            }
        }
        return trackedPackage
    }

    fun labelFor(pkg: String): String? = synchronized(labels) {
        labels.getOrPut(pkg) {
            try {
                packageManager.getApplicationInfo(pkg, 0).loadLabel(packageManager).toString()
            } catch (_: PackageManager.NameNotFoundException) {
                null
            }
        }
    }

    /** The active browser tab's origin, or null when a known browser isn't in front. */
    fun browserTab(): BrowserObservation? {
        val root = activeAppRoot() ?: return null
        try {
            val pkg = root.packageName?.toString() ?: return null
            val ids = BrowserAddressBars.viewIds(pkg)
            if (ids.isEmpty()) return null
            var origin: String? = null
            for (id in ids) {
                val nodes = root.findAccessibilityNodeInfosByViewId(id) ?: continue
                for (n in nodes) {
                    if (origin == null) origin = OriginReducer.reduce(n.text)
                    n.recycleCompat()
                }
                if (origin != null) break
            }
            return origin?.let { BrowserObservation(pkg, it, hasPrivateHint(root)) }
        } finally {
            root.recycleCompat()
        }
    }

    /**
     * True if a short label in the window's chrome says "Incognito" or "Private". Only content
     * descriptions and view ids are looked at, never page text, and the walk is bounded.
     */
    private fun hasPrivateHint(root: AccessibilityNodeInfo): Boolean {
        var seen = 0
        val queue = ArrayDeque<Pair<AccessibilityNodeInfo, Int>>()
        queue.add(root to 0)
        var found = false
        while (queue.isNotEmpty()) {
            val (node, depth) = queue.removeFirst()
            if (!found && seen < MAX_NODES) {
                seen++
                val d = node.contentDescription
                if ((d != null && d.length <= 60 && BrowserAddressBars.looksPrivate(d)) ||
                    BrowserAddressBars.looksPrivate(node.viewIdResourceName)
                ) {
                    found = true
                }
                if (!found && depth < MAX_DEPTH) {
                    for (i in 0 until node.childCount) {
                        node.getChild(i)?.let { queue.add(it to depth + 1) }
                    }
                }
            }
            if (node !== root) node.recycleCompat()
        }
        return found
    }

    private fun activeAppRoot(): AccessibilityNodeInfo? {
        val apps = windows.filter { it.type == AccessibilityWindowInfo.TYPE_APPLICATION }
        val window = apps.firstOrNull { it.isActive } ?: apps.firstOrNull { it.isFocused }
        val root = window?.root
        apps.forEach { it.recycleCompat() }
        return root
    }

    companion object {
        private const val TAG = "FaroA11y"
        const val UNKNOWN_PACKAGE = "unknown"
        private const val MIN_INTERVAL_MS = 340L
        private const val CAPTURE_TIMEOUT_MS = 5_000L
        private const val MAX_NODES = 300
        private const val MAX_DEPTH = 8

        /** The connected service, or null when Accessibility is off for Faro. */
        @Volatile
        var instance: FaroAccessibilityService? = null
            private set
    }
}

@Suppress("DEPRECATION")
private fun AccessibilityNodeInfo.recycleCompat() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) recycle()
}

@Suppress("DEPRECATION")
private fun AccessibilityWindowInfo.recycleCompat() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) recycle()
}
