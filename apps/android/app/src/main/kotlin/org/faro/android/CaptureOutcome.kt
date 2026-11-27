package org.faro.android

/** What one screenshot attempt came to. Independent of the generated Rust bindings. */
sealed class CaptureOutcome {
    /** [rgba] is tightly packed RGBA8888, `width * height * 4` bytes. The caller zeroes it when done. */
    class Frame(val width: Int, val height: Int, val rgba: ByteArray) : CaptureOutcome() {
        // Never print pixels.
        override fun toString() = "Frame(${width}x$height)"
    }

    /** A FLAG_SECURE window is in front of the app [pkg]. */
    data class Secure(val pkg: String) : CaptureOutcome()

    /** The accessibility service isn't allowed to take screenshots (or isn't connected). */
    data object Denied : CaptureOutcome()

    /** Rate limited, display off, an internal error. */
    data class Unavailable(val reason: String) : CaptureOutcome()
}

/** The active browser tab, with the address already reduced to `scheme://host/`. */
data class BrowserObservation(val browserPackage: String, val origin: String, val incognito: Boolean)
