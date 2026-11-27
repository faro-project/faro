package org.faro.android

/**
 * Which foreground packages may show a FLAG_SECURE window without it being tamper: the system's own
 * UI. Everything else, browsers included, is not exempt.
 */
object SecureWindowPolicy {
    private val system = setOf(
        "android",
        "com.android.systemui",
        "com.android.keyguard",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        // Credential prompts (PIN, password, fingerprint) are shown by the settings app.
        "com.android.settings",
    )

    fun isSystemExempt(pkg: String?): Boolean = pkg != null && pkg in system
}
