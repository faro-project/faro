package org.faro.android

import java.util.Locale

/**
 * Where each known browser keeps its address bar, by view id, and how some of them show a private
 * tab. Best effort: browsers rename views between releases, and an unknown browser simply yields no
 * tab. Pure Kotlin so the table is unit-tested.
 */
object BrowserAddressBars {
    /** `{pkg}` stands for the browser's own package name. */
    private val chromium = listOf("{pkg}:id/url_bar")
    private val firefox = listOf(
        "{pkg}:id/mozac_browser_toolbar_url_view",
        "{pkg}:id/url_bar_title",
        "{pkg}:id/display_url",
    )

    private val byPackage: Map<String, List<String>> = buildMap {
        // Chrome and its variants, other Chromium builds, Brave, Edge, Vivaldi.
        for (p in listOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary",
            "org.chromium.chrome", "com.google.android.apps.chrome",
            "com.brave.browser", "com.brave.browser_beta", "com.brave.browser_nightly",
            "com.microsoft.emmx", "com.microsoft.emmx.beta", "com.microsoft.emmx.dev",
            "com.microsoft.emmx.canary",
            "com.vivaldi.browser", "com.vivaldi.browser.snapshot",
        )) put(p, chromium)
        // Firefox, Focus and the forks.
        for (p in listOf(
            "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix",
            "org.mozilla.fenix.debug", "org.mozilla.focus", "org.mozilla.klar",
            "org.mozilla.fennec_fdroid", "org.mozilla.reference.browser",
            "us.spotco.fennec_dos", "io.github.forkmaintainers.iceraven",
            "org.torproject.torbrowser",
        )) put(p, firefox)
        // Samsung Internet.
        for (p in listOf("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta")) {
            put(p, listOf("{pkg}:id/location_bar_edit_text"))
        }
        // Opera.
        for (p in listOf("com.opera.browser", "com.opera.browser.beta", "com.opera.mini.native")) {
            put(p, listOf("{pkg}:id/url_field"))
        }
        // DuckDuckGo.
        put("com.duckduckgo.mobile.android", listOf("{pkg}:id/omnibarTextInput"))
    }

    fun isBrowser(pkg: String): Boolean = byPackage.containsKey(pkg)

    /** The address-bar view ids to look for in [pkg], most likely first; empty for an unknown app. */
    fun viewIds(pkg: String): List<String> =
        byPackage[pkg]?.map { it.replace("{pkg}", pkg) } ?: emptyList()

    private val incognitoWords = listOf(
        "incognito", "private tab", "private browsing", "inprivate", "secret mode",
    )

    /** True if a view's content description or text says the tab is private. */
    fun looksPrivate(description: CharSequence?): Boolean {
        val d = description?.toString()?.lowercase(Locale.ROOT) ?: return false
        return incognitoWords.any { d.contains(it) }
    }
}
