package org.faro.android

import java.net.IDN
import java.util.Locale

/**
 * Reduces what a browser's address bar shows to `scheme://host/`, the only form of a web address
 * that leaves this app (ARCHITECTURE.md section 3.5): no path, query, fragment, port or userinfo.
 *
 * Pure Kotlin with no Android dependency, so it is unit-tested on the JVM. It never logs.
 */
object OriginReducer {
    private const val MAX_LEN = 2048
    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+.-]*)://")
    private val LABELS = Regex("^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")
    private val IPV6 = Regex("^\[[0-9a-fA-F:.]+]$")

    /** The origin of [text] as `scheme://host/`, or null when it isn't a web address. */
    fun reduce(text: CharSequence?): String? {
        val raw = text?.toString()?.trim() ?: return null
        if (raw.isEmpty() || raw.length > MAX_LEN || raw.any { it.isWhitespace() || it.isISOControl() }) {
            return null
        }

        var rest = raw
        var scheme = "https"
        var hadScheme = false
        val m = SCHEME.find(rest)
        if (m != null) {
            scheme = m.groupValues[1].lowercase(Locale.ROOT)
            if (scheme != "http" && scheme != "https") return null
            rest = rest.substring(m.value.length)
            hadScheme = true
        } else if (rest.startsWith("//")) {
            rest = rest.substring(2)
        }

        val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
        var authority = if (end < 0) rest else rest.substring(0, end)

        val at = authority.lastIndexOf('@')
        if (at >= 0) {
            // "mailto:a@b" and the like are not addresses; a real userinfo needs an explicit scheme.
            if (!hadScheme) return null
            authority = authority.substring(at + 1)
        }

        val host: String
        if (authority.startsWith("[")) {
            val close = authority.indexOf(']')
            if (close < 0) return null
            host = authority.substring(0, close + 1)
            if (!validPort(authority.substring(close + 1))) return null
            if (!IPV6.matches(host)) return null
            return "$scheme://${host.lowercase(Locale.ROOT)}/"
        }
        val colon = authority.indexOf(':')
        host = if (colon < 0) authority else authority.substring(0, colon)
        if (colon >= 0 && !validPort(authority.substring(colon))) return null

        val ascii = toAsciiHost(host) ?: return null
        // A bare word is a search, not an address; "localhost" is the exception.
        if (!ascii.contains('.') && ascii != "localhost") return null
        return "$scheme://$ascii/"
    }

    /** The host as lower-case ASCII (punycode for an IDN), or null if it isn't a valid host name. */
    private fun toAsciiHost(host: String): String? {
        var h = host.trimEnd('.')
        if (h.isEmpty()) return null
        h = try {
            IDN.toASCII(h, IDN.ALLOW_UNASSIGNED)
        } catch (_: IllegalArgumentException) {
            return null
        }
        h = h.lowercase(Locale.ROOT)
        if (h.length > 253 || !LABELS.matches(h)) return null
        return h
    }

    /** [s] is empty, or ":" followed by up to five digits. */
    private fun validPort(s: String): Boolean {
        if (s.isEmpty()) return true
        if (s[0] != ':') return false
        val digits = s.substring(1)
        return digits.isEmpty() || (digits.length <= 5 && digits.all { it in '0'..'9' } && digits.toInt() <= 65535)
    }
}
