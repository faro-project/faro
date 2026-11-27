package org.faro.android

import java.net.URLEncoder

/**
 * Turns what the member pasted into the `faro://enroll?i=<instance>&c=<code>` link the Rust core
 * parses (the same fields as the desktop agent's enrollment window): either a whole link, or an
 * instance address plus the code the web app shows.
 */
object EnrollLink {
    sealed class Built {
        data class Link(val link: String) : Built()
        data object NeedLink : Built()
        data object NeedCode : Built()
    }

    fun build(first: String, second: String): Built {
        val a = first.trim()
        val code = second.trim()
        if (a.isEmpty()) return Built.NeedLink
        if (a.startsWith("faro:", ignoreCase = true)) return Built.Link(a)
        if (code.isEmpty()) return Built.NeedCode
        val instance = (if (a.contains("://")) a else "https://$a").trimEnd('/')
        return Built.Link("faro://enroll?i=${enc(instance)}&c=${enc(code.uppercase())}")
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}
