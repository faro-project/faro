package org.faro.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OriginReducerTest {
    private fun r(s: String?) = OriginReducer.reduce(s)

    @Test fun fullUrlLosesPathQueryFragment() {
        assertEquals("https://example.com/", r("https://example.com/a/b?q=1#frag"))
        assertEquals("http://example.com/", r("http://example.com?x=1"))
        assertEquals("https://example.com/", r("https://example.com#top"))
    }

    @Test fun portsAreDropped() {
        assertEquals("https://example.com/", r("https://example.com:8443/x"))
        assertEquals("http://localhost/", r("http://localhost:3000"))
        assertEquals("https://example.com/", r("example.com:8080/path"))
    }

    @Test fun badPortsAreGarbage() {
        assertNull(r("https://example.com:abc/"))
        assertNull(r("https://example.com:99999/"))
    }

    @Test fun userinfoIsStripped() {
        assertEquals("https://example.com/", r("https://user:pw@example.com/x"))
        assertEquals("https://example.com/", r("https://a@b@example.com:81/x"))
        assertNull(r("mailto:someone@example.com"))
    }

    @Test fun missingSchemeIsHttps() {
        assertEquals("https://example.com/", r("example.com"))
        assertEquals("https://example.com/", r("example.com/a?b"))
        assertEquals("https://example.com/", r("//example.com/x"))
    }

    @Test fun hostIsLowerCasedAndTrailingDotRemoved() {
        assertEquals("https://example.com/", r("HTTPS://Example.COM./X"))
    }

    @Test fun idnBecomesPunycode() {
        assertEquals("https://xn--bcher-kva.example/", r("https://bücher.example/seite"))
        assertEquals("https://xn--80ak6aa92e.com/", r("аррӏе.com"))
    }

    @Test fun ipLiterals() {
        assertEquals("http://192.168.0.1/", r("http://192.168.0.1:8080/admin"))
        assertEquals("http://[::1]/", r("http://[::1]:8080/"))
    }

    @Test fun otherSchemesAreNotWebAddresses() {
        assertNull(r("chrome://newtab"))
        assertNull(r("about:blank"))
        assertNull(r("file:///etc/passwd"))
        assertNull(r("javascript:alert(1)"))
        assertNull(r("ftp://example.com/"))
    }

    @Test fun searchTermsAndPlaceholdersAreGarbage() {
        assertNull(r("Search or type web address"))
        assertNull(r("hello"))
        assertNull(r("what is faro?"))
        assertNull(r(""))
        assertNull(r("   "))
        assertNull(r(null))
    }

    @Test fun garbageIsNull() {
        assertNull(r("https://"))
        assertNull(r("https:///path"))
        assertNull(r("http://exa mple.com/"))
        assertNull(r("http://-bad-.com/"))
        assertNull(r("http://[::1/"))
        assertNull(r("https://exa\u0000mple.com/"))
        assertNull(r("a".repeat(3000)))
    }

    @Test fun neverContainsMoreThanSchemeAndHost() {
        val out = r("https://user:secret@Example.com:444/private/path?token=abc#x")!!
        assertEquals("https://example.com/", out)
    }
}
