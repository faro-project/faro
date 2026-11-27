package org.faro.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FrameMathTest {
    @Test fun smallFramesAreKept() {
        assertEquals(400 to 700, FrameMath.targetSize(400, 700))
        assertEquals(768 to 768, FrameMath.targetSize(768, 768))
    }

    @Test fun longestSideBecomes768() {
        assertEquals(346 to 768, FrameMath.targetSize(1080, 2400))
        assertEquals(768 to 346, FrameMath.targetSize(2400, 1080))
        assertEquals(768 to 1, FrameMath.targetSize(100000, 100))
    }

    @Test fun blankDetection() {
        val black = ByteArray(10 * 10 * 4) // only colour is checked, not alpha
        assertTrue(FrameMath.looksBlank(black, 10, 10))
        val lit = ByteArray(10 * 10 * 4) { 200.toByte() }
        assertFalse(FrameMath.looksBlank(lit, 10, 10))
        assertFalse(FrameMath.looksBlank(ByteArray(3), 10, 10)) // too short is never "blank"
    }
}

class BrowserAddressBarsTest {
    @Test fun knownBrowsers() {
        assertEquals(listOf("com.android.chrome:id/url_bar"), BrowserAddressBars.viewIds("com.android.chrome"))
        assertEquals(listOf("com.brave.browser:id/url_bar"), BrowserAddressBars.viewIds("com.brave.browser"))
        assertTrue(BrowserAddressBars.viewIds("org.mozilla.fenix").first().startsWith("org.mozilla.fenix:id/"))
        assertTrue(BrowserAddressBars.isBrowser("com.sec.android.app.sbrowser"))
        assertTrue(BrowserAddressBars.isBrowser("com.duckduckgo.mobile.android"))
    }

    @Test fun unknownAppsHaveNoAddressBar() {
        assertFalse(BrowserAddressBars.isBrowser("com.example.game"))
        assertEquals(emptyList<String>(), BrowserAddressBars.viewIds("com.example.game"))
    }

    @Test fun privateTabWords() {
        assertTrue(BrowserAddressBars.looksPrivate("Incognito tab"))
        assertTrue(BrowserAddressBars.looksPrivate("InPrivate"))
        assertTrue(BrowserAddressBars.looksPrivate("Private browsing"))
        assertFalse(BrowserAddressBars.looksPrivate("Home"))
        assertFalse(BrowserAddressBars.looksPrivate(null))
    }
}

class SecureWindowPolicyTest {
    @Test fun systemUiIsExemptAppsAreNot() {
        assertTrue(SecureWindowPolicy.isSystemExempt("com.android.systemui"))
        assertTrue(SecureWindowPolicy.isSystemExempt("android"))
        assertFalse(SecureWindowPolicy.isSystemExempt("com.android.chrome"))
        assertFalse(SecureWindowPolicy.isSystemExempt("org.mozilla.firefox"))
        assertFalse(SecureWindowPolicy.isSystemExempt(null))
    }
}

class TamperQueueTest {
    @Test fun oneOffSignalsAreDrainedOnceAndNotDuplicated() {
        val q = TamperQueue<String>()
        q.offer("a"); q.offer("a"); q.offer("b")
        assertEquals(listOf("a", "b"), q.drain())
        assertEquals(emptyList<String>(), q.drain())
    }

    @Test fun levelFiresOnTheEdgeOnly() {
        val q = TamperQueue<String>()
        q.level("usb", true, "usb")
        assertEquals(listOf("usb"), q.drain())
        q.level("usb", true, "usb")
        assertEquals(emptyList<String>(), q.drain())
        q.level("usb", false, "usb")
        q.level("usb", true, "usb")
        assertEquals(listOf("usb"), q.drain())
    }
}

class SetupStepsTest {
    private val all = SetupState(true, true, true, true)

    @Test fun nothingMissing() {
        assertNull(all.nextStep())
        assertNull(FixChooser.fixFor(true, all))
    }

    @Test fun asksInOrder() {
        assertEquals(SetupStep.NOTIFICATIONS, all.copy(notifications = false, accessibility = false).nextStep())
        assertEquals(SetupStep.ACCESSIBILITY, all.copy(accessibility = false, deviceAdmin = false).nextStep())
        assertEquals(SetupStep.DEVICE_ADMIN, all.copy(deviceAdmin = false, batteryExempt = false).nextStep())
        assertEquals(SetupStep.BATTERY, all.copy(batteryExempt = false).nextStep())
    }

    @Test fun notEnrolledFixIsEnroll() {
        assertEquals(Fix.Enroll, FixChooser.fixFor(false, all))
        assertEquals(Fix.Setup(SetupStep.BATTERY), FixChooser.fixFor(true, all.copy(batteryExempt = false)))
    }
}

class EnrollLinkTest {
    @Test fun aLinkIsPassedThrough() {
        assertEquals(
            EnrollLink.Built.Link("faro://enroll?i=x&c=y"),
            EnrollLink.build(" faro://enroll?i=x&c=y ", ""),
        )
    }

    @Test fun addressAndCodeMakeALink() {
        assertEquals(
            EnrollLink.Built.Link("faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=7Q2K-M9XD"),
            EnrollLink.build("faro.example.org/", "7q2k-m9xd"),
        )
        assertEquals(
            EnrollLink.Built.Link("faro://enroll?i=http%3A%2F%2F10.0.0.2%3A8080&c=ABCD-1234"),
            EnrollLink.build("http://10.0.0.2:8080", "ABCD-1234"),
        )
    }

    @Test fun missingPieces() {
        assertEquals(EnrollLink.Built.NeedLink, EnrollLink.build("  ", "x"))
        assertEquals(EnrollLink.Built.NeedCode, EnrollLink.build("faro.example.org", " "))
    }
}
