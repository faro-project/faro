package org.faro.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * A full-screen notice from Faro (`show_notice`), such as the monthly list of the member's allies. A
 * window with an OK button, not only a notification, so Focus modes can't silently drop it. It stays
 * pending until the member taps OK.
 */
class NoticeActivity : Activity() {
    private lateinit var screen: Screen

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        screen = Screen(this)
        render()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        render()
    }

    private fun render() {
        screen.clear()
        val notices = NoticeStore.pending(this)
        screen.title(getString(R.string.notice_title))
        if (notices.isEmpty()) {
            finish()
            return
        }
        notices.forEach { screen.body(it) }
        screen.button(getString(R.string.notice_ok)) {
            NoticeStore.clear(this)
            finish()
        }
    }
}
