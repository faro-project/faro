package org.faro.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import java.util.concurrent.Executors

/**
 * The launcher screen: what Faro is doing, and the fix for a problem. State only, like the desktop
 * status menu. Nothing here stops, pauses or hides monitoring.
 */
class StatusActivity : Activity() {
    private lateinit var screen: Screen
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "faro-status").apply { isDaemon = true } }

    private class Snapshot(
        val headline: String,
        val detail: String?,
        val enrolled: Boolean,
        val coreProblem: String?,
        val setup: SetupState,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        screen = Screen(this)
        screen.title(getString(R.string.status_loading))
        MonitorService.start(this)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun refresh() {
        worker.execute {
            val snapshot = try {
                val s = FaroCore.get(this).status()
                Snapshot(s.headline, s.detail, s.enrolled, s.problem, Permissions.state(this))
            } catch (e: Exception) {
                null
            }
            runOnUiThread { if (!isDestroyed) render(snapshot) }
        }
    }

    private fun render(s: Snapshot?) {
        screen.clear()
        if (s == null) {
            screen.title(getString(R.string.status_unavailable_title))
            screen.body(getString(R.string.status_unavailable_detail))
            addFooter()
            return
        }
        screen.title(s.headline)
        val fix = FixChooser.fixFor(s.enrolled, s.setup)
        screen.body(s.detail ?: s.coreProblem ?: getString(R.string.status_nothing_to_do))
        if (s.enrolled && s.coreProblem != null && s.detail != null) screen.body(s.coreProblem)

        when (fix) {
            Fix.Enroll -> screen.button(getString(R.string.status_enroll)) {
                startActivity(Intent(this, EnrollActivity::class.java))
            }
            is Fix.Setup -> {
                screen.body(SetupActions.problemText(this, fix.step))
                screen.button(SetupActions.fixLabel(this, fix.step)) { SetupActions.launch(this, fix.step) }
            }
            null -> Unit
        }

        if (NoticeStore.pending(this).isNotEmpty()) {
            screen.body(getString(R.string.status_unread_notice))
            screen.button(getString(R.string.status_read_notice)) {
                startActivity(Notifications.noticeIntent(this))
            }
        }
        addFooter()
    }

    private fun addFooter() {
        screen.small(getString(R.string.status_state_only))
        screen.button(getString(R.string.status_about)) { startActivity(Intent(this, AboutActivity::class.java)) }
    }
}
