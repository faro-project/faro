package org.faro.android

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.EditText
import org.faro.core.ApprovalState
import org.faro.core.EnrollPreview
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Enrolls this phone: a `faro://enroll?...` link (tapped, or pasted with an address and code), the
 * instance's name for the member to confirm, the device's fingerprint to compare in the web app, then
 * waiting for approval. QR scanning is not here yet (see README.md).
 *
 * The Rust core does the work (`preview_enrollment`, `enroll`, `poll_approval`); these calls use the
 * network, so they run on a worker thread.
 */
class EnrollActivity : Activity() {
    private lateinit var screen: Screen
    private val worker = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "faro-enroll").apply { isDaemon = true }
    }
    private var polling: ScheduledFuture<*>? = null

    /** The link being enrolled with, once the member has pasted or opened one. */
    private var link: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        screen = Screen(this)
        val opened = intent?.data?.takeIf { it.scheme == "faro" }?.toString()
        if (opened != null) preview(opened) else showInput(null, null)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.data?.takeIf { it.scheme == "faro" }?.toString()?.let {
            polling?.cancel(false)
            preview(it)
        }
    }

    override fun onDestroy() {
        polling?.cancel(false)
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun showInput(error: String?, prefill: String?) {
        screen.clear()
        screen.title(getString(R.string.enroll_title))
        screen.body(getString(R.string.enroll_intro))
        val first: EditText = screen.input(getString(R.string.enroll_link_hint), url = true)
        prefill?.let { first.setText(it) }
        val second: EditText = screen.input(getString(R.string.enroll_code_hint))
        error?.let { screen.body(it) }
        screen.button(getString(R.string.enroll_continue)) {
            when (val built = EnrollLink.build(first.text.toString(), second.text.toString())) {
                is EnrollLink.Built.Link -> preview(built.link)
                EnrollLink.Built.NeedLink -> showInput(getString(R.string.enroll_need_link), null)
                EnrollLink.Built.NeedCode ->
                    showInput(getString(R.string.enroll_need_code), first.text.toString())
            }
        }
    }

    private fun preview(link: String) {
        this.link = link
        showBusy(getString(R.string.enroll_checking))
        worker.execute {
            try {
                val p = FaroCore.get(this).previewEnrollment(link)
                runOnUiThread { if (!isDestroyed) showConfirm(p) }
            } catch (e: Exception) {
                runOnUiThread { if (!isDestroyed) showFailure(e) }
            }
        }
    }

    private fun showConfirm(p: EnrollPreview) {
        screen.clear()
        screen.title(getString(R.string.enroll_confirm_title, p.instanceName))
        screen.body(getString(R.string.enroll_confirm_body, p.instanceUrl))
        p.memberFingerprint?.let { screen.body(getString(R.string.enroll_member_fingerprint, it)) }
        screen.button(getString(R.string.enroll_confirm_yes)) { enroll() }
        screen.button(getString(R.string.enroll_cancel)) { finish() }
    }

    private fun enroll() {
        val link = link ?: return
        showBusy(getString(R.string.enroll_enrolling))
        val name = listOf(Build.MANUFACTURER, Build.MODEL).filter { it.isNotBlank() }.joinToString(" ")
        worker.execute {
            try {
                val device = FaroCore.get(this).enroll(link, name)
                MonitorService.start(this)
                runOnUiThread { if (!isDestroyed) showWaiting(device.deviceFingerprint) }
                startPolling()
            } catch (e: Exception) {
                runOnUiThread { if (!isDestroyed) showFailure(e) }
            }
        }
    }

    private fun showWaiting(fingerprint: String) {
        screen.clear()
        screen.title(getString(R.string.enroll_waiting_title))
        screen.body(getString(R.string.enroll_waiting_body))
        screen.small(getString(R.string.enroll_fingerprint_label))
        screen.mono(fingerprint)
    }

    private fun startPolling() {
        polling?.cancel(false)
        polling = worker.scheduleWithFixedDelay({
            try {
                when (FaroCore.get(this).pollApproval()) {
                    ApprovalState.ACTIVE -> {
                        polling?.cancel(false)
                        MonitorService.start(this)
                        runOnUiThread { if (!isDestroyed) showApproved() }
                    }
                    ApprovalState.REFUSED -> {
                        polling?.cancel(false)
                        runOnUiThread { if (!isDestroyed) showRefused() }
                    }
                    else -> Unit
                }
            } catch (e: Exception) {
                // Try again at the next poll; the instance may be briefly unreachable.
            }
        }, POLL_SECONDS, POLL_SECONDS, TimeUnit.SECONDS)
    }

    private fun showApproved() {
        screen.clear()
        screen.title(getString(R.string.enroll_approved_title))
        screen.body(getString(R.string.enroll_approved_body))
        screen.button(getString(R.string.enroll_continue_setup)) {
            startActivity(SetupActivity.intent(this))
            finish()
        }
    }

    private fun showRefused() {
        screen.clear()
        screen.title(getString(R.string.enroll_refused_title))
        screen.body(getString(R.string.enroll_refused_body))
        screen.button(getString(R.string.enroll_try_again)) { showInput(null, null) }
    }

    private fun showBusy(text: String) {
        screen.clear()
        screen.title(text)
    }

    private fun showFailure(e: Exception) {
        screen.clear()
        screen.title(getString(R.string.enroll_title))
        screen.body(getString(R.string.enroll_failed, e.message ?: e.javaClass.simpleName))
        screen.button(getString(R.string.enroll_try_again)) { showInput(null, null) }
    }

    private companion object {
        const val POLL_SECONDS = 3L
    }
}
