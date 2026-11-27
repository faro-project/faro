package org.faro.android

import android.app.NotificationManager
import android.content.Context
import android.util.Log

/**
 * Notices from the Rust core (`show_notice`) that the member has not yet acknowledged. A notice is a
 * window, not only a notification, because notifications can be silenced; and it is kept here until
 * the member taps OK, so it can't be lost if the window could not be shown at that moment.
 */
object NoticeStore {
    private const val PREFS = "notices"
    private const val KEY = "pending"
    private const val SEP = '\u001e'

    @Synchronized
    fun add(context: Context, text: String) {
        val all = pending(context) + text
        prefs(context).edit().putString(KEY, all.joinToString(SEP.toString())).apply()
    }

    @Synchronized
    fun pending(context: Context): List<String> =
        prefs(context).getString(KEY, null)?.split(SEP)?.filter { it.isNotBlank() } ?: emptyList()

    @Synchronized
    fun clear(context: Context) {
        prefs(context).edit().remove(KEY).apply()
        context.getSystemService(NotificationManager::class.java).cancel(Notifications.ID_NOTICE)
    }

    /** Shows the notice window now if the system lets us, and always leaves a notification pointing at it. */
    fun show(context: Context, text: String) {
        add(context, text)
        val ctx = FaroAccessibilityService.instance ?: context
        try {
            ctx.startActivity(Notifications.noticeIntent(ctx))
        } catch (e: Exception) {
            Log.w("FaroNotice", "could not open the notice window: ${e.javaClass.simpleName}")
        }
        try {
            Notifications.ensureChannels(context)
            context.getSystemService(NotificationManager::class.java)
                .notify(Notifications.ID_NOTICE, Notifications.noticePointer(context))
        } catch (e: SecurityException) {
            Log.w("FaroNotice", "could not post the notice pointer")
        }
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
