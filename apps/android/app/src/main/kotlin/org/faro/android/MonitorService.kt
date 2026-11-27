package org.faro.android

import android.app.KeyguardManager
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.faro.core.SessionEvent
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The foreground service that keeps Faro running. It owns the Rust core's lifetime: it starts the core
 * once this phone is enrolled and approved, tells it about the screen locking and waking, and shows the
 * persistent notice that this phone is monitored. That notice has no action: nothing here stops,
 * pauses or hides monitoring.
 */
class MonitorService : Service() {
    private val worker = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "faro-monitor").apply { isDaemon = true }
    }
    private var screenReceiver: BroadcastReceiver? = null

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
        val first = Notifications.monitoring(this, getString(R.string.notification_starting), enrolled = false)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, Notifications.ID_MONITOR, first, type)
        registerScreenReceiver()
        worker.scheduleWithFixedDelay({ tick() }, 0, TICK_SECONDS, TimeUnit.SECONDS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Started again (app opened, boot, update, or the notification was swiped away and
        // ACTION_RESHOW_NOTICE arrived): look at the state now and post the notification again,
        // instead of waiting for the next tick.
        worker.execute { tick() }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        screenReceiver?.let { unregisterReceiver(it) }
        screenReceiver = null
        worker.shutdownNow()
        val app = applicationContext
        // A graceful stop sends the shutdown heartbeat, which is network: not on the main thread.
        Thread({
            try {
                FaroCore.get(app).stop()
            } catch (e: Exception) {
                Log.w(TAG, "stop failed: ${e.javaClass.simpleName}")
            }
        }, "faro-stop").start()
        super.onDestroy()
    }

    /** Refreshes the notification, and starts the core (or asks about approval) as the state allows. */
    private fun tick() {
        try {
            val core = FaroCore.get(this)
            var status = core.status()
            if (status.enrolled && !status.active) {
                // Waiting for approval in the web app, and the enrollment screen may be closed.
                core.pollApproval()
                status = core.status()
            }
            if (status.enrolled && status.active) core.start()
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(Notifications.ID_MONITOR, Notifications.monitoring(this, status.headline, status.enrolled))
        } catch (e: Exception) {
            // Only the kind of failure: a message could carry an address.
            Log.w(TAG, "tick failed: ${e.javaClass.simpleName}")
        }
    }

    private fun registerScreenReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val action = intent.action ?: return
                val keyguard = context.getSystemService(KeyguardManager::class.java)
                val events = when (action) {
                    Intent.ACTION_SCREEN_OFF -> listOfNotNull(
                        SessionEvent.DISPLAY_SLEEP,
                        SessionEvent.LOCKED.takeIf { keyguard.isKeyguardLocked },
                    )
                    Intent.ACTION_SCREEN_ON -> listOfNotNull(
                        SessionEvent.DISPLAY_WAKE,
                        SessionEvent.LOCKED.takeIf { keyguard.isKeyguardLocked },
                    )
                    Intent.ACTION_USER_PRESENT -> listOf(SessionEvent.UNLOCKED)
                    else -> return
                }
                // The Rust core may do I/O in session_changed: keep it off the main thread.
                try {
                    worker.execute {
                        try {
                            val core = FaroCore.get(context)
                            events.forEach { core.sessionChanged(it) }
                        } catch (e: Exception) {
                            Log.w(TAG, "session change failed: ${e.javaClass.simpleName}")
                        }
                    }
                } catch (_: java.util.concurrent.RejectedExecutionException) {
                    // Shutting down.
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        screenReceiver = receiver
    }

    companion object {
        private const val TAG = "FaroMonitor"
        private const val TICK_SECONDS = 30L

        /** Sent by the notification's delete intent when the member swipes it away. */
        const val ACTION_RESHOW_NOTICE = "org.faro.android.action.RESHOW_NOTICE"

        /** Starts the service. Android refuses from the background in some cases; then it is a no-op. */
        fun start(context: Context) {
            try {
                ContextCompat.startForegroundService(context, Intent(context, MonitorService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "could not start the service now: ${e.javaClass.simpleName}")
            }
        }
    }
}
