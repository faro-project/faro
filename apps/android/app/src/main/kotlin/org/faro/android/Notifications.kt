package org.faro.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build

/** Faro's two notifications: the persistent "monitored" one, and the pointer to an unread notice. */
object Notifications {
    const val CHANNEL_MONITOR = "monitor"
    const val CHANNEL_NOTICE = "notice"
    const val ID_MONITOR = 1
    const val ID_NOTICE = 2

    fun ensureChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_MONITOR,
                context.getString(R.string.channel_monitor_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = context.getString(R.string.channel_monitor_description)
                setShowBadge(false)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_NOTICE,
                context.getString(R.string.channel_notice_name),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = context.getString(R.string.channel_notice_description) },
        )
    }

    /**
     * The ongoing notification of the foreground service. It has no action: nothing in Faro stops,
     * pauses or hides monitoring.
     */
    fun monitoring(context: Context, headline: String, enrolled: Boolean): Notification {
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, StatusActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = context.getString(
            if (enrolled) R.string.notification_monitored else R.string.notification_not_monitored,
        )
        val builder = Notification.Builder(context, CHANNEL_MONITOR)
            .setSmallIcon(R.drawable.ic_stat_faro)
            .setContentTitle(headline)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return builder.build()
    }

    /** A high-priority pointer to [NoticeActivity], in case the activity could not be shown at once. */
    fun noticePointer(context: Context): Notification {
        val open = PendingIntent.getActivity(
            context,
            1,
            noticeIntent(context),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, CHANNEL_NOTICE)
            .setSmallIcon(R.drawable.ic_stat_faro)
            .setContentTitle(context.getString(R.string.notification_notice_title))
            .setContentText(context.getString(R.string.notification_notice_text))
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .build()
    }

    fun noticeIntent(context: Context): Intent =
        Intent(context, NoticeActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
}
