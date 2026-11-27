package org.faro.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.app.admin.DevicePolicyManager

/** A plain scrolling column of text, inputs and buttons: all the screens Faro needs, with no UI library. */
class Screen(private val activity: Activity) {
    private val column = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        val pad = dp(20)
        setPadding(pad, pad, pad, pad)
    }
    private val scroll = ScrollView(activity).apply {
        isFillViewport = true
        addView(column)
        // Targeting Android 15 draws behind the system bars: keep the content clear of them.
        setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
    }

    init {
        activity.setContentView(scroll)
    }

    fun dp(v: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), activity.resources.displayMetrics).toInt()

    fun clear() = column.removeAllViews()

    fun title(text: CharSequence): TextView = text(text, 24f, bold = true, top = 0)

    fun body(text: CharSequence): TextView = text(text, 16f, bold = false, top = 12)

    fun small(text: CharSequence): TextView = text(text, 13f, bold = false, top = 16)

    fun mono(text: CharSequence): TextView = text(text, 20f, bold = true, top = 8).apply {
        typeface = android.graphics.Typeface.MONOSPACE
        setTextIsSelectable(true)
    }

    private fun text(text: CharSequence, sp: Float, bold: Boolean, top: Int): TextView =
        TextView(activity).apply {
            this.text = text
            setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            layoutParams = params(top)
            column.addView(this)
        }

    fun button(label: CharSequence, onClick: () -> Unit): Button =
        Button(activity).apply {
            text = label
            isAllCaps = false
            layoutParams = params(16)
            setOnClickListener { onClick() }
            column.addView(this)
        }

    fun input(hint: CharSequence, url: Boolean = false): EditText =
        EditText(activity).apply {
            this.hint = hint
            inputType = if (url) InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_CLASS_TEXT
            else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
            setSingleLine(true)
            layoutParams = params(12)
            column.addView(this)
        }

    private fun params(topDp: Int) = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        topMargin = dp(topDp)
        gravity = Gravity.START
    }

    fun gone(v: View) {
        v.visibility = View.GONE
    }
}

/** The system screens that fix each missing permission. Each one only turns something on. */
object SetupActions {
    fun launch(activity: Activity, step: SetupStep) {
        when (step) {
            SetupStep.NOTIFICATIONS -> activity.startActivity(SetupActivity.intent(activity))
            SetupStep.ACCESSIBILITY -> openAccessibility(activity)
            SetupStep.DEVICE_ADMIN -> requestAdmin(activity)
            SetupStep.BATTERY -> requestBattery(activity)
        }
    }

    fun openAccessibility(activity: Activity) =
        activity.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))

    fun openAppInfo(activity: Activity) = activity.startActivity(
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", activity.packageName, null)),
    )

    fun openNotificationSettings(activity: Activity) = activity.startActivity(
        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName),
    )

    fun requestAdmin(activity: Activity) = activity.startActivity(
        Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, Permissions.adminComponent(activity))
            .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, activity.getString(R.string.setup_admin_explanation)),
    )

    @android.annotation.SuppressLint("BatteryLife")
    fun requestBattery(activity: Activity) = activity.startActivity(
        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${activity.packageName}")),
    )

    /** The label of the button that fixes [step] from the status screen. */
    fun fixLabel(activity: Activity, step: SetupStep): String = activity.getString(
        when (step) {
            SetupStep.NOTIFICATIONS -> R.string.fix_notifications
            SetupStep.ACCESSIBILITY -> R.string.fix_accessibility
            SetupStep.DEVICE_ADMIN -> R.string.fix_device_admin
            SetupStep.BATTERY -> R.string.fix_battery
        },
    )

    fun problemText(activity: Activity, step: SetupStep): String = activity.getString(
        when (step) {
            SetupStep.NOTIFICATIONS -> R.string.problem_notifications
            SetupStep.ACCESSIBILITY -> R.string.problem_accessibility
            SetupStep.DEVICE_ADMIN -> R.string.problem_device_admin
            SetupStep.BATTERY -> R.string.problem_battery
        },
    )
}
