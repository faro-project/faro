package org.faro.android

/** What the member must still switch on for Faro to work, in the order the setup flow asks. */
enum class SetupStep { NOTIFICATIONS, ACCESSIBILITY, DEVICE_ADMIN, BATTERY }

/** Which permissions Faro has right now. */
data class SetupState(
    val notifications: Boolean,
    val accessibility: Boolean,
    val deviceAdmin: Boolean,
    val batteryExempt: Boolean,
) {
    /** The first thing still missing, or null when setup is complete. */
    fun nextStep(): SetupStep? = when {
        !notifications -> SetupStep.NOTIFICATIONS
        !accessibility -> SetupStep.ACCESSIBILITY
        !deviceAdmin -> SetupStep.DEVICE_ADMIN
        !batteryExempt -> SetupStep.BATTERY
        else -> null
    }
}

/** The button the status screen shows for a problem. It only ever fixes something. */
sealed class Fix {
    data object Enroll : Fix()
    data class Setup(val step: SetupStep) : Fix()
}

object FixChooser {
    /** Not enrolled: enroll. Enrolled: the first missing permission. Otherwise nothing. */
    fun fixFor(enrolled: Boolean, state: SetupState): Fix? =
        if (!enrolled) Fix.Enroll else state.nextStep()?.let { Fix.Setup(it) }
}
