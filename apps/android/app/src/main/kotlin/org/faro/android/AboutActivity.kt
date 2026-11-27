package org.faro.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle

/** The version, what Faro is, and a link to the licences and the source. */
class AboutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val screen = Screen(this)
        screen.title(getString(R.string.about_title))
        screen.small(getString(R.string.about_version, BuildConfigVersion.name(this)))
        screen.body(getString(R.string.about_body))
        screen.button(getString(R.string.about_licences)) {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.about_licences_url))))
            } catch (_: android.content.ActivityNotFoundException) {
                // No browser installed: nothing to open.
            }
        }
        // ONNX Runtime's licence and notices, and the image model's, when the build packaged them.
        val notices = NoticeAssets.text(this)
        if (notices.isNotEmpty()) {
            var shown = false
            screen.button(getString(R.string.about_notices)) {
                if (!shown) {
                    shown = true
                    screen.small(notices)
                }
            }
        }
    }
}

/** The app's version name, from the package (BuildConfig is off to keep the build simple). */
object BuildConfigVersion {
    fun name(context: android.content.Context): String = try {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
    } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
        "?"
    }
}
