package org.faro.android

import android.content.Context
import java.io.File
import java.io.IOException
import java.io.InputStream

/**
 * The image model the APK carries (assets/model/opennsfw/, put there by the build when it is given
 * -Pfaro.modelDir) and its copy in app-private storage, where the Rust core loads it
 * (<noBackupFilesDir>/faro/models/opennsfw/manifest.json, `MODEL_MANIFEST` in faro-android).
 */
object ModelAssets {
    private const val ASSET_DIR = "model/opennsfw"
    private val FILES = listOf("opennsfw-int8.onnx", "manifest.json")

    /** Whether this APK was built with the model. The core then treats a missing model as tamper. */
    fun isPackaged(context: Context): Boolean = try {
        context.assets.open("$ASSET_DIR/manifest.json").close()
        true
    } catch (_: IOException) {
        false
    }

    /**
     * Copies the packaged model to [dir] (the `faro` state directory) when a file is missing or
     * differs from the APK's, the manifest last so it only appears once the model is whole. A copy
     * that fails is left for the core to report: it checks the files itself. Returns [isPackaged].
     */
    fun install(context: Context, dir: File): Boolean {
        if (!isPackaged(context)) return false
        val target = File(dir, "models/opennsfw")
        try {
            target.mkdirs()
            for (name in FILES) {
                val dest = File(target, name)
                if (sameAsAsset(context, "$ASSET_DIR/$name", dest)) continue
                val part = File(target, "$name.part")
                context.assets.open("$ASSET_DIR/$name").use { input ->
                    part.outputStream().use { input.copyTo(it) }
                }
                if (!part.renameTo(dest)) {
                    dest.delete()
                    if (!part.renameTo(dest)) throw IOException("cannot replace $dest")
                }
            }
        } catch (e: IOException) {
            android.util.Log.e("faro", "cannot copy the image model: ${e.message}")
        }
        return true
    }

    private fun sameAsAsset(context: Context, asset: String, file: File): Boolean {
        if (!file.isFile) return false
        return context.assets.open(asset).use { a -> file.inputStream().use { f -> sameBytes(a, f) } }
    }

    internal fun sameBytes(a: InputStream, b: InputStream): Boolean {
        val x = ByteArray(64 * 1024)
        val y = ByteArray(64 * 1024)
        while (true) {
            val n = a.readFill(x)
            val m = b.readFill(y)
            if (n != m || !x.copyOf(n).contentEquals(y.copyOf(m))) return false
            if (n == 0) return true
        }
    }

    private fun InputStream.readFill(buf: ByteArray): Int {
        var n = 0
        while (n < buf.size) {
            val r = read(buf, n, buf.size - n)
            if (r < 0) break
            n += r
        }
        return n
    }
}

/** The licences and notices the build put in assets/notices: ONNX Runtime's and the model's. */
object NoticeAssets {
    fun text(context: Context): String {
        val names = try {
            context.assets.list("notices")?.sorted().orEmpty()
        } catch (_: IOException) {
            emptyList()
        }
        return names.joinToString("\n\n\n") { name ->
            val body = try {
                context.assets.open("notices/$name").bufferedReader().use { it.readText() }
            } catch (_: IOException) {
                ""
            }
            "== $name ==\n\n$body"
        }
    }
}
