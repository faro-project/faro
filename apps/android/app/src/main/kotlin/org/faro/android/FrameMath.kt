package org.faro.android

/** Sizes and checks for screenshots, with no Android dependency. */
object FrameMath {
    /** The longest side of a frame handed to the Rust core. */
    const val MAX_SIDE = 768

    /** [w] x [h] scaled down (never up) so the longest side is at most [max], keeping the shape. */
    fun targetSize(w: Int, h: Int, max: Int = MAX_SIDE): Pair<Int, Int> {
        require(w > 0 && h > 0 && max > 0) { "empty frame" }
        val longest = maxOf(w, h)
        if (longest <= max) return w to h
        val scale = max.toDouble() / longest
        return maxOf(1, Math.round(w * scale).toInt()) to maxOf(1, Math.round(h * scale).toInt())
    }

    /**
     * True if (nearly) every sampled pixel of [rgba] (tightly packed RGBA8888) is black. Before
     * Android 14 a screenshot has no secure-window error: the system draws a FLAG_SECURE window as
     * black, so this is the only sign of one there.
     */
    fun looksBlank(rgba: ByteArray, width: Int, height: Int, samples: Int = 512): Boolean {
        val pixels = width.toLong() * height
        if (pixels <= 0 || rgba.size < pixels * 4) return false
        val step = maxOf(1L, pixels / samples)
        var i = 0L
        while (i < pixels) {
            val o = (i * 4).toInt()
            // A tolerance of a few levels: video-black and dark themes are not exactly zero.
            if ((rgba[o].toInt() and 0xFF) > 8 || (rgba[o + 1].toInt() and 0xFF) > 8 ||
                (rgba[o + 2].toInt() and 0xFF) > 8
            ) return false
            i += step
        }
        return true
    }
}
