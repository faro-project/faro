package org.faro.android

import java.util.ArrayDeque

/**
 * Tamper signals waiting for the Rust core's next poll. Thread-safe.
 *
 * [level] turns a condition that stays true (accessibility off, USB debugging on) into one signal
 * when it becomes true, and again each time it goes false and true; [offer] queues a one-off signal.
 * A signal already waiting isn't queued twice.
 */
class TamperQueue<T : Any> {
    private val lock = Any()
    private val pending = ArrayDeque<T>()
    private val active = HashSet<String>()

    fun offer(signal: T) = synchronized(lock) {
        if (signal !in pending) pending.add(signal)
    }

    /** Queue [signal] when [key]'s condition turns on; forget the condition when it turns off. */
    fun level(key: String, on: Boolean, signal: T) = synchronized(lock) {
        if (!on) {
            active.remove(key)
        } else if (active.add(key) && signal !in pending) {
            pending.add(signal)
        }
    }

    /** Everything queued since the last call, oldest first. */
    fun drain(): List<T> = synchronized(lock) {
        val out = pending.toList()
        pending.clear()
        out
    }
}
