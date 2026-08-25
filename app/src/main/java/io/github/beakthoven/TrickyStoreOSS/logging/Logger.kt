/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.logging

import android.os.SystemProperties
import android.util.Log

private const val TAG = "TrickyStoreOSS"

object Logger {
    private val logdReady: Boolean by lazy { SystemProperties.get("init.svc.logd", "") == "running" }

    fun v(msg: String, tr: Throwable? = null) = log(Log.VERBOSE, msg, tr)

    fun d(msg: String, tr: Throwable? = null) = log(Log.DEBUG, msg, tr)

    fun i(msg: String, tr: Throwable? = null) = log(Log.INFO, msg, tr)

    fun w(msg: String, tr: Throwable? = null) = log(Log.WARN, msg, tr)

    fun e(msg: String, tr: Throwable? = null) = log(Log.ERROR, msg, tr)

    private fun log(priority: Int, msg: String, tr: Throwable?) {
        if (!logdReady) return
        Log.println(priority, TAG, if (tr == null) msg else "$msg\n${Log.getStackTraceString(tr)}")
    }
}
