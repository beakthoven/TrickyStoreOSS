/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.Build
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.Keystore2Interceptor
import io.github.beakthoven.TrickyStoreOSS.interceptors.KeystoreInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

private const val RETRY_DELAY_MS = 1000L

fun main(args: Array<String>) {
    Log.i(TAG, "Welcome to TrickyStoreOSS!")
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.addProvider(BouncyCastleProvider())

    try {
        AndroidUtils.setupBootHash()
        initializeInterceptors()
        maintainService()
    } catch (e: Exception) {
        Log.e(TAG, "Fatal error in main", e)
        throw e
    }
}

private fun initializeInterceptors() {
    val interceptor = selectKeystoreInterceptor()

    while (!interceptor.tryRunKeystoreInterceptor()) {
        Log.d(TAG, "Retrying interceptor initialization...")
        Thread.sleep(RETRY_DELAY_MS)
    }

    PkgConfig.initialize()
    Log.i(TAG, "Interceptors initialized successfully")
}

private fun selectKeystoreInterceptor() =
    when {
        Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
            Log.i(TAG, "Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})")
            KeystoreInterceptor
        }
        else -> {
            Log.i(TAG, "Using Keystore2Interceptor for Android S+ (SDK ${Build.VERSION.SDK_INT})")
            Keystore2Interceptor
        }
    }

private fun maintainService() {
    Log.i(TAG, "Service started, entering maintenance mode")
    Thread.currentThread().join()
}
