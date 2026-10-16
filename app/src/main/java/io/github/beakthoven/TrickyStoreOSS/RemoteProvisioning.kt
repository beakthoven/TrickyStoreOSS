/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.content.Intent
import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.IUserManager
import android.os.ServiceManager
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

internal object RemoteProvisioning {
    private const val SERVICE_ACTION = "com.android.rkpdapp.IRemoteProvisioning"
    private const val SYSTEM_USER = 0
    private const val RETRY_DELAY_MS = 1000L

    // Run on the main thread before installing interceptors: waiting inside a Keystore
    // callback could block the very Keystore operations needed to unlock the user.
    fun waitForUserUnlockIfNeeded() {
        var requiresUnlock: Boolean? = null
        var lastWaitReason: String? = null
        while (true) {
            val waitReason =
                try {
                    if (requiresUnlock == null) requiresUnlock = requiresUserUnlock()
                    if (requiresUnlock == false) return

                    val binder = ServiceManager.checkService("user") ?: error("user service unavailable")
                    if (IUserManager.Stub.asInterface(binder).isUserUnlocked(SYSTEM_USER)) {
                        Logger.i("User 0 is unlocked; TEE probing may proceed")
                        return
                    }
                    "$SERVICE_ACTION is not direct-boot aware; delaying TEE probing until user 0 first unlocks"
                } catch (e: Exception) {
                    // An unavailable framework service is not evidence that TEE is broken.
                    "Waiting to check remote provisioning unlock requirements: ${e.message}"
                }

            if (waitReason != lastWaitReason) {
                Logger.i(waitReason)
                lastWaitReason = waitReason
            }
            Thread.sleep(RETRY_DELAY_MS)
        }
    }

    private fun requiresUserUnlock(): Boolean {
        val binder = ServiceManager.checkService("package") ?: error("package service unavailable")
        val pm = IPackageManager.Stub.asInterface(binder)
        val intent = Intent(SERVICE_ACTION)
        // Include unaware services even before unlock, when a default query hides them.
        val flags = PackageManager.MATCH_DIRECT_BOOT_AWARE or PackageManager.MATCH_DIRECT_BOOT_UNAWARE
        val services =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentServices(intent, null, flags.toLong(), SYSTEM_USER)
            } else {
                pm.queryIntentServices(intent, null, flags, SYSTEM_USER)
            }
        return services.list.any { it.serviceInfo?.directBootAware == false }
    }
}
