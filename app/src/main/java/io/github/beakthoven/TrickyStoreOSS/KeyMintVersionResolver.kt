/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.IKeyMintDevice
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.ServiceManager
import android.security.compat.IKeystoreCompatService
import android.util.Log
import androidx.annotation.RequiresApi
import io.github.beakthoven.TrickyStoreOSS.logging.TAG

/** Resolves versions from Android 12+ native KeyMint and legacy Keymaster backends. */
@RequiresApi(Build.VERSION_CODES.S)
internal object KeyMintVersionResolver {
    fun resolve(securityLevel: Int): AndroidUtils.AttestationVersions? =
        nativeKeyMintVersions(securityLevel) ?: compatKeymasterVersions(securityLevel)

    private fun keyMintInstance(securityLevel: Int): String? =
        when (securityLevel) {
            SecurityLevel.TRUSTED_ENVIRONMENT -> "default"
            SecurityLevel.STRONGBOX -> "strongbox"
            else -> null
        }

    private fun nativeKeyMintVersions(securityLevel: Int): AndroidUtils.AttestationVersions? {
        val instance = keyMintInstance(securityLevel) ?: return null
        val serviceName = "${IKeyMintDevice.DESCRIPTOR}/$instance"
        val binder = ServiceManager.checkService(serviceName) ?: return null

        return runCatching {
                val keyMint = IKeyMintDevice.Stub.asInterface(binder)
                val interfaceVersion = keyMint.interfaceVersion
                if (interfaceVersion <= 0) return@runCatching null
                val version = interfaceVersion * 100
                AndroidUtils.AttestationVersions(version, version)
            }
            .onSuccess { versions ->
                if (versions != null) Log.i(TAG, "Resolved $serviceName versions: $versions")
            }
            .onFailure { Log.w(TAG, "Failed to query $serviceName interface version", it) }
            .getOrNull()
    }

    private fun legacyKeymasterVersions(versionNumber: Int): AndroidUtils.AttestationVersions? =
        when (versionNumber) {
            20 -> AndroidUtils.AttestationVersions(1, 2)
            30 -> AndroidUtils.AttestationVersions(2, 3)
            40 -> AndroidUtils.AttestationVersions(3, 4)
            41 -> AndroidUtils.AttestationVersions(4, 41)
            else -> null
        }

    private fun compatKeymasterVersions(securityLevel: Int): AndroidUtils.AttestationVersions? {
        val serviceName = "android.security.compat"
        val binder = ServiceManager.checkService(serviceName) ?: return null

        return runCatching {
                val compat = IKeystoreCompatService.Stub.asInterface(binder)
                val keyMint = compat.getKeyMintDevice(securityLevel)
                val hardwareInfo = keyMint.hardwareInfo
                require(hardwareInfo.securityLevel == securityLevel) {
                    "Compat KeyMint security level ${hardwareInfo.securityLevel}, requested $securityLevel"
                }
                legacyKeymasterVersions(hardwareInfo.versionNumber)
                    ?: error("Unsupported legacy Keymaster version: ${hardwareInfo.versionNumber}")
            }
            .onSuccess { versions ->
                Log.i(TAG, "Resolved $serviceName level=$securityLevel versions: $versions")
            }
            .onFailure { Log.w(TAG, "Failed to query $serviceName level=$securityLevel", it) }
            .getOrNull()
    }
}
