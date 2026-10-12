/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.IKeyMintDevice
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import androidx.annotation.RequiresApi
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

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
            .onSuccess { versions -> if (versions != null) Logger.i("Resolved $serviceName versions: $versions") }
            .onFailure { Logger.w("Failed to query $serviceName interface version", it) }
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

    private const val COMPAT_DESCRIPTOR = "android.security.compat.IKeystoreCompatService"
    private const val TRANSACTION_GET_KEYMINT_DEVICE = IBinder.FIRST_CALL_TRANSACTION

    private fun compatKeyMintDevice(binder: IBinder, securityLevel: Int): IKeyMintDevice? {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(COMPAT_DESCRIPTOR)
            data.writeInt(securityLevel)
            if (!binder.transact(TRANSACTION_GET_KEYMINT_DEVICE, data, reply, 0)) return null
            reply.readException()
            reply.readStrongBinder()?.let { IKeyMintDevice.Stub.asInterface(it) }
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    private fun compatKeymasterVersions(securityLevel: Int): AndroidUtils.AttestationVersions? {
        val serviceName = "android.security.compat"
        val binder = ServiceManager.checkService(serviceName) ?: return null

        return runCatching {
                val keyMint = compatKeyMintDevice(binder, securityLevel)
                    ?: error("No compat KeyMint device for level $securityLevel")
                val hardwareInfo = keyMint.hardwareInfo
                require(hardwareInfo.securityLevel == securityLevel) {
                    "Compat KeyMint security level ${hardwareInfo.securityLevel}, requested $securityLevel"
                }
                legacyKeymasterVersions(hardwareInfo.versionNumber)
                    ?: error("Unsupported legacy Keymaster version: ${hardwareInfo.versionNumber}")
            }
            .onSuccess { versions -> Logger.i("Resolved $serviceName level=$securityLevel versions: $versions") }
            .onFailure { Logger.w("Failed to query $serviceName level=$securityLevel", it) }
            .getOrNull()
    }
}
