/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.os.IBinder
import android.os.Parcel
import android.os.Parcelable
import android.os.ServiceManager
import android.os.ServiceSpecificException
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import kotlin.system.exitProcess

abstract class BaseKeystoreInterceptor : BinderInterceptor() {

    protected lateinit var keystore: IBinder
    protected var triedCount = 0
    protected var injected = false
    protected open val maxRetries: Int = 3

    protected abstract val serviceName: String
    protected abstract val injectionCommand: String
    protected abstract val processName: String

    fun tryRunKeystoreInterceptor(): Boolean {
        Log.i(TAG, "Trying to register ${this::class.simpleName} (attempt $triedCount)...")

        val service = getService() ?: return false
        val backdoor = getBinderBackdoor(service)

        return if (backdoor != null) {
            setupInterceptor(service, backdoor)
        } else {
            handleMissingBackdoor()
        }
    }

    protected open fun getService(): IBinder? = ServiceManager.getService(serviceName)

    protected open fun setupInterceptor(service: IBinder, backdoor: IBinder): Boolean {
        keystore = service
        Log.i(TAG, "Registering for $serviceName: $keystore")

        registerBinderInterceptor(backdoor, service, this)
        service.linkToDeath(createDeathRecipient(), 0)
        onInterceptorSetup(service, backdoor)

        return true
    }

    private fun handleMissingBackdoor(): Boolean {
        if (triedCount >= maxRetries) {
            Log.e(TAG, "Tried injection $maxRetries times but still no backdoor, exiting")
            exitProcess(1)
        }

        if (!injected) {
            performInjection()
            injected = true
        }

        triedCount++
        return false
    }

    protected open fun performInjection() {
        Log.i(TAG, "Attempting to inject into $processName...")

        val command = arrayOf("/system/bin/sh", "-c", injectionCommand)
        Log.d(TAG, "Injection command: ${command.joinToString(" ")}")

        val process = Runtime.getRuntime().exec(command)

        if (process.waitFor() != 0) {
            Log.e(TAG, "Injection failed! Daemon will exit")
            exitProcess(1)
        }

        Log.i(TAG, "Injection completed successfully")
    }

    protected open fun createDeathRecipient(): IBinder.DeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                Log.d(TAG, "$serviceName died, daemon restarting")
                exitProcess(0)
            }
        }

    protected open fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        // Default implementation does nothing
    }
}

object InterceptorUtils {

    fun getTransactCode(clazz: Class<*>, method: String): Int =
        clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)

    fun createSuccessKeystoreResponse(): KeystoreResponse {
        val parcel = Parcel.obtain()
        try {
            parcel.writeInt(KeyStore.NO_ERROR)
            parcel.writeString("")
            parcel.setDataPosition(0)
            return KeystoreResponse.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    fun createSuccessReply(resultCode: Int = KeyStore.NO_ERROR): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeInt(resultCode)
        return BinderInterceptor.OverrideReply(0, parcel)
    }

    fun createByteArrayReply(data: ByteArray, resultCode: Int = KeyStore.NO_ERROR): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeByteArray(data)
        return BinderInterceptor.OverrideReply(resultCode, parcel)
    }

    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
        resultCode: Int = 0,
    ): BinderInterceptor.OverrideReply {
        val parcel = Parcel.obtain()
        parcel.writeNoException()
        parcel.writeTypedObject(obj, flags)
        return BinderInterceptor.OverrideReply(resultCode, parcel)
    }

    fun typedReply(metadata: Parcelable?): BinderInterceptor.OverrideReply = createTypedObjectReply(metadata)

    fun errorReply(errorCode: Int, message: String): BinderInterceptor.OverrideReply {
        val p = Parcel.obtain()
        p.writeException(ServiceSpecificException(errorCode, message))
        return BinderInterceptor.OverrideReply(0, p)
    }

    fun successReply(): BinderInterceptor.OverrideReply {
        val p = Parcel.obtain()
        p.writeNoException()
        return BinderInterceptor.OverrideReply(0, p)
    }

    fun String.extractAlias(): String {
        return when {
            contains("_") -> split("_")[1]
            else -> this
        }
    }

    fun Parcel.hasException(): Boolean {
        return runCatching { readException() }.exceptionOrNull() != null
    }
}
