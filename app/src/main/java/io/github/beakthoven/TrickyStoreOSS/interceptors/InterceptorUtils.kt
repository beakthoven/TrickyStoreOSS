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
import android.security.Credentials
import android.security.KeyStore
import android.security.keystore.KeystoreResponse
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

abstract class BaseKeystoreInterceptor : BinderInterceptor() {

    protected lateinit var keystore: IBinder
    protected var triedCount = 0
    protected var injected = false
    protected open val maxRetries: Int = 3

    protected abstract val serviceName: String
    protected abstract val injectionCommand: String
    protected abstract val processName: String

    private companion object {
        // Comfortably above the injector's own 20s budget, so the injector gets to fail and clean up first.
        const val INJECTION_TIMEOUT_SECONDS = 30L
    }

    fun tryRunKeystoreInterceptor(): Boolean {
        Logger.i("Trying to register ${this::class.simpleName} (attempt $triedCount)...")

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
        Logger.i("Registering for $serviceName: $service")

        if (!registerBinderInterceptor(backdoor, service, this)) {
            Logger.e("Failed to register interceptor for $serviceName; aborting setup")
            return false
        }

        keystore = service
        service.linkToDeath(createDeathRecipient(), 0)
        onInterceptorSetup(service, backdoor)

        return true
    }

    private fun handleMissingBackdoor(): Boolean {
        if (triedCount >= maxRetries) {
            Logger.e("Tried injection $maxRetries times but still no backdoor, exiting")
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
        Logger.i("Attempting to inject into $processName...")

        val command = listOf("/system/bin/sh", "-c", injectionCommand)
        Logger.d("Injection command: ${command.joinToString(" ")}")

        // The injector leaves the target attached for as long as it runs, and a remote call that never
        // returns would keep both it and this daemon waiting forever. Bound the wait and let the
        // supervisor restart the daemon, which retries against a tracer-free target.
        val process = ProcessBuilder(command).inheritIO().start()

        if (!process.waitFor(INJECTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            Logger.e("Injection timed out after ${INJECTION_TIMEOUT_SECONDS}s! Daemon will exit")
            exitProcess(1)
        }

        if (process.exitValue() != 0) {
            Logger.e("Injection failed! Daemon will exit")
            exitProcess(1)
        }

        Logger.i("Injection completed successfully")
    }

    protected open fun createDeathRecipient(): IBinder.DeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                Logger.d("$serviceName died, daemon restarting")
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

    fun String.extractAlias(): String =
        sequenceOf(
            Credentials.USER_PRIVATE_KEY,
            Credentials.USER_SECRET_KEY,
            Credentials.USER_CERTIFICATE,
            Credentials.CA_CERTIFICATE,
        ).firstNotNullOfOrNull { prefix ->
            if (startsWith(prefix) && length > prefix.length) substring(prefix.length) else null
        } ?: this

    fun Parcel.hasException(): Boolean {
        return runCatching { readException() }.exceptionOrNull() != null
    }
}
