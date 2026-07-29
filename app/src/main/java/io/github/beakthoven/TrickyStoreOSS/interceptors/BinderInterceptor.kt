/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.logging.TAG

open class BinderInterceptor : Binder() {

    /** Transaction codes to forward to Java hooks; empty intercepts all. */
    open val interceptedCodes: IntArray
        get() = IntArray(0)

    sealed class Result

    data object Skip : Result()

    data object Continue : Result()

    data class OverrideReply(val code: Int = 0, val reply: Parcel) : Result()

    companion object {
        private const val BACKDOOR_TRANSACTION_CODE = 0xdeadbeef.toInt()

        private const val REGISTER_INTERCEPTOR_CODE = 1

        private const val PRE_TRANSACT_CODE = 1
        private const val POST_TRANSACT_CODE = 2

        private const val RESULT_SKIP = 1
        private const val RESULT_CONTINUE = 2
        private const val RESULT_OVERRIDE_REPLY = 3

        fun getBinderBackdoor(binder: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            return try {
                val success = binder.transact(BACKDOOR_TRANSACTION_CODE, data, reply, 0)
                if (success) {
                    Log.d(TAG, "Backdoor access granted for binder: $binder")
                    reply.readStrongBinder()
                } else {
                    Log.d(TAG, "Backdoor access denied for binder: $binder")
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to access binder backdoor", e)
                null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        fun registerBinderInterceptor(backdoor: IBinder, target: IBinder, interceptor: BinderInterceptor) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                data.writeIntArray(interceptor.interceptedCodes)
                backdoor.transact(REGISTER_INTERCEPTOR_CODE, data, reply, 0)
                Log.d(TAG, "Registered interceptor for target: $target")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register binder interceptor", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    }

    open fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): Result = Skip

    open fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): Result = Skip

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        return try {
            val result =
                when (code) {
                    PRE_TRANSACT_CODE -> handlePreTransact(data)
                    POST_TRANSACT_CODE -> handlePostTransact(data)
                    else -> return super.onTransact(code, data, reply, flags)
                }
            writeResultToReply(result, reply!!)
            true
        } catch (e: Throwable) {
            Log.e(TAG, "onTransact uncaught exception", e)
            try {
                reply?.setDataPosition(0)
                reply?.setDataSize(0)
                reply?.writeInt(RESULT_SKIP)
            } catch (_: Throwable) {}
            true
        }
    }

    private fun handlePreTransact(data: Parcel): Result {
        val target = data.readStrongBinder()
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val dataSize = data.readLong()

        val transactionData = Parcel.obtain()
        return try {
            transactionData.appendFrom(data, data.dataPosition(), dataSize.toInt())
            transactionData.setDataPosition(0)
            onPreTransact(target, transactionCode, transactionFlags, callingUid, callingPid, transactionData)
        } catch (e: Throwable) {
            Log.e(TAG, "handlePreTransact exception code=$transactionCode uid=$callingUid", e)
            Skip
        } finally {
            transactionData.recycle()
        }
    }

    private fun handlePostTransact(data: Parcel): Result {
        val target = data.readStrongBinder()
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val resultCode = data.readInt()

        val transactionData = Parcel.obtain()
        val transactionReply = Parcel.obtain()

        return try {
            val dataSize = data.readLong().toInt()
            transactionData.appendFrom(data, data.dataPosition(), dataSize)
            transactionData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)

            val replySize = data.readLong().toInt()
            val reply =
                if (replySize > 0) {
                    transactionReply.appendFrom(data, data.dataPosition(), replySize)
                    transactionReply.setDataPosition(0)
                    transactionReply
                } else null

            onPostTransact(
                target,
                transactionCode,
                transactionFlags,
                callingUid,
                callingPid,
                transactionData,
                reply,
                resultCode,
            )
        } catch (e: Throwable) {
            Log.e(TAG, "handlePostTransact exception code=$transactionCode uid=$callingUid", e)
            Skip
        } finally {
            transactionData.recycle()
            transactionReply.recycle()
        }
    }

    private fun writeResultToReply(result: Result, reply: Parcel) {
        try {
            when (result) {
                Skip -> reply.writeInt(RESULT_SKIP)
                Continue -> reply.writeInt(RESULT_CONTINUE)
                is OverrideReply -> {
                    reply.writeInt(RESULT_OVERRIDE_REPLY)
                    reply.writeInt(result.code)
                    reply.writeLong(result.reply.dataSize().toLong())
                    reply.appendFrom(result.reply, 0, result.reply.dataSize())
                    result.reply.recycle()
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "writeResultToReply exception", e)
            try {
                reply.setDataPosition(0)
                reply.setDataSize(0)
                reply.writeInt(RESULT_SKIP)
            } catch (_: Throwable) {}
        }
    }
}
