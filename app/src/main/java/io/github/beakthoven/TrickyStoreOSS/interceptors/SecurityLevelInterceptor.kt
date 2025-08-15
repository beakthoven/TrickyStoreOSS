/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import androidx.annotation.Keep
import io.github.beakthoven.TrickyStoreOSS.CertificateHacker
import io.github.beakthoven.TrickyStoreOSS.core.config.Config
import io.github.beakthoven.TrickyStoreOSS.core.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val deleteKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "deleteKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")

        @Keep
        val keys = ConcurrentHashMap<Key, Info>()

        @Keep
        val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        @Keep
        val skipLeafHacks = ConcurrentHashMap<Key, Boolean>()

        @Keep
        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response

        @Keep
        fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? =
            keyPairs[Key(uid, alias)]

        @Keep
        fun shouldSkipLeafHack(uid: Int, alias: String): Boolean =
            skipLeafHacks[Key(uid, alias)] ?: false
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (code == generateKeyTransaction) {
            Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
            kotlin.runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor =
                    data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val aFlags = data.readInt()
                val entropy = data.createByteArray()
                val kgp = CertificateHacker.KeyGenParameters(params)
                if (Config.needGenerate(callingUid)) {
                    val pair = CertificateHacker.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                        ?: return@runCatching
                    keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                    val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                    val p = Parcel.obtain()
                    p.writeNoException()
                    p.writeTypedObject(response.metadata, 0)
                    return OverrideReply(0, p)
                } else if (Config.needHack(callingUid)) {
                    if ((kgp.purpose.contains(7)) || (attestationKeyDescriptor != null)) {
                        Logger.i("Generating key in generation mode for attestation: uid=$callingUid alias=${keyDescriptor.alias}")
                        val pair = CertificateHacker.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                            ?: return@runCatching
                        keyPairs[Key(callingUid, keyDescriptor.alias)] = Pair(pair.first, pair.second)
                        val response = buildResponse(pair.second, kgp, attestationKeyDescriptor ?: keyDescriptor)
                        keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                        SecurityLevelInterceptor.skipLeafHacks[Key(callingUid, keyDescriptor.alias)] = true
                        val p = Parcel.obtain()
                        p.writeNoException()
                        p.writeTypedObject(response.metadata, 0)
                        return OverrideReply(0, p)
                    } else {
                        skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                        Logger.i("Cleared skip flag for non-attestation key: uid=$callingUid alias=${keyDescriptor.alias}")
                        return Skip
                    }
                }
            }.onFailure {
                Logger.e("parse key gen request", it)
            }
        }
        return Skip
    }

    private fun buildResponse(
        chain: List<Certificate>,
        params: CertificateHacker.KeyGenParameters,
        descriptor: KeyDescriptor
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        metadata.putCertificateChain(chain.toTypedArray()).getOrThrow()
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest.toList()) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true)
        a.securityLevel = level
        authorizations.add(a)
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}