/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import android.system.keystore2.KeyParameters
import androidx.annotation.Keep
import io.github.beakthoven.TrickyStoreOSS.AndroidUtils
import io.github.beakthoven.TrickyStoreOSS.CertificateGen
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.PersistenceManager
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.errorReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.typedReply
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap

private const val MAX_ATTESTATION_CHALLENGE_BYTES = 128

private const val KM_ERROR_INVALID_INPUT_LENGTH = -21

class SecurityLevelInterceptor(private val original: IKeystoreSecurityLevel, private val level: Int) : BinderInterceptor() {
    override val interceptedCodes: IntArray by lazy {
        intArrayOf(
            generateKeyTransaction,
            createOperationTransaction,
            importKeyTransaction,
        ).filter { it >= 0 }.toIntArray()
    }
    companion object {
        private val generateKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val createOperationTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val importKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")

        private val secureRandom = SecureRandom()

        @Keep val keys = ConcurrentHashMap<Key, Info>()

        @Keep val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        @Keep val skipLeafHacks = ConcurrentHashMap<Key, Boolean>()

        @Keep val keysByNspace = ConcurrentHashMap<Long, Key>()

        @Keep val patchedResponses = ConcurrentHashMap<Key, KeyEntryResponse>()

        @Keep fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? = keyPairs[Key(uid, alias)]

        @Keep
        fun findGeneratedKeyByKeyId(uid: Int, nspace: Long): Info? {
            val k = keysByNspace[nspace] ?: return null
            return if (k.uid == uid) keys[k] else null
        }

        @Keep
        fun findGeneratedKey(uid: Int, descriptor: KeyDescriptor): Info? {
            if (descriptor.nspace != 0L) {
                findGeneratedKeyByKeyId(uid, descriptor.nspace)?.let {
                    return it
                }
                grants[descriptor.nspace]
                    ?.takeIf { it.granteeUid == uid }
                    ?.let { g ->
                        keys[g.key]?.let {
                            return it
                        }
                    }
            }
            return descriptor.alias?.let { keys[Key(uid, it)] }
        }

        @Keep
        fun resolvePatchedResponse(uid: Int, descriptor: KeyDescriptor): KeyEntryResponse? {
            if (descriptor.nspace != 0L) {
                keysByNspace[descriptor.nspace]
                    ?.takeIf { it.uid == uid }
                    ?.let {
                        return patchedResponses[it]
                    }
                grants[descriptor.nspace]
                    ?.takeIf { it.granteeUid == uid }
                    ?.let { g ->
                        patchedResponses[g.key]?.let {
                            return it
                        }
                    }
            }
            return descriptor.alias?.let { patchedResponses[Key(uid, it)] }
        }

        @Keep
        fun shouldSkipLeafHackFor(uid: Int, descriptor: KeyDescriptor): Boolean {
            if (descriptor.nspace != 0L) {
                keysByNspace[descriptor.nspace]
                    ?.takeIf { it.uid == uid }
                    ?.let {
                        return skipLeafHacks[it] ?: false
                    }
                grants[descriptor.nspace]
                    ?.takeIf { it.granteeUid == uid }
                    ?.let { g ->
                        return skipLeafHacks[g.key] ?: false
                    }
            }
            return descriptor.alias?.let { skipLeafHacks[Key(uid, it)] } ?: false
        }

        @Keep val grants = ConcurrentHashMap<Long, GrantInfo>()

        @Keep
        fun resolveKey(uid: Int, descriptor: KeyDescriptor): Key? {
            if (descriptor.nspace != 0L) {
                keysByNspace[descriptor.nspace]
                    ?.takeIf { it.uid == uid }
                    ?.let {
                        return it
                    }
            }
            return descriptor.alias?.let { Key(uid, it) }
        }

        @Keep
        fun updateKeyCertChain(key: Key, publicCert: ByteArray?, certificateChain: ByteArray?) {
            keys[key]?.let {
                it.response.metadata.certificate = publicCert
                it.response.metadata.certificateChain = certificateChain
            }
            patchedResponses[key]?.metadata?.let {
                it.certificate = publicCert
                it.certificateChain = certificateChain
            }
            skipLeafHacks.remove(key)
        }

        @Keep val usageRemaining = ConcurrentHashMap<Key, Int>()

        @Keep
        fun cleanupKey(uid: Int, alias: String) {
            val k = Key(uid, alias)
            keys[k]?.response?.metadata?.key?.nspace?.let { keysByNspace.remove(it) }
            keys.remove(k)
            keyPairs.remove(k)
            skipLeafHacks.remove(k)
            patchedResponses.remove(k)
            usageRemaining.remove(k)
            grants.values.removeIf { it.key == k }
            CertificateHack.leafAlgorithms.remove(CertificateHack.KeyIdentifier(alias, uid))
            PersistenceManager.deleteKey(uid, alias)
        }

        @Keep
        fun cleanupAll() {
            keys.clear()
            keyPairs.clear()
            skipLeafHacks.clear()
            patchedResponses.clear()
            keysByNspace.clear()
            usageRemaining.clear()
            grants.clear()
            PersistenceManager.clearAll()
        }
    }

    data class Key(val uid: Int, val alias: String)

    data class Info(
        val keyPair: KeyPair?,
        val secretKey: javax.crypto.SecretKey?,
        val response: KeyEntryResponse,
        val params: CertificateGen.KeyGenParameters,
    )

    data class GrantInfo(val ownerUid: Int, val granteeUid: Int, val key: Key, val accessVector: Int = 0)

    override fun onPreTransact(target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel): Result {
        if (code == importKeyTransaction) {
            return if (PkgConfig.needHack(callingUid) || PkgConfig.needGenerate(callingUid)) Continue else Skip
        }
        if (code == generateKeyTransaction) {
            Log.i(TAG, "intercept key gen uid=$callingUid pid=$callingPid")
            kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                    val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    val params = data.createTypedArray(KeyParameter.CREATOR)!!
                    val aFlags = data.readInt()
                    val entropy = data.createByteArray()
                    val kgp = CertificateGen.KeyGenParameters(params)
                    val challenge = kgp.attestationChallenge
                    if (challenge != null && challenge.size > MAX_ATTESTATION_CHALLENGE_BYTES) {
                        Log.i(TAG, 
                            "Rejecting oversized attestation challenge (${challenge.size}B > $MAX_ATTESTATION_CHALLENGE_BYTES) uid=$callingUid alias=${keyDescriptor.alias}"
                        )
                        return errorReply(KM_ERROR_INVALID_INPUT_LENGTH, "Oversized attestation challenge")
                    }
                    if (keyDescriptor.alias == null) {
                        Log.d(TAG, "KeyDescriptor has null alias (KEY_ID domain), passing through to real keystore")
                        return Skip
                    }
                    val hasDeviceIdAttestation = params.any {
                        it.tag == Tag.ATTESTATION_ID_IMEI || it.tag == Tag.ATTESTATION_ID_MEID ||
                            it.tag == Tag.ATTESTATION_ID_SERIAL || it.tag == Tag.ATTESTATION_ID_SECOND_IMEI ||
                            it.tag == Tag.DEVICE_UNIQUE_ATTESTATION
                    }
                    // device-ID/attest-key/BYO must be forged — real TEE can't do them; non-target UIDs too, or keystore2 fails with -66
                    val forceForge = PkgConfig.needGenerate(callingUid) || hasDeviceIdAttestation ||
                        kgp.purpose.contains(KeyPurpose.ATTEST_KEY) || attestationKeyDescriptor != null
                    when {
                        forceForge -> {
                            val isSymmetric = kgp.algorithm == Algorithm.AES || kgp.algorithm == Algorithm.HMAC
                            if (isSymmetric) {
                                val secretKey = CertificateGen.generateSecretKey(kgp) ?: return@runCatching
                                return storeGeneratedKey(callingUid, keyDescriptor, kgp, null, secretKey, null, false)
                            }
                            val pair =
                                CertificateGen.generateKeyPair(callingUid, keyDescriptor, attestationKeyDescriptor, kgp, level)
                                    ?: return@runCatching
                            return storeGeneratedKey(
                                callingUid, keyDescriptor, kgp, pair.first, null, pair.second, PkgConfig.needHack(callingUid)
                            )
                        }
                        PkgConfig.needHack(callingUid) -> {
                            skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                            Log.i(TAG,
                                "Forwarding non-attestation key to real keystore (post-hook will patch): uid=$callingUid alias=${keyDescriptor.alias}"
                            )
                            return Continue
                        }
                        else -> return Skip
                    }
                }
                .onFailure { Log.e(TAG, "parse key gen request", it) }
        }
        if (code == createOperationTransaction) {
            val result =
                kotlin
                    .runCatching {
                        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching null
                        val info = findGeneratedKey(callingUid, descriptor)
                        if (info == null) return@runCatching null
                        val opParams = data.createTypedArray(KeyParameter.CREATOR) ?: emptyArray<KeyParameter>()
                        val opRequest = OpRequest.parse(opParams)
                        val errCode = authorizeOperation(info.params, opRequest)
                        if (errCode != null) {
                            Log.i(TAG, 
                                "createOperation rejected for uid=$callingUid alias=${descriptor.alias} nspace=${descriptor.nspace}: KM error $errCode"
                            )
                            return@runCatching errorReply(errCode, "Operation not authorized")
                        }
                        Log.d(TAG, 
                            "createOperation: serving software operation for uid=$callingUid alias=${descriptor.alias} nspace=${descriptor.nspace}"
                        )
                        val op = SoftwareOperationBinder.create(info, opRequest, resolveKey(callingUid, descriptor))
                        val response =
                            CreateOperationResponse().apply {
                                iOperation = op
                                parameters = op.beginParameters?.let { KeyParameters().apply { keyParameter = it } }
                            }
                        typedReply(response)
                    }
                    .onFailure { Log.e(TAG, "handle createOperation request", it) }
                    .getOrNull()
            if (result != null) return result
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): Result {
        if (code == generateKeyTransaction && reply != null && !reply.hasException()) {
            val result =
                kotlin
                    .runCatching {
                        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching null
                        val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return@runCatching null
                        val chain =
                            CertificateUtils.run {
                                val leaf = metadata.certificate?.toCertificate()
                                val rest = metadata.certificateChain?.toCertificates() ?: emptyList()
                                if (leaf == null) null else (listOf<Certificate>(leaf) + rest).toTypedArray()
                            } ?: return@runCatching null
                        val patched = CertificateHack.hackCertificateChain(chain)
                        metadata.putCertificateChain(patched).getOrThrow()
                        metadata.authorizations = CertificateHack.patchAuthorizations(metadata.authorizations)
                        val response =
                            KeyEntryResponse().apply {
                                this.metadata = metadata
                                iSecurityLevel = original
                            }
                        patchedResponses[Key(callingUid, keyDescriptor.alias)] = response
                        metadata.key?.nspace?.let { nspace ->
                            if (nspace != 0L) keysByNspace[nspace] = Key(callingUid, keyDescriptor.alias)
                        }
                        Log.i(TAG, "Patched generateKey chain for uid=$callingUid alias=${keyDescriptor.alias}")
                        typedReply(metadata)
                    }
                    .onFailure { Log.e(TAG, "patch generateKey reply", it) }
                    .getOrNull()
            if (result != null) return result
        }
        if (code == importKeyTransaction && reply != null && !reply.hasException()) {
            kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                    Log.i(TAG, "importKey succeeded, clearing generated state for uid=$callingUid alias=${keyDescriptor.alias}")
                    cleanupKey(callingUid, keyDescriptor.alias)
                }
                .onFailure { Log.e(TAG, "parse importKey request", it) }
        }
        return Skip
    }

    private fun storeGeneratedKey(
        callingUid: Int,
        keyDescriptor: KeyDescriptor,
        kgp: CertificateGen.KeyGenParameters,
        keyPair: KeyPair?,
        secretKey: javax.crypto.SecretKey?,
        chain: List<Certificate>?,
        skipLeafHack: Boolean,
    ): Result {
        keyDescriptor.nspace = secureRandom.nextLong()
        val key = Key(callingUid, keyDescriptor.alias)
        keysByNspace[keyDescriptor.nspace] = key
        if (keyPair != null && chain != null) keyPairs[key] = Pair(keyPair, chain)
        val response = buildResponse(chain, kgp, keyDescriptor, callingUid)
        keys[key] = Info(keyPair, secretKey, response, kgp)
        if (kgp.usageCountLimit > 0) usageRemaining[key] = kgp.usageCountLimit
        if (skipLeafHack) skipLeafHacks[key] = true
        if (keyPair != null || secretKey != null) {
            PersistenceManager.saveKey(
                callingUid,
                keyDescriptor.alias,
                level,
                skipLeafHack,
                keyDescriptor.nspace,
                keyDescriptor.domain,
                keyPair,
                secretKey,
                chain,
                marshalKeyMetadata(response.metadata),
                kgp,
            )
        }
        return typedReply(response.metadata)
    }

    private fun buildResponse(
        chain: List<Certificate>?,
        params: CertificateGen.KeyGenParameters,
        descriptor: KeyDescriptor,
        callingUid: Int = 0,
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        metadata.modificationTimeMs = System.currentTimeMillis() / 1000
        if (chain != null && chain.isNotEmpty()) {
            metadata.putCertificateChain(chain.toTypedArray()).getOrThrow()
        } else {
            metadata.certificate = null
            metadata.certificateChain = null
        }
        val d = KeyDescriptor()
        d.domain = 4
        d.nspace = descriptor.nspace
        d.alias = null
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        fun tee(tag: Int, value: KeyParameterValue) = authorizations.add(auth(tag, value, level))
        fun sw(tag: Int, value: KeyParameterValue) = authorizations.add(auth(tag, value, 0 /* SoftwareLevel.SOFTWARE */))

        tee(Tag.ALGORITHM, KeyParameterValue.algorithm(params.algorithm))
        for (i in params.purpose) tee(Tag.PURPOSE, KeyParameterValue.keyPurpose(i))
        for (i in params.blockMode) tee(Tag.BLOCK_MODE, KeyParameterValue.blockMode(i))
        for (i in params.digest) tee(Tag.DIGEST, KeyParameterValue.digest(i))
        for (i in params.padding) tee(Tag.PADDING, KeyParameterValue.paddingMode(i))
        for (i in params.mgfDigest) tee(Tag.RSA_OAEP_MGF_DIGEST, KeyParameterValue.digest(i))
        tee(Tag.KEY_SIZE, KeyParameterValue.integer(params.keySize))

        if (params.algorithm == Algorithm.EC && params.ecCurve != 0) tee(Tag.EC_CURVE, KeyParameterValue.ecCurve(params.ecCurve))
        params.rsaPublicExponent?.let { tee(Tag.RSA_PUBLIC_EXPONENT, KeyParameterValue.longInteger(it.toLong())) }

        tee(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true))
        tee(Tag.ORIGIN, KeyParameterValue.origin(0)) // GENERATED
        tee(Tag.OS_VERSION, KeyParameterValue.integer(AndroidUtils.osVersion))

        if (AndroidUtils.patchLevel != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.patchLevel))
        if (AndroidUtils.vendorPatchLevelLong != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.VENDOR_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.vendorPatchLevelLong))
        if (AndroidUtils.bootPatchLevelLong != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.BOOT_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.bootPatchLevelLong))

        sw(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis()))
        sw(Tag.USER_ID, KeyParameterValue.integer(callingUid / 100000))

        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }

    private fun auth(tag: Int, value: KeyParameterValue, secLevel: Int): Authorization =
        Authorization().apply {
            keyParameter =
                KeyParameter().apply {
                    this.tag = tag
                    this.value = value
                }
            securityLevel = secLevel
        }

    fun loadPersistedKeys() {
        PersistenceManager.loadAll()
            .filter { it.securityLevel == level }
            .forEach { pk ->
                runCatching {
                        val descriptor =
                            KeyDescriptor().apply {
                                domain = pk.domain
                                nspace = pk.nspace
                                alias = pk.alias
                            }
                        val metadata = pk.metadataBytes?.let { unmarshalKeyMetadata(it) }
                        val response =
                            if (metadata != null) {
                                KeyEntryResponse().apply {
                                    this.metadata = metadata
                                    iSecurityLevel = original
                                }
                            } else {
                                buildResponse(pk.chain, pk.params, descriptor, pk.uid)
                            }
                        val key = Key(pk.uid, pk.alias)
                        keys[key] = Info(pk.keyPair, pk.secretKey, response, pk.params)
                        if (pk.keyPair != null) keyPairs[key] = Pair(pk.keyPair, pk.chain)
                        if (pk.nspace != 0L) keysByNspace[pk.nspace] = key
                        if (pk.skipLeafHack) skipLeafHacks[key] = true
                        Log.i(TAG, "Restored persisted key uid=${pk.uid} alias=${pk.alias}")
                    }
                    .onFailure { Log.e(TAG, "Failed to restore persisted key uid=${pk.uid} alias=${pk.alias}", it) }
            }
    }

    private fun marshalKeyMetadata(metadata: KeyMetadata): ByteArray? =
        runCatching {
                val p = Parcel.obtain()
                try {
                    p.writeTypedObject(metadata, 0)
                    p.marshall()
                } finally {
                    p.recycle()
                }
            }
            .getOrNull()

    private fun unmarshalKeyMetadata(bytes: ByteArray): KeyMetadata? =
        runCatching {
                val p = Parcel.obtain()
                try {
                    p.unmarshall(bytes, 0, bytes.size)
                    p.setDataPosition(0)
                    p.readTypedObject(KeyMetadata.CREATOR)
                } finally {
                    p.recycle()
                }
            }
            .getOrNull()
}
