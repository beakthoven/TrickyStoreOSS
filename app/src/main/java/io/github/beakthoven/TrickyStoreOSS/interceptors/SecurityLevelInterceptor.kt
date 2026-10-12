/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.system.keystore2.Authorization
import android.system.keystore2.Domain
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import android.system.keystore2.KeyParameters
import android.system.keystore2.KeyPermission
import android.system.keystore2.ResponseCode
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
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.LockSupport

private const val MAX_ATTESTATION_CHALLENGE_BYTES = 128

class SecurityLevelInterceptor(private val original: IKeystoreSecurityLevel, private val level: Int) :
    BinderInterceptor() {
    override val interceptedCodes: IntArray by lazy {
        intArrayOf(generateKeyTransaction, createOperationTransaction, importKeyTransaction)
            .filter { it >= 0 }
            .toIntArray()
    }

    // software forges reply faster than real TEE keygen, which timing probes pick up —
    // pad forged replies to the measured real latency (EMA of forwarded generateKey calls)
    @Volatile private var realKeygenEmaMs: Double? = null
    private val pendingKeygenStarts = ConcurrentHashMap<String, Long>()

    companion object {
        private const val DEFAULT_KEYGEN_MS = 3.0
        private const val MAX_PLAUSIBLE_TIMESTAMP_MS = 4_102_444_800_000L
        private val generateKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val createOperationTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        private val importKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")

        private val secureRandom = SecureRandom()

        private fun softwarePolicySupported(params: Array<KeyParameter>): Boolean {
            val noAuth = params.filter { it.tag == Tag.NO_AUTH_REQUIRED }
            if (noAuth.size != 1 || runCatching { !noAuth.single().value.boolValue }.getOrDefault(true)) return false
            return params.none {
                it.tag == Tag.USER_SECURE_ID ||
                    it.tag == Tag.USER_AUTH_TYPE ||
                    it.tag == Tag.AUTH_TIMEOUT ||
                    it.tag == Tag.ALLOW_WHILE_ON_BODY ||
                    it.tag == Tag.TRUSTED_USER_PRESENCE_REQUIRED ||
                    it.tag == Tag.TRUSTED_CONFIRMATION_REQUIRED ||
                    it.tag == Tag.UNLOCKED_DEVICE_REQUIRED ||
                    it.tag == Tag.EARLY_BOOT_ONLY ||
                    it.tag == Tag.ROLLBACK_RESISTANCE ||
                    it.tag == Tag.STORAGE_KEY ||
                    it.tag == Tag.IDENTITY_CREDENTIAL_KEY ||
                    it.tag == Tag.MIN_SECONDS_BETWEEN_OPS ||
                    it.tag == Tag.MAX_USES_PER_BOOT
            }
        }

        @Keep val keys = ConcurrentHashMap<Key, Info>()

        @Keep val keyPairs = ConcurrentHashMap<Key, Pair<KeyPair, List<Certificate>>>()

        @Keep val skipLeafHacks = ConcurrentHashMap<Key, Boolean>()

        @Keep val keysByNspace = ConcurrentHashMap<Long, Key>()

        @Keep val patchedResponses = ConcurrentHashMap<Key, KeyEntryResponse>()

        @Keep fun getKeyPairs(uid: Int, alias: String): Pair<KeyPair, List<Certificate>>? = keyPairs[Key(uid, alias)]

        @Keep
        fun findAliasForNspace(uid: Int, nspace: Long): String? {
            val key = keysByNspace[nspace]?.takeIf { it.uid == uid } ?: return null
            return key.alias
        }

        enum class AccessAction(val permission: Int) {
            GET_INFO(KeyPermission.GET_INFO),
            USE(KeyPermission.USE),
            UPDATE(KeyPermission.UPDATE),
            DELETE(KeyPermission.DELETE),
            GRANT(KeyPermission.GRANT),
        }

        enum class DescriptorProvenance { APP_OWNER, KEY_ID_OWNER, GRANT }

        data class AuthorizedKey(
            val key: Key,
            val info: Info?,
            val provenance: DescriptorProvenance,
            val accessVector: Int,
            val allowed: Boolean,
        )

        @Keep val grants = ConcurrentHashMap<Long, GrantInfo>()

        @Keep
        fun resolveAuthorizedKey(uid: Int, descriptor: KeyDescriptor, action: AccessAction): AuthorizedKey? {
            val key: Key
            val provenance: DescriptorProvenance
            val accessVector: Int
            when (descriptor.domain) {
                Domain.APP -> {
                    // keystore2 uses -1 as the APP namespace sentinel for the calling UID.
                    if (descriptor.nspace != -1L && descriptor.nspace != uid.toLong()) return null
                    key = descriptor.alias?.let { Key(uid, it) } ?: return null
                    provenance = DescriptorProvenance.APP_OWNER
                    accessVector = OWNER_ACCESS
                }
                Domain.KEY_ID -> {
                    key = keysByNspace[descriptor.nspace]?.takeIf { it.uid == uid } ?: return null
                    provenance = DescriptorProvenance.KEY_ID_OWNER
                    accessVector = OWNER_ACCESS
                }
                Domain.GRANT -> {
                    val grant = grants[descriptor.nspace]?.takeIf { it.granteeUid == uid } ?: return null
                    key = grant.key
                    provenance = DescriptorProvenance.GRANT
                    accessVector = grant.accessVector
                }
                else -> return null
            }
            return withKeyLock(key) {
                if (descriptor.domain == Domain.KEY_ID && keysByNspace[descriptor.nspace] != key) return@withKeyLock null
                if (descriptor.domain == Domain.GRANT && grants[descriptor.nspace]?.let {
                        it.granteeUid == uid && it.key == key
                    } != true) return@withKeyLock null
                AuthorizedKey(
                    key,
                    keys[key],
                    provenance,
                    accessVector,
                    accessVector and action.permission != 0,
                )
            }
        }

        private const val OWNER_ACCESS = KeyPermission.GET_INFO or KeyPermission.USE or KeyPermission.UPDATE or
            KeyPermission.DELETE or KeyPermission.GRANT

        @Keep
        fun resolveDesignatedAttestationKey(uid: Int, descriptor: KeyDescriptor): AuthorizedKey? =
            resolveAuthorizedKey(uid, descriptor, AccessAction.USE)?.takeIf { it.allowed }

        @Keep
        fun findGeneratedKey(uid: Int, descriptor: KeyDescriptor): Info? =
            resolveAuthorizedKey(uid, descriptor, AccessAction.GET_INFO)?.takeIf { it.allowed }?.info

        @Keep
        fun resolvePatchedResponse(uid: Int, descriptor: KeyDescriptor): KeyEntryResponse? {
            val resolved = resolveAuthorizedKey(uid, descriptor, AccessAction.GET_INFO)?.takeIf { it.allowed } ?: return null
            return patchedResponses[resolved.key]
        }

        @Keep fun isPatchedKey(key: Key): Boolean = keys.containsKey(key) || patchedResponses.containsKey(key)

        @Keep
        fun shouldSkipLeafHackFor(uid: Int, descriptor: KeyDescriptor): Boolean {
            val resolved = resolveAuthorizedKey(uid, descriptor, AccessAction.GET_INFO)?.takeIf { it.allowed }
                ?: return false
            return skipLeafHacks[resolved.key] ?: false
        }

        @Keep
        fun resolveKey(uid: Int, descriptor: KeyDescriptor): Key? =
            resolveAuthorizedKey(uid, descriptor, AccessAction.GET_INFO)?.takeIf { it.allowed }?.key

        @Keep
        fun updateKeyCertChain(key: Key, publicCert: ByteArray?, certificateChain: ByteArray?): Boolean = withKeyLock(key) {
            val info = keys[key] ?: return@withKeyLock false
            val certs = runCatching {
                with(CertificateUtils) {
                    (publicCert?.toCertificate()?.let { listOf<Certificate>(it) } ?: emptyList()) +
                        (certificateChain?.toCertificates() ?: emptyList())
                }
            }.getOrNull() ?: return@withKeyLock false
            val metadata = copyMetadata(info.response.metadata) ?: return@withKeyLock false
            val ownerIdentity = PkgConfig.getPm()?.let { AndroidUtils.packageSigningIdentityFingerprint(it, key.uid) }
                ?: return@withKeyLock false
            metadata.certificate = publicCert
            metadata.certificateChain = certificateChain
            metadata.modificationTimeMs = System.currentTimeMillis()
            val saved = PersistenceManager.saveKey(
                key.uid, key.alias, metadata.keySecurityLevel, false, metadata.key?.nspace ?: 0L,
                Domain.APP, info.keyPair, info.secretKey, certs, marshalMetadata(metadata), info.params,
                currentUseState(key, info.params), ownerIdentity,
            )
            if (!saved) {
                Logger.e("Unable to persist certificate update uid=${key.uid} alias=${key.alias}")
                return@withKeyLock false
            }
            info.response.metadata = metadata
            patchedResponses[key]?.metadata = copyMetadata(metadata) ?: metadata
            info.keyPair?.let { keyPairs[key] = it to certs }
            skipLeafHacks.remove(key)
            true
        }

        private fun copyMetadata(metadata: KeyMetadata): KeyMetadata? =
            marshalMetadata(metadata)?.let(::unmarshalMetadata)

        private fun unmarshalMetadata(bytes: ByteArray): KeyMetadata? = runCatching {
            Parcel.obtain().let { p ->
                try {
                    p.unmarshall(bytes, 0, bytes.size)
                    p.setDataPosition(0)
                    p.readTypedObject(KeyMetadata.CREATOR)
                } finally {
                    p.recycle()
                }
            }
        }.getOrNull()

        private fun marshalMetadata(metadata: KeyMetadata): ByteArray? = runCatching {
            Parcel.obtain().let { p ->
                try {
                    p.writeTypedObject(metadata, 0)
                    p.marshall()
                } finally {
                    p.recycle()
                }
            }
        }.getOrNull()

        private fun currentUseState(key: Key, params: CertificateGen.KeyGenParameters): PersistenceManager.UseState? =
            if (params.usageCountLimit <= 0 && params.maxUsesPerBoot <= 0) null else
                PersistenceManager.UseState(
                    usageRemaining[key], perBootRemaining[key], bootIdentity(),
                )

        @Keep val usageRemaining = ConcurrentHashMap<Key, Int>()
        @Keep val perBootRemaining = ConcurrentHashMap<Key, Int>()
        private val usageLocks = ConcurrentHashMap<Key, Any>()

        internal fun <T> withKeyLock(key: Key, action: () -> T): T =
            synchronized(usageLocks.computeIfAbsent(key) { Any() }, action)

        @Keep
        fun consumeUsage(key: Key, params: CertificateGen.KeyGenParameters) {
            withKeyLock(key) {
                val lifetimeBefore = usageRemaining[key]
                val perBootBefore = perBootRemaining[key]
                if ((params.usageCountLimit > 0 && (lifetimeBefore ?: params.usageCountLimit) <= 0) ||
                    (params.maxUsesPerBoot > 0 && (perBootBefore ?: params.maxUsesPerBoot) <= 0)) {
                    throw ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_MAX_OPS_EXCEEDED, "Key usage limit exhausted")
                }
                if (params.usageCountLimit > 0) usageRemaining[key] = (lifetimeBefore ?: params.usageCountLimit) - 1
                if (params.maxUsesPerBoot > 0) perBootRemaining[key] = (perBootBefore ?: params.maxUsesPerBoot) - 1
                if (!persistUsageState(key)) {
                    if (lifetimeBefore == null) usageRemaining.remove(key) else usageRemaining[key] = lifetimeBefore
                    if (perBootBefore == null) perBootRemaining.remove(key) else perBootRemaining[key] = perBootBefore
                    throw ServiceSpecificException(ResponseCode.SYSTEM_ERROR, "Unable to persist key usage")
                }
            }
        }

        private fun persistUsageState(key: Key): Boolean {
            val info = keys[key] ?: return false
            val metadata = marshalMetadata(info.response.metadata) ?: return false
            return PersistenceManager.saveKey(
                key.uid, key.alias, info.response.metadata.keySecurityLevel, skipLeafHacks[key] == true,
                info.response.metadata.key?.nspace ?: 0L, Domain.KEY_ID, info.keyPair, info.secretKey,
                keyPairs[key]?.second, metadata, info.params, currentUseState(key, info.params),
                PkgConfig.getPm()?.let { AndroidUtils.packageSigningIdentityFingerprint(it, key.uid) },
            )
        }

        private fun bootIdentity(): String? = runCatching {
            File("/proc/sys/kernel/random/boot_id").readText().trim().takeIf { it.isNotEmpty() }
        }.getOrNull()

        private fun normalizeModificationTime(value: Long): Long {
            val now = System.currentTimeMillis()
            return if (value in 1..4_102_444_800L && value <= now / 1000L) value * 1000L else value
        }

        @Keep
        fun cleanupKey(uid: Int, alias: String): Boolean {
            val k = Key(uid, alias)
            return withKeyLock(k) {
                if (!PersistenceManager.deleteKey(uid, alias)) return@withKeyLock false
                keys[k]?.response?.metadata?.key?.nspace?.let { keysByNspace.remove(it) }
                keys.remove(k)
                keyPairs.remove(k)
                skipLeafHacks.remove(k)
                patchedResponses.remove(k)
                usageRemaining.remove(k)
                perBootRemaining.remove(k)
                grants.values.removeIf { it.key == k }
                CertificateHack.leafAlgorithms.remove(CertificateHack.KeyIdentifier(alias, uid))
                true
            }
        }

        @Keep
        fun invalidatePatchedResponses() {
            patchedResponses.clear()
            CertificateHack.clearLeafAlgorithms()
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

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): Result {
        if (code == importKeyTransaction) {
            return if (PkgConfig.needHack(callingUid) || PkgConfig.needGenerate(callingUid)) Continue else Skip
        }
        if (code == generateKeyTransaction) {
            val startNanos = System.nanoTime()
            Logger.d("intercept key gen uid=$callingUid pid=$callingPid")
            val raw = runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)!!
                val aFlags = data.readInt()
                val entropy = data.createByteArray()
                val hasSoftwareTarget = PkgConfig.needGenerate(callingUid)
                val hasLeafTarget = PkgConfig.needHack(callingUid)
                if (!hasSoftwareTarget && !hasLeafTarget) return Skip
                if (!softwarePolicySupported(params)) {
                    Logger.i("Forwarding unsupported or incomplete authorization policy uid=$callingUid")
                    return Skip
                }
                val kgp = CertificateGen.KeyGenParameters(params)
                val challenge = kgp.attestationChallenge
                if (challenge != null && challenge.size > MAX_ATTESTATION_CHALLENGE_BYTES) {
                    Logger.i(
                        "Rejecting oversized attestation challenge (${challenge.size}B > $MAX_ATTESTATION_CHALLENGE_BYTES) uid=$callingUid alias=${keyDescriptor.alias}"
                    )
                    return errorReply(KeymasterDefs.KM_ERROR_INVALID_INPUT_LENGTH, "Oversized attestation challenge")
                }
                if (keyDescriptor.alias == null) {
                    Logger.d("KeyDescriptor has null alias (KEY_ID domain), passing through to real keystore")
                    return Skip
                }
                if (params.any { it.tag == Tag.CREATION_DATETIME }) {
                    Logger.i("Rejecting caller-supplied CREATION_DATETIME uid=$callingUid alias=${keyDescriptor.alias}")
                    return errorReply(ResponseCode.INVALID_ARGUMENT, "CREATION_DATETIME is auto-injected")
                }
                val hasDeviceIdAttestation = params.any {
                    it.tag == Tag.ATTESTATION_ID_IMEI ||
                        it.tag == Tag.ATTESTATION_ID_MEID ||
                        it.tag == Tag.ATTESTATION_ID_SERIAL ||
                        it.tag == Tag.ATTESTATION_ID_SECOND_IMEI ||
                        it.tag == Tag.DEVICE_UNIQUE_ATTESTATION
                }
                if (
                    hasDeviceIdAttestation &&
                        !PkgConfig.hasPermissionForUid(callingUid, "android.permission.READ_PRIVILEGED_PHONE_STATE")
                ) {
                    Logger.i("Rejecting device ID attestation without READ_PRIVILEGED_PHONE_STATE uid=$callingUid")
                    return errorReply(
                        KeymasterDefs.KM_ERROR_CANNOT_ATTEST_IDS,
                        "Caller lacks READ_PRIVILEGED_PHONE_STATE",
                    )
                }
                if (attestationKeyDescriptor != null) {
                    val designated = resolveAuthorizedKey(callingUid, attestationKeyDescriptor, AccessAction.USE)
                    if (designated?.info == null) {
                        return if (PkgConfig.needHack(callingUid)) forwardKeygen(keyDescriptor.alias, startNanos) else Skip
                    }
                    if (!designated.allowed) return errorReply(ResponseCode.PERMISSION_DENIED, "USE permission not granted")
                    if (designated.info.params.purpose != listOf(KeyPurpose.ATTEST_KEY)) {
                        return errorReply(KeymasterDefs.KM_ERROR_INVALID_ARGUMENT, "Designated key is not an ATTEST_KEY")
                    }
                }
                val forceForge = hasSoftwareTarget
                when {
                    forceForge -> {
                        val isSymmetric = kgp.algorithm == Algorithm.AES || kgp.algorithm == Algorithm.HMAC
                        if (isSymmetric) {
                            // Symmetric keys are never used for attestation, so forging them
                            // gains nothing and breaks apps whose AES/HMAC operations don't
                            // match the forged key's parameters (e.g. AES-GCM decrypt without
                            // a digest tag -> KM_ERROR_UNSUPPORTED_DIGEST from authorizeOperation).
                            // Forward to the real keystore instead.
                            Logger.d(
                                "generateKey: forwarding symmetric key uid=$callingUid alias=${keyDescriptor.alias}"
                            )
                            return forwardKeygen(keyDescriptor.alias, startNanos)
                        }
                        val needsForgedAttestation =
                            challenge != null ||
                                hasDeviceIdAttestation ||
                                kgp.purpose.contains(KeyPurpose.ATTEST_KEY) ||
                                attestationKeyDescriptor != null
                        if (!needsForgedAttestation) {
                            // Plain asymmetric keys without any attestation request are
                            // only used for local crypto (e.g. RSA wrapping of stored
                            // secrets). Forging them injects digest/attestation
                            // authorizations the real operation cannot satisfy, which
                            // surfaces as KM_ERROR_UNSUPPORTED_DIGEST (-12) on begin().
                            // Forward to the real keystore instead.
                            Logger.d(
                                "generateKey: forwarding plain asymmetric key uid=$callingUid alias=${keyDescriptor.alias}"
                            )
                            return forwardKeygen(keyDescriptor.alias, startNanos)
                        }
                        val pair =
                            CertificateGen.generateKeyPair(
                                callingUid,
                                keyDescriptor,
                                attestationKeyDescriptor,
                                kgp,
                                level,
                            ) ?: return errorReply(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR, "Software attestation generation failed")
                        return storeGeneratedKey(
                            callingUid,
                            keyDescriptor,
                            kgp,
                            pair.first,
                            null,
                            pair.second,
                            PkgConfig.needHack(callingUid),
                            startNanos,
                        )
                    }
                    PkgConfig.needHack(callingUid) -> {
                        skipLeafHacks.remove(Key(callingUid, keyDescriptor.alias))
                        Logger.d(
                            "generateKey: forwarding non-attestation key uid=$callingUid alias=${keyDescriptor.alias}"
                        )
                        return forwardKeygen(keyDescriptor.alias, startNanos)
                    }
                    else -> return Skip
                }
            }
            raw.onFailure { Logger.e("parse key gen request", it) }
        }
        if (code == createOperationTransaction) {
            val raw = runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching null
                val resolved = resolveAuthorizedKey(callingUid, descriptor, AccessAction.USE)
                if (resolved == null || resolved.info == null) return@runCatching null
                if (!resolved.allowed) {
                    return@runCatching errorReply(ResponseCode.PERMISSION_DENIED, "USE permission not granted")
                }
                val info = resolved.info
                if (!info.params.noAuthRequiredIsValid) {
                    return@runCatching errorReply(ResponseCode.PERMISSION_DENIED, "Legacy or unsupported authorization policy")
                }
                val opParams = data.createTypedArray(KeyParameter.CREATOR) ?: emptyArray<KeyParameter>()
                // AIDL: createOperation(KeyDescriptor, KeyParameter[], boolean force)
                val force = data.dataAvail() > 0 && data.readBoolean()
                if (force) {
                    Logger.i("createOperation rejected: forced op uid=$callingUid alias=${descriptor.alias}")
                    return@runCatching errorReply(
                        ResponseCode.PERMISSION_DENIED,
                        "Forced operations require system privilege",
                    )
                }
                val key = resolveKey(callingUid, descriptor)
                if (key != null &&
                    ((info.params.usageCountLimit > 0 && (usageRemaining[key] ?: info.params.usageCountLimit) <= 0) ||
                        (info.params.maxUsesPerBoot > 0 && (perBootRemaining[key] ?: info.params.maxUsesPerBoot) <= 0))
                ) {
                    Logger.i("createOperation: usage exhausted uid=$callingUid alias=${descriptor.alias}")
                    return@runCatching errorReply(KeymasterDefs.KM_ERROR_KEY_MAX_OPS_EXCEEDED, "Key usage limit exhausted")
                }
                val opRequest = OpRequest.parse(opParams)
                val errCode = authorizeOperation(info.params, opRequest)
                if (errCode != null) {
                    Logger.i(
                        "createOperation rejected for uid=$callingUid alias=${descriptor.alias} nspace=${descriptor.nspace}: KM error $errCode"
                    )
                    return@runCatching errorReply(errCode, "Operation not authorized")
                }
                Logger.d(
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
            val result =
                raw.fold(
                    onSuccess = { it },
                    onFailure = {
                        Logger.e("handle createOperation request", it)
                        errorReply(
                            (it as? android.os.ServiceSpecificException)?.errorCode ?: ResponseCode.SYSTEM_ERROR,
                            "Software operation failed",
                        )
                    },
                )
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
            val raw = runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching null
                recordRealKeygen(keyDescriptor.alias)
                val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return@runCatching null
                val chain =
                    with(CertificateUtils) {
                        val leaf = metadata.certificate?.toCertificate() ?: return@runCatching null
                        val rest = metadata.certificateChain?.toCertificates() ?: emptyList()
                        (listOf<Certificate>(leaf) + rest).toTypedArray()
                    }
                val patched = CertificateHack.hackCertificateChain(chain, callingUid)
                metadata.putCertificateChain(patched).getOrThrow()
                metadata.authorizations = CertificateHack.patchAuthorizations(metadata.authorizations, callingUid)
                val response =
                    KeyEntryResponse().apply {
                        this.metadata = metadata
                        iSecurityLevel = original
                    }
                patchedResponses[Key(callingUid, keyDescriptor.alias)] = response
                metadata.key?.nspace?.let { nspace ->
                    if (nspace != 0L) keysByNspace[nspace] = Key(callingUid, keyDescriptor.alias)
                }
                Logger.i("Patched generateKey chain for uid=$callingUid alias=${keyDescriptor.alias}")
                typedReply(metadata)
            }
            val result = raw.onFailure { Logger.e("patch generateKey reply", it) }.getOrNull()
            if (result != null) return result
        }
        if (code == importKeyTransaction && reply != null && !reply.hasException()) {
            val raw = runCatching {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
                Logger.i(
                    "importKey succeeded, clearing generated state for uid=$callingUid alias=${keyDescriptor.alias}"
                )
                cleanupKey(callingUid, keyDescriptor.alias)
            }
            raw.onFailure { Logger.e("parse importKey request", it) }
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
        startNanos: Long,
    ): Result {
        val ownerIdentityFingerprint = PkgConfig.getPm()?.let {
            AndroidUtils.packageSigningIdentityFingerprint(it, callingUid)
        } ?: return errorReply(ResponseCode.SYSTEM_ERROR, "Unable to verify key owner identity")
        val key = Key(callingUid, keyDescriptor.alias)
        val result = withKeyLock(key) {
            val previousNspace = keys[key]?.response?.metadata?.key?.nspace
            keyDescriptor.nspace = secureRandom.nextLong()
            val response = buildResponse(chain, kgp, keyDescriptor, callingUid)
            val boot = bootIdentity()
            if (keyPair != null || secretKey != null) {
                val saved = PersistenceManager.saveKey(
                    callingUid, keyDescriptor.alias, level, skipLeafHack, keyDescriptor.nspace,
                    keyDescriptor.domain, keyPair, secretKey, chain, marshalKeyMetadata(response.metadata), kgp,
                    PersistenceManager.UseState(
                        kgp.usageCountLimit.takeIf { it > 0 },
                        kgp.maxUsesPerBoot.takeIf { it > 0 },
                        boot,
                    ),
                    ownerIdentityFingerprint,
                )
                if (!saved) return@withKeyLock null
            }
            previousNspace?.let { keysByNspace.remove(it, key) }
            keys[key] = Info(keyPair, secretKey, response, kgp)
            keyPairs.remove(key)
            if (keyPair != null && chain != null) keyPairs[key] = keyPair to chain
            keysByNspace[keyDescriptor.nspace] = key
            if (kgp.usageCountLimit > 0) usageRemaining[key] = kgp.usageCountLimit else usageRemaining.remove(key)
            if (kgp.maxUsesPerBoot > 0) perBootRemaining[key] = kgp.maxUsesPerBoot else perBootRemaining.remove(key)
            if (skipLeafHack) skipLeafHacks[key] = true else skipLeafHacks.remove(key)
            response
        } ?: return errorReply(ResponseCode.SYSTEM_ERROR, "Unable to persist generated key")
        padForgedKeygen(startNanos)
        return typedReply(result.metadata)
    }

    private fun forwardKeygen(alias: String?, startNanos: Long): Result {
        alias?.let { pendingKeygenStarts[it] = startNanos }
        return Continue
    }

    private fun recordRealKeygen(alias: String?) {
        val start = alias?.let { pendingKeygenStarts.remove(it) } ?: return
        val elapsedMs = (System.nanoTime() - start) / 1_000_000.0
        if (elapsedMs in 0.3..80.0) realKeygenEmaMs = realKeygenEmaMs?.let { it * 0.75 + elapsedMs * 0.25 } ?: elapsedMs
    }

    private fun padForgedKeygen(startNanos: Long) {
        val targetMs =
            (realKeygenEmaMs ?: DEFAULT_KEYGEN_MS) * (1.0 + (secureRandom.nextGaussian() * 0.06).coerceIn(-0.15, 0.25))
        val remainingNanos = (targetMs * 1_000_000).toLong() - (System.nanoTime() - startNanos)
        if (remainingNanos > 0) LockSupport.parkNanos(remainingNanos)
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
        val createdAtMs = params.createdAtMs ?: System.currentTimeMillis().also { params.createdAtMs = it }
        metadata.modificationTimeMs = createdAtMs
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
        fun sw(tag: Int, value: KeyParameterValue) =
            authorizations.add(auth(tag, value, 0 /* SoftwareLevel.SOFTWARE */))

        tee(Tag.ALGORITHM, KeyParameterValue.algorithm(params.algorithm))
        for (i in params.purpose) tee(Tag.PURPOSE, KeyParameterValue.keyPurpose(i))
        for (i in params.blockMode) tee(Tag.BLOCK_MODE, KeyParameterValue.blockMode(i))
        for (i in params.digest) tee(Tag.DIGEST, KeyParameterValue.digest(i))
        for (i in params.padding) tee(Tag.PADDING, KeyParameterValue.paddingMode(i))
        for (i in params.mgfDigest) tee(Tag.RSA_OAEP_MGF_DIGEST, KeyParameterValue.digest(i))
        val effectiveKey = CertificateGen.effectiveKeySize(params)
        if (effectiveKey > 0) tee(Tag.KEY_SIZE, KeyParameterValue.integer(effectiveKey))

        if (params.algorithm == Algorithm.EC && params.ecCurve != 0)
            tee(Tag.EC_CURVE, KeyParameterValue.ecCurve(params.ecCurve))
        params.rsaPublicExponent?.let { tee(Tag.RSA_PUBLIC_EXPONENT, KeyParameterValue.longInteger(it.toLong())) }

        if (params.noAuthRequired == true) tee(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true))
        tee(Tag.ORIGIN, KeyParameterValue.origin(params.origin ?: 0))
        tee(Tag.OS_VERSION, KeyParameterValue.integer(AndroidUtils.osVersion))

        if (AndroidUtils.patchLevel(callingUid) != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.patchLevel(callingUid)))
        if (AndroidUtils.vendorPatchLevelLong(callingUid) != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.VENDOR_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.vendorPatchLevelLong(callingUid)))
        if (AndroidUtils.bootPatchLevelLong(callingUid) != AndroidUtils.DO_NOT_REPORT)
            tee(Tag.BOOT_PATCHLEVEL, KeyParameterValue.integer(AndroidUtils.bootPatchLevelLong(callingUid)))

        authorizations.add(auth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(createdAtMs), SecurityLevel.KEYSTORE))
        params.activeDateTime?.let { sw(Tag.ACTIVE_DATETIME, KeyParameterValue.dateTime(it)) }
        params.originationExpireDateTime?.let { sw(Tag.ORIGINATION_EXPIRE_DATETIME, KeyParameterValue.dateTime(it)) }
        params.usageExpireDateTime?.let { sw(Tag.USAGE_EXPIRE_DATETIME, KeyParameterValue.dateTime(it)) }
        if (params.usageCountLimit > 0) sw(Tag.USAGE_COUNT_LIMIT, KeyParameterValue.integer(params.usageCountLimit))
        params.unlockedDeviceRequired?.let { sw(Tag.UNLOCKED_DEVICE_REQUIRED, KeyParameterValue.boolValue(it)) }
        if (params.callerNonce == true) tee(Tag.CALLER_NONCE, KeyParameterValue.boolValue(true))
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
        PersistenceManager.loadAll { uid ->
            PkgConfig.getPm()?.let { AndroidUtils.packageSigningIdentityFingerprint(it, uid) }
        }
            .filter { it.securityLevel == level }
            .forEach { pk ->
                val raw = runCatching {
                    val descriptor =
                        KeyDescriptor().apply {
                            domain = pk.domain
                            nspace = pk.nspace
                            alias = pk.alias
                        }
                    val metadata = pk.metadataBytes?.let { unmarshalKeyMetadata(it) }
                    val response =
                        if (metadata != null) {
                            if (pk.params.createdAtMs == null) {
                                val createdAt = metadata.authorizations
                                    ?.firstOrNull { it.keyParameter?.tag == Tag.CREATION_DATETIME }
                                    ?.keyParameter?.value?.dateTime
                                if (createdAt != null && createdAt in 0..MAX_PLAUSIBLE_TIMESTAMP_MS) {
                                    pk.params.createdAtMs = createdAt
                                }
                            }
                            metadata.modificationTimeMs = normalizeModificationTime(metadata.modificationTimeMs)
                            KeyEntryResponse().apply {
                                this.metadata = metadata
                                iSecurityLevel = original
                            }
                        } else {
                            buildResponse(pk.chain, pk.params, descriptor, pk.uid)
                        }
                    val key = Key(pk.uid, pk.alias)
                    withKeyLock(key) {
                        keys[key] = Info(pk.keyPair, pk.secretKey, response, pk.params)
                        if (pk.keyPair != null) keyPairs[key] = Pair(pk.keyPair, pk.chain) else keyPairs.remove(key)
                        if (pk.nspace != 0L) keysByNspace[pk.nspace] = key
                        if (pk.skipLeafHack) skipLeafHacks[key] = true else skipLeafHacks.remove(key)
                        pk.useState?.let { state ->
                            if (pk.params.usageCountLimit > 0) usageRemaining[key] = state.lifetimeRemaining ?: 0
                            if (pk.params.maxUsesPerBoot > 0) {
                                perBootRemaining[key] = if (state.bootIdentity == bootIdentity()) state.perBootRemaining ?: 0 else pk.params.maxUsesPerBoot
                            }
                        }
                        if (pk.ownerIdentityFingerprint != null) {
                            val normalized = metadata?.let { marshalKeyMetadata(it) }
                            val state = currentUseState(key, pk.params)
                            if (normalized != null && (pk.useState?.bootIdentity != bootIdentity() || pk.params.createdAtMs != null)) {
                                PersistenceManager.saveKey(
                                    pk.uid, pk.alias, level, pk.skipLeafHack, pk.nspace, pk.domain,
                                    pk.keyPair, pk.secretKey, pk.chain, normalized, pk.params, state,
                                    pk.ownerIdentityFingerprint,
                                )
                            }
                        }
                    }
                    Logger.i("Restored persisted key uid=${pk.uid} alias=${pk.alias}")
                }
                raw.onFailure { Logger.e("Failed to restore persisted key uid=${pk.uid} alias=${pk.alias}", it) }
            }
    }

    private fun marshalKeyMetadata(metadata: KeyMetadata): ByteArray? {
        val raw = runCatching {
            val p = Parcel.obtain()
            try {
                p.writeTypedObject(metadata, 0)
                p.marshall()
            } finally {
                p.recycle()
            }
        }
        return raw.getOrNull()
    }

    private fun unmarshalKeyMetadata(bytes: ByteArray): KeyMetadata? {
        val raw = runCatching {
            val p = Parcel.obtain()
            try {
                p.unmarshall(bytes, 0, bytes.size)
                p.setDataPosition(0)
                p.readTypedObject(KeyMetadata.CREATOR)
            } finally {
                p.recycle()
            }
        }
        return raw.getOrNull()
    }
}
