/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.Algorithm
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyGenParameters
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object PersistenceManager {
    private const val FORMAT_VERSION = 4
    private const val LEGACY_FORMAT_VERSION = 3
    private const val MAX_RECORD_BYTES = 16 * 1024 * 1024
    private const val MAX_ALIAS_LENGTH = 4096
    private const val MAX_BLOB_BYTES = 8 * 1024 * 1024
    private const val MAX_CHAIN_COUNT = 64
    private const val MAX_INT_LIST_COUNT = 256
    private val dir = File("/data/adb/tricky_store/keys")

    data class UseState(
        val lifetimeRemaining: Int?,
        val perBootRemaining: Int?,
        val bootIdentity: String?,
    )

    sealed class LoadResult {
        data class Loaded(val keys: List<PersistedKey>, val skippedRecords: Int) : LoadResult()
        data class Failed(val reason: String) : LoadResult()
    }

    // single-threaded, off the binder thread — save/delete can't race
    private val keyLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()

    private fun keyLock(uid: Int, alias: String): Any = keyLocks.computeIfAbsent("$uid:$alias") { Any() }

    data class PersistedKey(
        val uid: Int,
        val alias: String,
        val securityLevel: Int,
        val skipLeafHack: Boolean,
        val nspace: Long,
        val domain: Int,
        val keyPair: KeyPair?,
        val secretKey: SecretKey?,
        val chain: List<Certificate>,
        val params: KeyGenParameters,
        val metadataBytes: ByteArray?,
        val useState: UseState? = null,
        val ownerIdentityFingerprint: ByteArray? = null,
    )

    private fun fileFor(uid: Int, alias: String): File {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val hash = md.digest(alias.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        return File(File(dir, uid.toString()), "$hash.bin")
    }

    fun saveKey(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, null, null)

    fun saveKey(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
        useState: UseState,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, useState, null)

    fun saveKey(
        uid: Int, alias: String, securityLevel: Int, skipLeafHack: Boolean, nspace: Long, domain: Int,
        keyPair: KeyPair?, secretKey: SecretKey?, chain: List<Certificate>?, metadataBytes: ByteArray?,
        params: KeyGenParameters, useState: UseState?, ownerIdentityFingerprint: ByteArray?,
    ): Boolean = saveKeySync(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, useState, ownerIdentityFingerprint)

    private fun saveKeySync(
        uid: Int,
        alias: String,
        securityLevel: Int,
        skipLeafHack: Boolean,
        nspace: Long,
        domain: Int,
        keyPair: KeyPair?,
        secretKey: SecretKey?,
        chain: List<Certificate>?,
        metadataBytes: ByteArray?,
        params: KeyGenParameters,
        useState: UseState?,
        ownerIdentityFingerprint: ByteArray? = null,
    ): Boolean = synchronized(keyLock(uid, alias)) {
        runCatching {
            require(uid >= 0 && alias.isNotEmpty() && alias.length <= MAX_ALIAS_LENGTH)
            require(ownerIdentityFingerprint == null || ownerIdentityFingerprint.size == 32)
            require(params.usageCountLimit >= 0 && params.maxUsesPerBoot >= 0)
            require(useState == null || (useState.lifetimeRemaining == null || useState.lifetimeRemaining >= 0) && (useState.perBootRemaining == null || useState.perBootRemaining >= 0) && (useState.bootIdentity == null || useState.bootIdentity.length <= 256))
            val file = fileFor(uid, alias)
            val parent = file.parentFile ?: error("Missing persistence directory")
            if (!parent.exists()) require(parent.mkdirs())
            require(parent.setReadable(true, true) || parent.canRead())
            require(parent.setWritable(true, true) || parent.canWrite())
            require(parent.setExecutable(true, true) || parent.canExecute())
            val snapshot = serializeSnapshot(uid, alias, securityLevel, skipLeafHack, nspace, domain, keyPair, secretKey, chain, metadataBytes, params, useState, ownerIdentityFingerprint)
            require(snapshot.size <= MAX_RECORD_BYTES)
            val tmp = File(parent, "${file.name}.tmp")
            FileOutputStream(tmp).use { fos ->
                android.system.Os.chmod(tmp.absolutePath, 0x180)
                fos.write(snapshot)
                fos.flush()
                fos.fd.sync()
            }
            android.system.Os.chmod(parent.absolutePath, 0x1c0)
            android.system.Os.rename(tmp.absolutePath, file.absolutePath)
            val directoryFd = android.system.Os.open(
                parent.absolutePath,
                android.system.OsConstants.O_RDONLY,
                0,
            )
            try {
                android.system.Os.fsync(directoryFd)
            } finally {
                android.system.Os.close(directoryFd)
            }
            true
        }.onFailure { Logger.e("Failed to persist key uid=$uid", it) }.getOrDefault(false)
    }

    private fun serializeSnapshot(
        uid: Int, alias: String, securityLevel: Int, skipLeafHack: Boolean, nspace: Long, domain: Int,
        keyPair: KeyPair?, secretKey: SecretKey?, chain: List<Certificate>?, metadataBytes: ByteArray?,
        params: KeyGenParameters, useState: UseState?, ownerIdentityFingerprint: ByteArray?,
    ): ByteArray {
        val bytes = java.io.ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
                out.writeByte(FORMAT_VERSION)
                out.writeInt(uid)
                out.writeUTF(alias)
                out.writeInt(securityLevel)
                out.writeBoolean(skipLeafHack)
                out.writeLong(nspace)
                out.writeInt(domain)

                out.writeBoolean(keyPair != null)
                if (keyPair != null) {
                    val priv = keyPair!!.private.encoded
                    val pub = keyPair.public.encoded
                    out.writeInt(priv.size)
                    out.write(priv)
                    out.writeInt(pub.size)
                    out.write(pub)
                }
                out.writeBoolean(secretKey != null)
                if (secretKey != null) {
                    out.writeUTF(secretKey!!.algorithm)
                    val secretBytes = secretKey.encoded
                    out.writeInt(secretBytes.size)
                    out.write(secretBytes)
                }

                val chainList = chain ?: emptyList()
                out.writeInt(chainList.size)
                chainList.forEach { c ->
                    val b = c.encoded
                    out.writeInt(b.size)
                    out.write(b)
                }

                out.writeBoolean(metadataBytes != null)
                if (metadataBytes != null) {
                    out.writeInt(metadataBytes!!.size)
                    out.write(metadataBytes)
                }

                out.writeInt(params.algorithm)
                out.writeInt(params.keySize)
                out.writeInt(params.ecCurve)
                writeIntList(out, params.purpose)
                writeIntList(out, params.digest)
                writeIntList(out, params.padding)
                writeIntList(out, params.blockMode)
                writeIntList(out, params.mgfDigest)
                out.writeInt(params.usageCountLimit)
                val callerNonce = params.callerNonce
                out.writeBoolean(callerNonce != null)
                if (callerNonce != null) out.writeBoolean(callerNonce)
                val unlockedDeviceRequired = params.unlockedDeviceRequired
                out.writeBoolean(unlockedDeviceRequired != null)
                if (unlockedDeviceRequired != null) out.writeBoolean(unlockedDeviceRequired)
                val activeDateTime = params.activeDateTime
                out.writeBoolean(activeDateTime != null)
                if (activeDateTime != null) out.writeLong(activeDateTime)
                val originationExpireDateTime = params.originationExpireDateTime
                out.writeBoolean(originationExpireDateTime != null)
                if (originationExpireDateTime != null) out.writeLong(originationExpireDateTime)
                val usageExpireDateTime = params.usageExpireDateTime
                out.writeBoolean(usageExpireDateTime != null)
                if (usageExpireDateTime != null) out.writeLong(usageExpireDateTime)

                val noAuthRequired = params.noAuthRequired
                out.writeBoolean(noAuthRequired != null)
                if (noAuthRequired != null) out.writeBoolean(noAuthRequired)
                val origin = params.origin
                out.writeBoolean(origin != null)
                if (origin != null) out.writeInt(origin)

                val rsaExp = params.rsaPublicExponent
                out.writeBoolean(rsaExp != null)
                if (rsaExp != null) {
                    val b = rsaExp.toByteArray()
                    out.writeInt(b.size)
                    out.write(b)
                }
                out.writeInt(params.maxUsesPerBoot)
                out.writeInt(params.userSecureIds.size)
                params.userSecureIds.forEach(out::writeLong)
                writeNullableInt(out, params.userAuthType)
                writeNullableInt(out, params.authTimeout)
                writeNullableBoolean(out, params.allowWhileOnBody)
                writeNullableBoolean(out, params.trustedUserPresenceRequired)
                writeNullableBoolean(out, params.trustedConfirmationRequired)
                out.writeInt(params.authPolicyProvenance.ordinal)
                out.writeBoolean(params.createdAtMs != null)
                params.createdAtMs?.let(out::writeLong)
                writeNullableInt(out, useState?.lifetimeRemaining)
                writeNullableInt(out, useState?.perBootRemaining)
                out.writeBoolean(useState?.bootIdentity != null)
                useState?.bootIdentity?.let(out::writeUTF)
                out.writeBoolean(ownerIdentityFingerprint != null)
                ownerIdentityFingerprint?.let { out.write(it.copyOf()) }
            }
        return bytes.toByteArray()
    }

    fun loadAll(): List<PersistedKey> = loadAll(null)

    fun loadAll(ownerIdentityForUid: ((Int) -> ByteArray?)?): List<PersistedKey> {
        val result = mutableListOf<PersistedKey>()
        if (!dir.exists()) return result
        dir.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".bin") }
            .forEach { file ->
                val raw = runCatching {
                    DataInputStream(file.inputStream().buffered()).use { ins ->
                        require(file.length() in 1..MAX_RECORD_BYTES.toLong())
                        val version = ins.readUnsignedByte()
                        require(version == FORMAT_VERSION || version == LEGACY_FORMAT_VERSION) { "unsupported format $version" }
                        val uid = ins.readInt()
                        require(uid >= 0)
                        val alias = ins.readUTF()
                        require(alias.isNotEmpty() && alias.length <= MAX_ALIAS_LENGTH)
                        val securityLevel = ins.readInt()
                        val skipLeafHack = ins.readBoolean()
                        val nspace = ins.readLong()
                        val domain = ins.readInt()

                        var privBytes: ByteArray? = null
                        var pubBytes: ByteArray? = null
                        if (ins.readBoolean()) {
                            val privSize = ins.readInt()
                            require(privSize in 1..MAX_BLOB_BYTES)
                            privBytes = ByteArray(privSize).also { ins.readFully(it) }
                            val pubSize = ins.readInt()
                            require(pubSize in 1..MAX_BLOB_BYTES)
                            pubBytes = ByteArray(pubSize).also { ins.readFully(it) }
                        }

                        var secretKey: SecretKey? = null
                        if (ins.readBoolean()) {
                            val algo = ins.readUTF()
                            require(algo.length <= 128)
                            val secretSize = ins.readInt()
                            require(secretSize in 1..MAX_BLOB_BYTES)
                            val secretBytes = ByteArray(secretSize).also { ins.readFully(it) }
                            secretKey = SecretKeySpec(secretBytes, algo)
                        }

                        val cf = CertificateUtils.certificateFactory
                        val chainSize = ins.readInt()
                        require(chainSize in 0..MAX_CHAIN_COUNT)
                        val chain = List(chainSize) {
                            val size = ins.readInt()
                            require(size in 1..MAX_BLOB_BYTES)
                            val b = ByteArray(size).also { ins.readFully(it) }
                            cf.generateCertificate(ByteArrayInputStream(b))
                        }

                        var metadataBytes: ByteArray? = null
                        if (ins.readBoolean()) {
                            val metadataSize = ins.readInt()
                            require(metadataSize in 0..MAX_BLOB_BYTES)
                            metadataBytes = ByteArray(metadataSize).also { ins.readFully(it) }
                        }

                        val algorithm = ins.readInt()
                        val keySize = ins.readInt()
                        val ecCurve = ins.readInt()
                        val purpose = readIntList(ins)
                        val digest = readIntList(ins)
                        val padding = readIntList(ins)
                        val blockMode = readIntList(ins)
                        val mgfDigest = readIntList(ins)
                        val usageCountLimit = ins.readInt()
                        val callerNonce = if (ins.readBoolean()) ins.readBoolean() else null
                        val unlockedDeviceRequired = if (ins.readBoolean()) ins.readBoolean() else null
                        val activeDateTime = if (ins.readBoolean()) ins.readLong() else null
                        val originationExpireDateTime = if (ins.readBoolean()) ins.readLong() else null
                        val usageExpireDateTime = if (ins.readBoolean()) ins.readLong() else null
                        val noAuthRequired = if (ins.readBoolean()) ins.readBoolean() else null
                        val origin = if (ins.readBoolean()) ins.readInt() else null
                        val rsaExp =
                            if (ins.readBoolean()) {
                                val size = ins.readInt()
                                require(size in 1..1024)
                                val b = ByteArray(size).also { ins.readFully(it) }
                                java.math.BigInteger(b)
                            } else null
                        val maxUsesPerBoot: Int
                        val userSecureIds: List<Long>
                        val userAuthType: Int?
                        val authTimeout: Int?
                        val allowWhileOnBody: Boolean?
                        val trustedUserPresenceRequired: Boolean?
                        val trustedConfirmationRequired: Boolean?
                        val authPolicyProvenance: CertificateGen.AuthPolicyProvenance
                        val createdAtMs: Long?
                        val useState: UseState?
                        var ownerIdentityFingerprint: ByteArray? = null
                        if (version >= FORMAT_VERSION) {
                            maxUsesPerBoot = ins.readInt().also { require(it >= 0) }
                            val sidCount = ins.readInt()
                            require(sidCount in 0..MAX_INT_LIST_COUNT)
                            userSecureIds = List(sidCount) { ins.readLong() }
                            userAuthType = readNullableInt(ins)
                            authTimeout = readNullableInt(ins)
                            allowWhileOnBody = readNullableBoolean(ins)
                            trustedUserPresenceRequired = readNullableBoolean(ins)
                            trustedConfirmationRequired = readNullableBoolean(ins)
                            authPolicyProvenance = CertificateGen.AuthPolicyProvenance.entries.getOrElse(ins.readInt()) { CertificateGen.AuthPolicyProvenance.UNKNOWN }
                            createdAtMs = if (ins.readBoolean()) ins.readLong() else null
                            val lifetime = readNullableInt(ins)
                            val perBoot = readNullableInt(ins)
                            val boot = if (ins.readBoolean()) ins.readUTF().also { require(it.length <= 256) } else null
                            useState = UseState(lifetime, perBoot, boot)
                            if (ins.readBoolean()) {
                                ownerIdentityFingerprint = ByteArray(32).also { ins.readFully(it) }
                            }
                        } else {
                            maxUsesPerBoot = 0
                            userSecureIds = emptyList()
                            userAuthType = null
                            authTimeout = null
                            allowWhileOnBody = null
                            trustedUserPresenceRequired = null
                            trustedConfirmationRequired = null
                            authPolicyProvenance = CertificateGen.AuthPolicyProvenance.UNKNOWN
                            createdAtMs = null
                            useState = UseState(if (usageCountLimit > 0) 0 else null, if (usageCountLimit > 0) 0 else null, null)
                        }
                        require(ins.available() == 0)

                        val keyPair: KeyPair? =
                            if (privBytes != null && pubBytes != null) {
                                val keyAlgo = if (algorithm == Algorithm.RSA) "RSA" else "EC"
                                val kf = KeyFactory.getInstance(keyAlgo)
                                KeyPair(
                                    kf.generatePublic(X509EncodedKeySpec(pubBytes)),
                                    kf.generatePrivate(PKCS8EncodedKeySpec(privBytes)),
                                )
                            } else null

                        val params =
                            KeyGenParameters().apply {
                                this.algorithm = algorithm
                                this.keySize = keySize
                                this.ecCurve = ecCurve
                                this.purpose = purpose.toMutableList()
                                this.digest = digest.toMutableList()
                                this.padding = padding.toMutableList()
                                this.blockMode = blockMode.toMutableList()
                                this.mgfDigest = mgfDigest.toMutableList()
                                this.usageCountLimit = usageCountLimit
                                this.maxUsesPerBoot = maxUsesPerBoot
                                this.userSecureIds = userSecureIds.toMutableList()
                                this.userAuthType = userAuthType
                                this.authTimeout = authTimeout
                                this.allowWhileOnBody = allowWhileOnBody
                                this.trustedUserPresenceRequired = trustedUserPresenceRequired
                                this.trustedConfirmationRequired = trustedConfirmationRequired
                                this.authPolicyProvenance = authPolicyProvenance
                                this.createdAtMs = createdAtMs
                                this.callerNonce = callerNonce
                                this.unlockedDeviceRequired = unlockedDeviceRequired
                                this.activeDateTime = activeDateTime
                                this.originationExpireDateTime = originationExpireDateTime
                                this.usageExpireDateTime = usageExpireDateTime
                                this.noAuthRequired = noAuthRequired
                                this.origin = origin
                                this.rsaPublicExponent = rsaExp
                            }

                        require(keyPair == null || keyPair.public.algorithm.equals(if (algorithm == Algorithm.RSA) "RSA" else "EC", ignoreCase = true))
                        require(keyPair == null || chain.isEmpty() || chain.first().publicKey.encoded.contentEquals(keyPair.public.encoded))
                        require(keyPair == null || params.algorithm == Algorithm.RSA || params.algorithm == Algorithm.EC)
                        if (ownerIdentityForUid != null) {
                            val currentFingerprint = ownerIdentityForUid(uid)
                            if (ownerIdentityFingerprint == null || currentFingerprint == null || !ownerIdentityFingerprint.contentEquals(currentFingerprint)) {
                                Logger.w(
                                    if (version == LEGACY_FORMAT_VERSION && ownerIdentityFingerprint == null)
                                        "Preserved legacy format-3 key uid=$uid alias=$alias on disk; owner identity is unavailable, key access withheld, re-enrollment required"
                                    else
                                        "Preserved key uid=$uid alias=$alias on disk; owner identity is unknown or changed, key access withheld"
                                )
                                return@runCatching
                            }
                        }
                        result.add(
                            PersistedKey(
                                uid,
                                alias,
                                securityLevel,
                                skipLeafHack,
                                nspace,
                                domain,
                                keyPair,
                                secretKey,
                                chain,
                                params,
                                metadataBytes,
                                useState,
                                ownerIdentityFingerprint,
                            )
                        )
                    }
                }
                raw.onFailure { Logger.e("Failed to load persisted key from ${file.name}", it) }
            }
        return result
    }

    fun deleteKey(uid: Int, alias: String): Boolean = synchronized(keyLock(uid, alias)) {
        runCatching {
            val file = fileFor(uid, alias)
            if (!file.exists()) return@runCatching true
            check(file.delete()) { "Unable to delete persisted record" }
            val parent = file.parentFile ?: error("Missing persistence directory")
            val directoryFd = android.system.Os.open(
                parent.absolutePath,
                android.system.OsConstants.O_RDONLY,
                0,
            )
            try {
                android.system.Os.fsync(directoryFd)
            } finally {
                android.system.Os.close(directoryFd)
            }
            true
        }.onFailure { Logger.e("Failed to delete persisted key uid=$uid alias=$alias", it) }.getOrDefault(false)
    }

    private fun writeIntList(out: DataOutputStream, list: List<Int>) {
        require(list.size <= MAX_INT_LIST_COUNT)
        out.writeInt(list.size)
        list.forEach(out::writeInt)
    }

    private fun readIntList(ins: DataInputStream): List<Int> {
        val n = ins.readInt()
        require(n in 0..MAX_INT_LIST_COUNT)
        return List(n) { ins.readInt() }
    }

    private fun writeNullableInt(out: DataOutputStream, value: Int?) {
        out.writeBoolean(value != null)
        value?.let(out::writeInt)
    }

    private fun readNullableInt(ins: DataInputStream): Int? = if (ins.readBoolean()) ins.readInt() else null

    private fun writeNullableBoolean(out: DataOutputStream, value: Boolean?) {
        out.writeBoolean(value != null)
        value?.let(out::writeBoolean)
    }

    private fun readNullableBoolean(ins: DataInputStream): Boolean? = if (ins.readBoolean()) ins.readBoolean() else null
}
