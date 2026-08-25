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
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Executors
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object PersistenceManager {
    private const val FORMAT_VERSION = 3
    private val dir = File("/data/adb/tricky_store/keys")

    // single-threaded, off the binder thread — save/delete/clearAll can't race
    private val persistExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ts-persist").apply { isDaemon = true }
    }

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
    ) = persistExecutor.execute {
        saveKeySync(
            uid,
            alias,
            securityLevel,
            skipLeafHack,
            nspace,
            domain,
            keyPair,
            secretKey,
            chain,
            metadataBytes,
            params,
        )
    }

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
    ) {
        val raw = runCatching {
            val file = fileFor(uid, alias)
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, "${file.name}.tmp")
            DataOutputStream(tmp.outputStream().buffered()).use { out ->
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
            }
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
        }
        raw.onFailure { Logger.e("Failed to persist key uid=$uid alias=$alias", it) }
    }

    fun loadAll(): List<PersistedKey> {
        val result = mutableListOf<PersistedKey>()
        if (!dir.exists()) return result
        dir.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".bin") }
            .forEach { file ->
                val raw = runCatching {
                    DataInputStream(file.inputStream().buffered()).use { ins ->
                        val version = ins.readByte().toInt()
                        if (version != FORMAT_VERSION) {
                            Logger.i("Skipping persisted key ${file.name}: unsupported format $version")
                            return@runCatching
                        }
                        val uid = ins.readInt()
                        val alias = ins.readUTF()
                        val securityLevel = ins.readInt()
                        val skipLeafHack = ins.readBoolean()
                        val nspace = ins.readLong()
                        val domain = ins.readInt()

                        var privBytes: ByteArray? = null
                        var pubBytes: ByteArray? = null
                        if (ins.readBoolean()) {
                            privBytes = ByteArray(ins.readInt()).also { ins.readFully(it) }
                            pubBytes = ByteArray(ins.readInt()).also { ins.readFully(it) }
                        }

                        var secretKey: SecretKey? = null
                        if (ins.readBoolean()) {
                            val algo = ins.readUTF()
                            val secretBytes = ByteArray(ins.readInt()).also { ins.readFully(it) }
                            secretKey = SecretKeySpec(secretBytes, algo)
                        }

                        val cf = CertificateUtils.certificateFactory
                        val chainSize = ins.readInt()
                        val chain =
                            (1..chainSize).map {
                                val b = ByteArray(ins.readInt()).also { ins.readFully(it) }
                                cf.generateCertificate(ByteArrayInputStream(b))
                            }

                        var metadataBytes: ByteArray? = null
                        if (ins.readBoolean()) {
                            metadataBytes = ByteArray(ins.readInt()).also { ins.readFully(it) }
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
                                val b = ByteArray(ins.readInt()).also { ins.readFully(it) }
                                java.math.BigInteger(b)
                            } else null

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
                                this.callerNonce = callerNonce
                                this.unlockedDeviceRequired = unlockedDeviceRequired
                                this.activeDateTime = activeDateTime
                                this.originationExpireDateTime = originationExpireDateTime
                                this.usageExpireDateTime = usageExpireDateTime
                                this.noAuthRequired = noAuthRequired
                                this.origin = origin
                                this.rsaPublicExponent = rsaExp
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
                            )
                        )
                    }
                }
                raw.onFailure { Logger.e("Failed to load persisted key from ${file.name}", it) }
            }
        return result
    }

    fun deleteKey(uid: Int, alias: String) {
        persistExecutor.execute {
            runCatching { fileFor(uid, alias).delete() }
                .onFailure { Logger.e("Failed to delete persisted key uid=$uid alias=$alias", it) }
        }
    }

    fun clearAll() {
        persistExecutor.execute {
            runCatching { dir.deleteRecursively() }.onFailure { Logger.e("Failed to clear persisted keys", it) }
        }
    }

    private fun writeIntList(out: DataOutputStream, list: List<Int>) {
        out.writeInt(list.size)
        list.forEach { out.writeInt(it) }
    }

    private fun readIntList(ins: DataInputStream): List<Int> {
        val n = ins.readInt()
        return (1..n).map { ins.readInt() }
    }
}
