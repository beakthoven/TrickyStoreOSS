/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.RemoteException
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.ResponseCode
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyGenParameters
import java.security.Key
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val MAX_RECEIVE_DATA = 0x8000

internal class OpRequest(
    val purpose: Int = -1,
    val digest: Int = 0,
    val digestSpecified: Boolean = false,
    val padding: Int = 0,
    val blockMode: Int = 0,
    val nonce: ByteArray? = null,
    val macLength: Int? = null,
    val mgfDigest: Int = 0,
    val mgfDigestSpecified: Boolean = false,
) {
    companion object {
        fun parse(params: Array<KeyParameter>): OpRequest {
            var purpose = -1
            var digest = 0
            var digestSpecified = false
            var padding = 0
            var blockMode = 0
            var nonce: ByteArray? = null
            var macLength: Int? = null
            var mgfDigest = 0
            var mgfDigestSpecified = false
            for (p in params) {
                try {
                    val v = p.value
                    when (p.tag) {
                        Tag.PURPOSE -> purpose = v.keyPurpose
                        Tag.DIGEST -> {
                            digest = v.digest
                            digestSpecified = true
                        }
                        Tag.PADDING -> padding = v.paddingMode
                        Tag.BLOCK_MODE -> blockMode = v.blockMode
                        Tag.NONCE -> nonce = v.blob
                        Tag.MAC_LENGTH -> macLength = v.integer
                        Tag.RSA_OAEP_MGF_DIGEST -> {
                            mgfDigest = v.digest
                            mgfDigestSpecified = true
                        }
                    }
                } catch (_: Exception) {}
            }
            return OpRequest(purpose, digest, digestSpecified, padding, blockMode, nonce, macLength, mgfDigest, mgfDigestSpecified)
        }
    }
}

private fun digestNameOrNull(digest: Int): String? =
    when (digest) {
        KeymasterDefs.KM_DIGEST_NONE -> "NONE"
        KeymasterDefs.KM_DIGEST_SHA1 -> "SHA1"
        KeymasterDefs.KM_DIGEST_SHA_2_224 -> "SHA224"
        KeymasterDefs.KM_DIGEST_SHA_2_256 -> "SHA256"
        KeymasterDefs.KM_DIGEST_SHA_2_384 -> "SHA384"
        KeymasterDefs.KM_DIGEST_SHA_2_512 -> "SHA512"
        else -> null
    }

private fun mgf1ParameterSpecOrNull(digest: Int): MGF1ParameterSpec? =
    when (digest) {
        KeymasterDefs.KM_DIGEST_SHA1 -> MGF1ParameterSpec.SHA1
        KeymasterDefs.KM_DIGEST_SHA_2_224 -> MGF1ParameterSpec.SHA224
        KeymasterDefs.KM_DIGEST_SHA_2_256 -> MGF1ParameterSpec.SHA256
        KeymasterDefs.KM_DIGEST_SHA_2_384 -> MGF1ParameterSpec.SHA384
        KeymasterDefs.KM_DIGEST_SHA_2_512 -> MGF1ParameterSpec.SHA512
        else -> null
    }

private data class EffectiveOperationParameters(
    val padding: Int,
    val digest: Int,
    val mgfDigest: Int,
    val digestError: Int? = null,
    val mgfDigestError: Int? = null,
)

private fun effectiveOperationParameters(
    keyParams: KeyGenParameters,
    op: OpRequest,
    purpose: Int = op.purpose,
): EffectiveOperationParameters {
    val padding = op.padding.takeIf { it != 0 } ?: keyParams.padding.firstOrNull() ?: KeymasterDefs.KM_PAD_NONE
    val digest =
        if (op.digestSpecified) op.digest
        else if (keyParams.algorithm == Algorithm.RSA && padding == KeymasterDefs.KM_PAD_RSA_OAEP)
            KeymasterDefs.KM_DIGEST_SHA1
        else keyParams.digest.firstOrNull() ?: KeymasterDefs.KM_DIGEST_NONE
    val mgfDigest = if (op.mgfDigestSpecified) op.mgfDigest else KeymasterDefs.KM_DIGEST_SHA1
    val usesDigest = purpose == KeyPurpose.SIGN || (keyParams.algorithm == Algorithm.RSA && padding == KeymasterDefs.KM_PAD_RSA_OAEP)
    val digestError =
        if (
            usesDigest && (digestNameOrNull(digest) == null || digest == KeymasterDefs.KM_DIGEST_NONE) &&
                !(keyParams.algorithm == Algorithm.RSA && purpose == KeyPurpose.SIGN &&
                    padding != KeymasterDefs.KM_PAD_RSA_PSS && digest == KeymasterDefs.KM_DIGEST_NONE)
        ) KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST
        else if (
            keyParams.algorithm == Algorithm.RSA && padding == KeymasterDefs.KM_PAD_RSA_PSS &&
                digest == KeymasterDefs.KM_DIGEST_NONE
        ) KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST
        else if (usesDigest && keyParams.digest.isNotEmpty() && digest !in keyParams.digest)
            KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST
        else null
    val mgfDigestError =
        if (keyParams.algorithm != Algorithm.RSA || padding != KeymasterDefs.KM_PAD_RSA_OAEP) null
        else if (mgf1ParameterSpecOrNull(mgfDigest) == null) KeymasterDefs.KM_ERROR_UNSUPPORTED_MGF_DIGEST
        else if (keyParams.mgfDigest.isNotEmpty() && mgfDigest !in keyParams.mgfDigest)
            KeymasterDefs.KM_ERROR_UNSUPPORTED_MGF_DIGEST
        else null
    return EffectiveOperationParameters(padding, digest, mgfDigest, digestError, mgfDigestError)
}

internal fun authorizeOperation(keyParams: KeyGenParameters, op: OpRequest): Int? {
    val purpose = op.purpose
    if (purpose < 0) return KeymasterDefs.KM_ERROR_INVALID_ARGUMENT
    val isAsymmetric = keyParams.algorithm == Algorithm.EC || keyParams.algorithm == Algorithm.RSA
    if (isAsymmetric && (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT))
        return KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE
    if (purpose == KeyPurpose.AGREE_KEY && keyParams.algorithm != Algorithm.EC)
        return KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE
    if (purpose !in keyParams.purpose) return KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE
    val now = System.currentTimeMillis()
    keyParams.activeDateTime?.let { if (now < it) return KeymasterDefs.KM_ERROR_KEY_NOT_YET_VALID }
    if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.ENCRYPT)
        keyParams.originationExpireDateTime?.let { if (now > it) return KeymasterDefs.KM_ERROR_KEY_EXPIRED }
    if (purpose == KeyPurpose.DECRYPT || purpose == KeyPurpose.VERIFY)
        keyParams.usageExpireDateTime?.let { if (now > it) return KeymasterDefs.KM_ERROR_KEY_EXPIRED }
    if (
        op.nonce != null &&
            (purpose == KeyPurpose.ENCRYPT || purpose == KeyPurpose.SIGN) &&
            keyParams.callerNonce != true
    )
        return KeymasterDefs.KM_ERROR_CALLER_NONCE_PROHIBITED
    val effective = effectiveOperationParameters(keyParams, op, purpose)
    if (keyParams.padding.isNotEmpty() && effective.padding !in keyParams.padding)
        return KeymasterDefs.KM_ERROR_UNSUPPORTED_PADDING_MODE
    if (keyParams.blockMode.isNotEmpty() && op.blockMode !in keyParams.blockMode)
        return KeymasterDefs.KM_ERROR_UNSUPPORTED_BLOCK_MODE
    effective.digestError?.let { return it }
    effective.mgfDigestError?.let { return it }
    return null
}

private sealed interface OpEngine {
    val beginParameters: Array<KeyParameter>?
        get() = null

    fun update(data: ByteArray?): ByteArray? = null

    fun updateAad(data: ByteArray?) {
        throw ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_TAG, "updateAad not supported")
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
}

private class SignatureEngine(private val signature: Signature, private val verify: Boolean) : OpEngine {
    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) this.signature.update(data)
        return if (verify) {
            if (signature == null || !this.signature.verify(signature))
                throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                    "Signature verification failed",
                )
            null
        } else {
            this.signature.sign()
        }
    }
}

private class MacEngine(private val mac: Mac, private val verify: Boolean) : OpEngine {
    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        val tag = mac.doFinal()
        return if (verify) {
            if (signature == null || !MessageDigest.isEqual(tag, signature))
                throw ServiceSpecificException(KeymasterDefs.KM_ERROR_VERIFICATION_FAILED, "HMAC verification failed")
            null
        } else {
            tag
        }
    }
}

private class CipherEngine(private val cipher: Cipher) : OpEngine {
    override val beginParameters: Array<KeyParameter>? =
        cipher.iv?.let {
            arrayOf(
                KeyParameter().apply {
                    tag = Tag.NONCE
                    value = KeyParameterValue.blob(it)
                }
            )
        }

    override fun update(data: ByteArray?): ByteArray? = data?.let { cipher.update(it) }

    override fun updateAad(data: ByteArray?) {
        if (data != null) cipher.updateAAD(data)
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()
}

private class KeyAgreementEngine(private val agreement: KeyAgreement) : OpEngine {
    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) {
            val peerKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(data))
            agreement.doPhase(peerKey, true)
        }
        return agreement.generateSecret()
    }
}

internal class SoftwareOperationBinder
private constructor(
    private val engine: OpEngine,
    private val usageKey: SecurityLevelInterceptor.Key?,
    private val keyParams: KeyGenParameters,
) : IKeystoreOperation.Stub() {
    @Volatile private var active = true

    val beginParameters: Array<KeyParameter>?
        get() = engine.beginParameters

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? =
        synchronized(this) {
            checkActive()
            checkInput(input)
            engine.update(input)
        }

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) =
        synchronized(this) {
            checkActive()
            checkInput(aadInput)
            try {
                engine.updateAad(aadInput)
            } catch (e: Throwable) {
                active = false
                throw e
            }
        }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? =
        synchronized(this) {
            checkActive()
            checkInput(input)
            try {
                val result = engine.finish(input, signature)
                consumeUsage()
                result
            } catch (e: ServiceSpecificException) {
                throw e
            } catch (e: AEADBadTagException) {
                throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                    "GCM tag verification failed",
                )
            } catch (e: Throwable) {
                throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                    e.message ?: "operation failed",
                )
            } finally {
                active = false
            }
        }

    @Throws(RemoteException::class) override fun abort() = synchronized(this) { active = false }

    private fun checkActive() {
        if (!active)
            throw ServiceSpecificException(
                KeymasterDefs.KM_ERROR_INVALID_OPERATION_HANDLE,
                "Operation is no longer active",
            )
    }

    private fun checkInput(data: ByteArray?) {
        if (data != null && data.size > MAX_RECEIVE_DATA)
            throw ServiceSpecificException(ResponseCode.TOO_MUCH_DATA, "Oversized input (${data.size}B)")
    }

    private fun consumeUsage() {
        if (usageKey == null || (keyParams.usageCountLimit <= 0 && keyParams.maxUsesPerBoot <= 0)) return
        SecurityLevelInterceptor.consumeUsage(usageKey, keyParams)
    }

    companion object {
        fun create(
            info: SecurityLevelInterceptor.Info,
            op: OpRequest,
            usageKey: SecurityLevelInterceptor.Key?,
        ): SoftwareOperationBinder {
            val p = info.params
            val purpose =
                op.purpose.takeIf { it >= 0 }
                    ?: p.purpose.firstOrNull()
                    ?: throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                        "No key purpose specified",
                    )
            val effective = effectiveOperationParameters(p, op, purpose)
            effective.digestError?.let { throw ServiceSpecificException(it, "Unsupported operation digest") }
            effective.mgfDigestError?.let { throw ServiceSpecificException(it, "Unsupported MGF digest") }
            val digest = effective.digest
            val padding = effective.padding
            val blockMode = op.blockMode.takeIf { it != 0 } ?: p.blockMode.firstOrNull()
            val engine: OpEngine =
                try {
                    when (p.algorithm) {
                    Algorithm.HMAC -> {
                        if (purpose != KeymasterDefs.KM_PURPOSE_SIGN && purpose != KeymasterDefs.KM_PURPOSE_VERIFY)
                            throw ServiceSpecificException(
                                KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                                "Unsupported purpose for HMAC: $purpose",
                            )
                        if (digest == KeymasterDefs.KM_DIGEST_NONE)
                            throw ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST, "HMAC requires a digest")
                        MacEngine(
                            Mac.getInstance("Hmac${operationDigestName(digest)}").apply {
                                init(
                                    info.secretKey
                                        ?: throw ServiceSpecificException(
                                            KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                                            "HMAC operation has no secret key",
                                        )
                                )
                            },
                            purpose == KeymasterDefs.KM_PURPOSE_VERIFY,
                        )
                    }
                    Algorithm.EC,
                    Algorithm.RSA ->
                        when (purpose) {
                            KeyPurpose.SIGN ->
                                SignatureEngine(
                                    Signature.getInstance(signatureAlgorithm(p.algorithm, digest, padding)).apply {
                                        initSign(info.keyPair!!.private)
                                    },
                                    false,
                                )
                            KeyPurpose.VERIFY ->
                                SignatureEngine(
                                    Signature.getInstance(signatureAlgorithm(p.algorithm, digest, padding)).apply {
                                        initVerify(info.keyPair!!.public)
                                    },
                                    true,
                                )
                            KeyPurpose.AGREE_KEY ->
                                KeyAgreementEngine(
                                    KeyAgreement.getInstance("ECDH").apply { init(info.keyPair!!.private) }
                                )
                            KeyPurpose.ENCRYPT,
                            KeyPurpose.DECRYPT ->
                                CipherEngine(buildCipher(p, op, digest, effective.mgfDigest, padding, blockMode, info, purpose))
                            else ->
                                throw ServiceSpecificException(
                                    KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                                    "Unsupported purpose: $purpose",
                                )
                        }
                    Algorithm.AES ->
                        when (purpose) {
                            KeyPurpose.ENCRYPT,
                            KeyPurpose.DECRYPT ->
                                CipherEngine(buildCipher(p, op, digest, effective.mgfDigest, padding, blockMode, info, purpose))
                            else ->
                                throw ServiceSpecificException(
                                    KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                                    "Unsupported purpose: $purpose",
                                )
                        }
                    else ->
                        throw ServiceSpecificException(
                            KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                            "Unsupported algorithm: ${p.algorithm}",
                        )
                    }
                } catch (e: ServiceSpecificException) {
                    throw e
                } catch (e: Throwable) {
                    throw ServiceSpecificException(
                        KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        e.message ?: "Software operation setup failed",
                    )
                }
            return SoftwareOperationBinder(engine, usageKey, p)
        }

        private fun operationDigestName(digest: Int): String =
            digestNameOrNull(digest)
                ?: throw ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_DIGEST, "Unsupported digest: $digest")

        private fun signatureAlgorithm(algorithm: Int, digest: Int, padding: Int?): String {
            val keyAlgo =
                when (algorithm) {
                    Algorithm.EC -> "ECDSA"
                    Algorithm.RSA -> "RSA"
                    else ->
                        throw ServiceSpecificException(
                            KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                            "Unsupported signature algorithm",
                        )
                }
            val name = "${operationDigestName(digest)}with$keyAlgo"
            return if (algorithm == Algorithm.RSA && padding == KeymasterDefs.KM_PAD_RSA_PSS)
                "${operationDigestName(digest)}withRSA/PSS"
            else name
        }

        private fun buildCipher(
            p: KeyGenParameters,
            op: OpRequest,
            digest: Int,
            mgfDigest: Int,
            padding: Int?,
            blockMode: Int?,
            info: SecurityLevelInterceptor.Info,
            purpose: Int,
        ): Cipher {
            val keyAlgo =
                when (p.algorithm) {
                    Algorithm.RSA -> "RSA"
                    Algorithm.AES -> "AES"
                    else ->
                        throw ServiceSpecificException(
                            KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                            "Unsupported cipher algorithm",
                        )
                }
            val mode =
                when (blockMode) {
                    KeymasterDefs.KM_MODE_ECB -> "ECB"
                    KeymasterDefs.KM_MODE_CBC -> "CBC"
                    KeymasterDefs.KM_MODE_CTR -> "CTR"
                    KeymasterDefs.KM_MODE_GCM -> "GCM"
                    else -> "ECB"
                }
            val pad =
                when (padding) {
                    KeymasterDefs.KM_PAD_NONE -> "NoPadding"
                    KeymasterDefs.KM_PAD_RSA_OAEP -> "OAEPPadding"
                    KeymasterDefs.KM_PAD_RSA_PKCS1_1_5_ENCRYPT,
                    KeymasterDefs.KM_PAD_RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
                    KeymasterDefs.KM_PAD_PKCS7 -> "PKCS7Padding"
                    else -> "NoPadding"
                }
            val opMode = if (purpose == KeyPurpose.ENCRYPT) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
            return Cipher.getInstance("$keyAlgo/$mode/$pad").apply {
                val spec: java.security.spec.AlgorithmParameterSpec? =
                    when {
                        blockMode == KeymasterDefs.KM_MODE_GCM ->
                            GCMParameterSpec(op.macLength ?: 128, op.nonce ?: ByteArray(12))
                        padding == KeymasterDefs.KM_PAD_RSA_OAEP ->
                            OAEPParameterSpec(
                                operationDigestName(digest).replace("SHA", "SHA-"),
                                "MGF1",
                                mgf1ParameterSpecOrNull(mgfDigest)
                                    ?: throw ServiceSpecificException(
                                        KeymasterDefs.KM_ERROR_UNSUPPORTED_MGF_DIGEST,
                                        "Unsupported MGF digest: $mgfDigest",
                                    ),
                                PSource.PSpecified.DEFAULT,
                            )
                        op.nonce != null -> IvParameterSpec(op.nonce)
                        else -> null
                    }
                val key: Key =
                    when {
                        info.secretKey != null -> info.secretKey
                        opMode == Cipher.ENCRYPT_MODE -> info.keyPair!!.public
                        else -> info.keyPair!!.private
                    }
                if (spec != null) init(opMode, key, spec) else init(opMode, key)
            }
        }
    }
}
