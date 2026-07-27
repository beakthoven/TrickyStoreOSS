/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.content.pm.PackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.Tag
import android.os.Build
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import android.security.keymaster.KeymasterDefs
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

object CertificateGen {
    data class KeyBox(val keyPair: KeyPair, val certificates: List<Certificate>)

    data class KeyGenParameters(
        var keySize: Int = 0,
        var algorithm: Int = 0,
        var certificateSerial: BigInteger? = null,
        var certificateNotBefore: Date? = null,
        var certificateNotAfter: Date? = null,
        var certificateSubject: X500Name? = null,
        var rsaPublicExponent: BigInteger? = null,
        var ecCurve: Int = 0,
        var ecCurveName: String? = null,
        var purpose: MutableList<Int> = mutableListOf(),
        var digest: MutableList<Int> = mutableListOf(),
        var padding: MutableList<Int> = mutableListOf(),
        var blockMode: MutableList<Int> = mutableListOf(),
        var mgfDigest: MutableList<Int> = mutableListOf(),
        var usageCountLimit: Int = 0,
        var callerNonce: Boolean? = null,
        var activeDateTime: Long? = null,
        var originationExpireDateTime: Long? = null,
        var usageExpireDateTime: Long? = null,
        var attestationChallenge: ByteArray? = null,
        var brand: ByteArray? = null,
        var device: ByteArray? = null,
        var product: ByteArray? = null,
        var manufacturer: ByteArray? = null,
        var model: ByteArray? = null,
        var imei1: ByteArray? = null,
        var imei2: ByteArray? = null,
        var meid: ByteArray? = null,
        var serialno: ByteArray? = null,
    ) {
        constructor(params: Array<KeyParameter>) : this() {
            params.forEach { p ->
                runCatching {
                        val v = p.value
                        when (p.tag) {
                            Tag.KEY_SIZE -> keySize = v.integer
                            Tag.ALGORITHM -> algorithm = v.algorithm
                            Tag.CERTIFICATE_SERIAL -> certificateSerial = BigInteger(v.blob)
                            Tag.CERTIFICATE_NOT_BEFORE -> certificateNotBefore = Date(v.dateTime)
                            Tag.CERTIFICATE_NOT_AFTER -> certificateNotAfter = Date(v.dateTime)
                            Tag.CERTIFICATE_SUBJECT -> certificateSubject = X500Name(X500Principal(v.blob).name)
                            Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = BigInteger.valueOf(v.longInteger)
                            Tag.EC_CURVE -> {
                                ecCurve = v.ecCurve
                                ecCurveName = ecCurveName(ecCurve)
                            }
                            Tag.PURPOSE -> purpose.add(v.keyPurpose)
                            Tag.DIGEST -> digest.add(v.digest)
                            Tag.PADDING -> padding.add(v.paddingMode)
                            Tag.BLOCK_MODE -> blockMode.add(v.blockMode)
                            Tag.RSA_OAEP_MGF_DIGEST -> mgfDigest.add(v.digest)
                            Tag.USAGE_COUNT_LIMIT -> usageCountLimit = v.integer
                            Tag.MAX_USES_PER_BOOT -> if (usageCountLimit == 0) usageCountLimit = v.integer
                            Tag.CALLER_NONCE -> callerNonce = v.boolValue
                            Tag.ACTIVE_DATETIME -> activeDateTime = v.dateTime
                            Tag.ORIGINATION_EXPIRE_DATETIME -> originationExpireDateTime = v.dateTime
                            Tag.USAGE_EXPIRE_DATETIME -> usageExpireDateTime = v.dateTime
                            Tag.ATTESTATION_CHALLENGE -> attestationChallenge = v.blob
                            Tag.ATTESTATION_ID_BRAND -> brand = v.blob
                            Tag.ATTESTATION_ID_DEVICE -> device = v.blob
                            Tag.ATTESTATION_ID_PRODUCT -> product = v.blob
                            Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = v.blob
                            Tag.ATTESTATION_ID_MODEL -> model = v.blob
                            Tag.ATTESTATION_ID_IMEI -> imei1 = v.blob
                            Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = v.blob
                            Tag.ATTESTATION_ID_MEID -> meid = v.blob
                            Tag.ATTESTATION_ID_SERIAL -> serialno = v.blob
                        }
                    }
                    .onFailure { Logger.d("Skipping key parameter tag=${p.tag}: ${it.message}") }
            }
            if (ecCurveName == null && keySize != 0) ecCurveName = ecCurveNameByKeySize(keySize)
        }
    }

    fun generateKeyPair(params: KeyGenParameters): KeyPair? =
        runCatching {
                when (params.algorithm) {
                    Algorithm.EC -> {
                        Logger.d("Generating EC keypair of size ${params.keySize}")
                        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                            .apply { initialize(ECGenParameterSpec(params.ecCurveName ?: "secp256r1")) }
                            .generateKeyPair()
                    }

                    Algorithm.RSA -> {
                        Logger.d("Generating RSA keypair of size ${params.keySize}")
                        KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
                            .apply { initialize(RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent)) }
                            .generateKeyPair()
                    }

                    else -> {
                        Logger.i("Skipping non-EC/non-RSA algorithm: ${params.algorithm}")
                        null
                    }
                }
            }
            .onFailure { Logger.e("Failed to generate key pair", it) }
            .getOrNull()

    fun generateSecretKey(params: KeyGenParameters): javax.crypto.SecretKey? =
        runCatching {
                when (params.algorithm) {
                    Algorithm.AES ->
                        javax.crypto.KeyGenerator.getInstance("AES")
                            .apply { init(params.keySize.coerceAtLeast(128)) }
                            .generateKey()

                    Algorithm.HMAC -> {
                        val algo =
                            when (params.digest.firstOrNull { it != 0 }) {
                                KeymasterDefs.KM_DIGEST_SHA1 -> "HmacSHA1"
                                KeymasterDefs.KM_DIGEST_SHA_2_256 -> "HmacSHA256"
                                KeymasterDefs.KM_DIGEST_SHA_2_384 -> "HmacSHA384"
                                KeymasterDefs.KM_DIGEST_SHA_2_512 -> "HmacSHA512"
                                else -> "HmacSHA256"
                            }
                        javax.crypto.KeyGenerator.getInstance(algo)
                            .apply { init(params.keySize.coerceAtLeast(256)) }
                            .generateKey()
                    }

                    else -> null
                }
            }
            .onFailure { Logger.e("Failed to generate secret key", it) }
            .getOrNull()

    fun generateKeyPair(
        uid: Int,
        descriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        params: KeyGenParameters,
        securityLevel: Int = 1,
    ): Pair<KeyPair, List<Certificate>>? =
        runCatching {
                Logger.i("Requested KeyPair with alias: ${descriptor.alias}")
                attestKeyDescriptor?.let { Logger.i("Requested KeyPair with attestKey: ${it.alias}") }

                val keyPair = generateKeyPair(params) ?: return null
                val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
                if (keybox.certificates.isEmpty()) {
                    Logger.e("Keybox has no certificates")
                    return null
                }

                val signing =
                    attestKeyDescriptor?.let { getAttestationKeyInfo(uid, it) }
                        ?: (keybox.keyPair to X509CertificateHolder(keybox.certificates[0].encoded).subject)

                val leaf = buildCertificate(keyPair, keybox, params, signing.second, uid, securityLevel, signing.first)
                val chain = buildList {
                    add(leaf)
                    if (attestKeyDescriptor == null) addAll(keybox.certificates)
                }
                keyPair to chain
            }
            .onFailure { Logger.e("Failed to generate key pair with certificates", it) }
            .getOrNull()

    private fun getKeyboxForAlgorithm(algorithm: Int): KeyBox? {
        val name =
            when (algorithm) {
                Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC

                Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA

                else -> {
                    Logger.e("Unsupported algorithm: $algorithm")
                    null
                }
            } ?: return null
        return KeyBoxUtils.keyboxes[name] ?: KeyBoxUtils.keyboxes.values.firstOrNull()
    }

    private fun getAttestationKeyInfo(uid: Int, descriptor: KeyDescriptor): Pair<KeyPair, X500Name>? {
        val alias = descriptor.alias ?: return null
        val keyInfo = SecurityLevelInterceptor.getKeyPairs(uid, alias) ?: return null
        return keyInfo.first to X509CertificateHolder(keyInfo.second[0].encoded).subject
    }

    private fun buildCertificate(
        keyPair: KeyPair,
        keybox: KeyBox,
        params: KeyGenParameters,
        issuer: X500Name,
        uid: Int,
        securityLevel: Int = 1,
        signingKeyPair: KeyPair = keybox.keyPair,
    ): Certificate {
        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                params.certificateNotBefore ?: Date(),
                params.certificateNotAfter ?: (keybox.certificates[0] as X509Certificate).notAfter,
                params.certificateSubject ?: X500Name("CN=Android Keystore Key"),
                keyPair.public,
            )
        val keyUsageBits =
            params.purpose.fold(0) { acc, p ->
                acc or
                    when (p) {
                        KeyPurpose.SIGN -> KeyUsage.digitalSignature
                        KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                        KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                        KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                        KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                        else -> 0
                    }
            }
        if (keyUsageBits != 0) builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        builder.addExtension(buildAttestExtension(params, uid, securityLevel))
        val signerAlgorithm =
            when (signingKeyPair.private) {
                is java.security.interfaces.ECPrivateKey -> "ECDSA"
                is java.security.interfaces.RSAPrivateKey -> "RSA"
                else ->
                    throw UnsupportedOperationException(
                        "Unsupported attestation signing key algorithm: ${signingKeyPair.private.algorithm}"
                    )
            }
        val signer =
            JcaContentSignerBuilder("${CertificateUtils.digestJcaName(params.digest.firstOrNull { it != 0 } ?: 0)}with$signerAlgorithm")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)
        return JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer))
    }

    private fun ecCurveName(curve: Int): String =
        when (curve) {
            EcCurve.CURVE_25519 -> "CURVE_25519"
            EcCurve.P_224 -> "secp224r1"
            EcCurve.P_256 -> "secp256r1"
            EcCurve.P_384 -> "secp384r1"
            EcCurve.P_521 -> "secp521r1"
            else -> "secp256r1"
        }

    private fun ecCurveNameByKeySize(size: Int): String =
        when (size) {
            224 -> "secp224r1"
            256 -> "secp256r1"
            384 -> "secp384r1"
            521 -> "secp521r1"
            else -> "secp256r1"
        }

    fun generateChain(uid: Int, params: KeyGenParameters, keyPair: KeyPair, securityLevel: Int = 1): List<ByteArray>? =
        runCatching {
                val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
                val issuer = X509CertificateHolder(keybox.certificates[0].encoded).subject
                val leaf = buildCertificate(keyPair, keybox, params, issuer, uid, securityLevel)
                CertificateUtils.run {
                    buildList {
                            add(leaf)
                            addAll(keybox.certificates)
                        }
                        .toByteArrayList()
                }
            }
            .onFailure { Logger.e("Failed to generate certificate chain", it) }
            .getOrNull()

    private fun buildAttestExtension(params: KeyGenParameters, uid: Int, securityLevel: Int = 1): Extension {
        val key = AndroidUtils.bootKey
        val hash = AndroidUtils.getBootHashFromProp()
        val rootOfTrust = DERSequence(arrayOf(DEROctetString(key), ASN1Boolean.TRUE, ASN1Enumerated(0), DEROctetString(hash)))
        val osVersion = ASN1Integer(AndroidUtils.osVersion.toLong())
        val creationDateTime = ASN1Integer(System.currentTimeMillis())
        val origin = ASN1Integer(0L)
        val moduleHash = DEROctetString(AndroidUtils.moduleHash)

        val tee = mutableListOf<ASN1Encodable>()

        fun teeTag(tag: Int, v: ASN1Encodable) = tee.add(DERTaggedObject(true, tag, v))

        fun teeSet(tag: Int, vs: List<Int>) =
            vs.takeIf { it.isNotEmpty() }?.let { teeTag(tag, DERSet(it.map { ASN1Integer(it.toLong()) }.toTypedArray())) }

        teeSet(1, params.purpose)
        teeTag(2, ASN1Integer(params.algorithm.toLong()))
        teeTag(3, ASN1Integer(params.keySize.toLong()))
        teeSet(5, params.digest)
        teeTag(503, DERNull.INSTANCE)
        teeTag(702, origin)
        teeTag(704, rootOfTrust)
        teeTag(705, osVersion)
        if (AndroidUtils.patchLevel != AndroidUtils.DO_NOT_REPORT) teeTag(706, ASN1Integer(AndroidUtils.patchLevel.toLong()))
        if (AndroidUtils.vendorPatchLevelLong != AndroidUtils.DO_NOT_REPORT) {
            teeTag(718, ASN1Integer(AndroidUtils.vendorPatchLevelLong.toLong()))
        }
        if (AndroidUtils.bootPatchLevelLong != AndroidUtils.DO_NOT_REPORT) {
            teeTag(719, ASN1Integer(AndroidUtils.bootPatchLevelLong.toLong()))
        }
        teeSet(4, params.blockMode)
        teeSet(6, params.padding)
        if (AndroidUtils.attestVersion >= 100) teeSet(203, params.mgfDigest)
        if (params.algorithm == Algorithm.EC && params.ecCurve != 0) teeTag(10, ASN1Integer(params.ecCurve.toLong()))
        if (params.algorithm == Algorithm.RSA && params.rsaPublicExponent != null)
            teeTag(200, ASN1Integer(params.rsaPublicExponent))
        params.brand?.let { teeTag(710, DEROctetString(it)) }
        params.device?.let { teeTag(711, DEROctetString(it)) }
        params.product?.let { teeTag(712, DEROctetString(it)) }
        params.manufacturer?.let { teeTag(716, DEROctetString(it)) }
        params.model?.let { teeTag(717, DEROctetString(it)) }
        params.serialno?.let { teeTag(713, DEROctetString(it)) }
        params.imei1?.let { teeTag(714, DEROctetString(it)) }
        params.meid?.let { teeTag(715, DEROctetString(it)) }
        if (AndroidUtils.attestVersion >= 300) params.imei2?.let { teeTag(723, DEROctetString(it)) }
        tee.sortBy { (it as DERTaggedObject).tagNo }

        val sw = mutableListOf<ASN1Encodable>(DERTaggedObject(true, 701, creationDateTime))
        if (params.attestationChallenge != null) sw.add(DERTaggedObject(true, 709, createApplicationId(uid)))
        if (AndroidUtils.attestVersion >= 400) sw.add(DERTaggedObject(true, 724, moduleHash))

        val keyDesc =
            arrayOf(
                ASN1Integer(AndroidUtils.attestVersion.toLong()),
                ASN1Enumerated(securityLevel),
                ASN1Integer(AndroidUtils.keymasterVersion.toLong()),
                ASN1Enumerated(securityLevel),
                DEROctetString(params.attestationChallenge ?: ByteArray(0)),
                DEROctetString(ByteArray(0)),
                DERSequence(sw.toTypedArray()),
                DERSequence(tee.toTypedArray()),
            )
        return Extension(ATTESTATION_OID, false, DEROctetString(DERSequence(keyDesc).encoded))
    }

    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm = PkgConfig.getPm() ?: throw IllegalStateException("PackageManager not found!")
        val packages = pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")
        val md = MessageDigest.getInstance("SHA-256")
        val signatures = LinkedHashSet<ByteArray>()

        val packageInfoArray =
            packages
                .map { pkg ->
                    val info =
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES.toLong(), uid / 100000)
                        } else {
                            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES, uid / 100000)
                        }
                    info.signingInfo?.signingCertificateHistory?.forEach { sig -> signatures.add(md.digest(sig.toByteArray())) }
                    info
                }
                .map { info ->
                    DERSequence(
                        arrayOf(
                            DEROctetString(info.packageName.toByteArray(StandardCharsets.UTF_8)),
                            ASN1Integer(info.longVersionCode),
                        )
                    )
                }
                .toTypedArray()

        val sigArray = signatures.map { DEROctetString(it) }.toTypedArray()
        return DEROctetString(DERSequence(arrayOf(DERSet(packageInfoArray), DERSet(sigArray))).encoded)
    }
}
