/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
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
import android.os.ServiceSpecificException
import android.security.keymaster.KeymasterDefs
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
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
        var unlockedDeviceRequired: Boolean? = null,
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
        var includeUniqueId: Boolean? = null,
        var noAuthRequired: Boolean? = null,
        var origin: Int? = null,
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
                                ecCurveName = resolveEcCurveName(ecCurve, 0)
                            }
                            Tag.PURPOSE -> purpose.add(v.keyPurpose)
                            Tag.DIGEST -> digest.add(v.digest)
                            Tag.PADDING -> padding.add(v.paddingMode)
                            Tag.BLOCK_MODE -> blockMode.add(v.blockMode)
                            Tag.RSA_OAEP_MGF_DIGEST -> mgfDigest.add(v.digest)
                            Tag.USAGE_COUNT_LIMIT -> usageCountLimit = v.integer
                            Tag.MAX_USES_PER_BOOT -> if (usageCountLimit == 0) usageCountLimit = v.integer
                            Tag.CALLER_NONCE -> callerNonce = v.boolValue
                            Tag.UNLOCKED_DEVICE_REQUIRED -> unlockedDeviceRequired = v.boolValue
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
                            Tag.INCLUDE_UNIQUE_ID -> includeUniqueId = v.boolValue
                            Tag.NO_AUTH_REQUIRED -> noAuthRequired = v.boolValue
                            Tag.ORIGIN -> origin = v.origin
                        }
                    }
                    .onFailure { Log.d(TAG, "Skipping key parameter tag=${p.tag}: ${it.message}") }
            }
            if (ecCurveName == null && keySize != 0) ecCurveName = resolveEcCurveName(0, keySize)
        }
    }

    private data class EcCurveInfo(val curve: Int, val name: String, val size: Int)

    // P_256 before CURVE_25519 so that fallback maps 256 -> secp256r1
    private val EC_CURVES = listOf(
        EcCurveInfo(EcCurve.P_224, "secp224r1", 224),
        EcCurveInfo(EcCurve.P_256, "secp256r1", 256),
        EcCurveInfo(EcCurve.P_384, "secp384r1", 384),
        EcCurveInfo(EcCurve.P_521, "secp521r1", 521),
        EcCurveInfo(EcCurve.CURVE_25519, "CURVE_25519", 256),
    )

    fun effectiveKeySize(params: KeyGenParameters): Int {
        if (params.keySize > 0) return params.keySize
        if (params.algorithm != Algorithm.EC) return 0
        return EC_CURVES.firstOrNull { it.name == params.ecCurveName }?.size ?: 256
    }

    fun generateKeyPair(params: KeyGenParameters): KeyPair? {
        val raw = runCatching {
            when (params.algorithm) {
                Algorithm.EC -> {
                    Log.d(TAG, "Generating EC keypair of size ${params.keySize}")
                    KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                        .apply { initialize(ECGenParameterSpec(params.ecCurveName ?: "secp256r1")) }
                        .generateKeyPair()
                }

                Algorithm.RSA -> {
                    Log.d(TAG, "Generating RSA keypair of size ${params.keySize}")
                    KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
                        .apply { initialize(RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4)) }
                        .generateKeyPair()
                }

                else -> {
                    Log.i(TAG, "Skipping non-EC/non-RSA algorithm: ${params.algorithm}")
                    null
                }
            }
        }
        return raw.onFailure { Log.e(TAG, "Failed to generate key pair", it) }.getOrNull()
    }

    fun generateSecretKey(params: KeyGenParameters): javax.crypto.SecretKey? {
        val raw = runCatching {
            when (params.algorithm) {
                Algorithm.AES ->
                    javax.crypto.KeyGenerator.getInstance("AES")
                        .apply { init(params.keySize.coerceAtLeast(128)) }
                        .generateKey()

                Algorithm.HMAC -> {
                    val algo =
                        "Hmac${CertificateUtils.digestName(params.digest.firstOrNull { it != 0 } ?: 0, false)}"
                    javax.crypto.KeyGenerator.getInstance(algo)
                        .apply { init(params.keySize.coerceAtLeast(256)) }
                        .generateKey()
                }

                else -> null
            }
        }
        return raw.onFailure { Log.e(TAG, "Failed to generate secret key", it) }.getOrNull()
    }

    fun generateKeyPair(
        uid: Int,
        descriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        params: KeyGenParameters,
        securityLevel: Int = 1,
    ): Pair<KeyPair, List<Certificate>>? {
        val raw = runCatching {
            Log.i(TAG, "Requested KeyPair with alias: ${descriptor.alias}")
            attestKeyDescriptor?.let { Log.i(TAG, "Requested KeyPair with attestKey: ${it.alias}") }

            val keyPair = generateKeyPair(params) ?: return null
            val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
            if (keybox.certificates.isEmpty()) {
                Log.e(TAG, "Keybox has no certificates")
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
        return raw.onFailure { Log.e(TAG, "Failed to generate key pair with certificates", it) }.getOrNull()
    }

    private fun getKeyboxForAlgorithm(algorithm: Int): KeyBox? {
        val name =
            when (algorithm) {
                Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC

                Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA

                else -> {
                    Log.e(TAG, "Unsupported algorithm: $algorithm")
                    null
                }
            } ?: return null
        return KeyBoxUtils.keyboxes[name] ?: KeyBoxUtils.keyboxes.values.firstOrNull()
    }

    private fun getAttestationKeyInfo(uid: Int, descriptor: KeyDescriptor): Pair<KeyPair, X500Name> {
        val alias =
            descriptor.alias
                ?: SecurityLevelInterceptor.findAliasForNspace(uid, descriptor.nspace)
                ?: throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                    "Designated attest key not resolvable (nspace=${descriptor.nspace}) for uid $uid",
                )
        val keyInfo =
            SecurityLevelInterceptor.getKeyPairs(uid, alias)
                ?: throw ServiceSpecificException(
                    KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                    "Designated attest key not found for uid $uid alias=$alias",
                )
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
                params.certificateNotBefore ?: Date(0),
                params.certificateNotAfter ?: Date(253402300799000L),
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
        val digestName = CertificateUtils.digestName(params.digest.firstOrNull { it != 0 } ?: 0, false)
        val signer =
            JcaContentSignerBuilder("${digestName}with$signerAlgorithm")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)
        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))
    }

    private fun resolveEcCurveName(curve: Int, keySize: Int): String =
        EC_CURVES.firstOrNull { it.curve == curve }?.name
            ?: EC_CURVES.firstOrNull { it.size == keySize }?.name
            ?: "secp256r1"

    fun generateChain(uid: Int, params: KeyGenParameters, keyPair: KeyPair, securityLevel: Int = 1): List<ByteArray>? {
        val raw = runCatching {
            val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
            val issuer = X509CertificateHolder(keybox.certificates[0].encoded).subject
            val leaf = buildCertificate(keyPair, keybox, params, issuer, uid, securityLevel)
            (listOf(leaf) + keybox.certificates).map { it.encoded }
        }
        return raw.onFailure { Log.e(TAG, "Failed to generate certificate chain", it) }.getOrNull()
    }

    private fun buildAttestExtension(params: KeyGenParameters, uid: Int, securityLevel: Int = 1): Extension {
        val versions = AndroidUtils.attestationVersions(securityLevel)
        val attestationVersion = versions.attestation
        val keymasterVersion = versions.keymaster
        val key = AndroidUtils.bootKey
        val hash = AndroidUtils.getBootHashFromProp()
        val rootOfTrust =
            DERSequence(arrayOf(DEROctetString(key), ASN1Boolean.TRUE, ASN1Enumerated(0), DEROctetString(hash)))
        val osVersion = ASN1Integer(AndroidUtils.osVersion.toLong())
        val creationTimeMs = System.currentTimeMillis()
        val creationDateTime = ASN1Integer(creationTimeMs)
        val origin = ASN1Integer((params.origin ?: 0).toLong())
        val moduleHash = DEROctetString(AndroidUtils.moduleHash)
        val applicationId = if (params.attestationChallenge != null) createApplicationId(uid) else null
        val uniqueId =
            if (params.includeUniqueId == true && applicationId != null) {
                computeUniqueId(creationTimeMs, applicationId.octets)
            } else {
                ByteArray(0)
            }

        val tee = mutableListOf<ASN1Encodable>()

        fun teeTag(tag: Int, v: ASN1Encodable) = tee.add(DERTaggedObject(true, tag, v))

        fun teeSet(tag: Int, vs: List<Int>) =
            vs.takeIf { it.isNotEmpty() }
                ?.let { teeTag(tag, DERSet(it.map { ASN1Integer(it.toLong()) }.toTypedArray())) }

        teeSet(1, params.purpose)
        teeTag(2, ASN1Integer(params.algorithm.toLong()))
        val effectiveKey = effectiveKeySize(params)
        if (effectiveKey > 0) teeTag(3, ASN1Integer(effectiveKey.toLong()))
        teeSet(5, params.digest)
        if (params.noAuthRequired == true) teeTag(503, DERNull.INSTANCE)
        if (params.callerNonce == true) teeTag(1005, DERNull.INSTANCE)
        teeTag(702, origin)
        teeTag(704, rootOfTrust)
        teeTag(705, osVersion)
        if (AndroidUtils.patchLevel(uid) != AndroidUtils.DO_NOT_REPORT)
            teeTag(706, ASN1Integer(AndroidUtils.patchLevel(uid).toLong()))
        if (AndroidUtils.vendorPatchLevelLong(uid) != AndroidUtils.DO_NOT_REPORT) {
            teeTag(718, ASN1Integer(AndroidUtils.vendorPatchLevelLong(uid).toLong()))
        }
        if (AndroidUtils.bootPatchLevelLong(uid) != AndroidUtils.DO_NOT_REPORT) {
            teeTag(719, ASN1Integer(AndroidUtils.bootPatchLevelLong(uid).toLong()))
        }
        teeSet(4, params.blockMode)
        teeSet(6, params.padding)
        if (attestationVersion >= 100) teeSet(203, params.mgfDigest)
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
        if (attestationVersion >= 300) params.imei2?.let { teeTag(723, DEROctetString(it)) }
        tee.sortBy { (it as DERTaggedObject).tagNo }

        val sw = mutableListOf<ASN1Encodable>(DERTaggedObject(true, 701, creationDateTime))
        params.activeDateTime?.let { sw.add(DERTaggedObject(true, 400, ASN1Integer(it))) }
        params.originationExpireDateTime?.let { sw.add(DERTaggedObject(true, 401, ASN1Integer(it))) }
        params.usageExpireDateTime?.let { sw.add(DERTaggedObject(true, 402, ASN1Integer(it))) }
        if (params.usageCountLimit > 0) sw.add(DERTaggedObject(true, 405, ASN1Integer(params.usageCountLimit.toLong())))
        if (params.unlockedDeviceRequired == true) sw.add(DERTaggedObject(true, 509, DERNull.INSTANCE))
        if (applicationId != null) sw.add(DERTaggedObject(true, 709, applicationId))
        if (attestationVersion >= 400) sw.add(DERTaggedObject(true, 724, moduleHash))
        sw.sortBy { (it as DERTaggedObject).tagNo }

        val keyDesc =
            arrayOf(
                ASN1Integer(attestationVersion.toLong()),
                ASN1Enumerated(securityLevel),
                ASN1Integer(keymasterVersion.toLong()),
                ASN1Enumerated(securityLevel),
                DEROctetString(params.attestationChallenge ?: ByteArray(0)),
                DEROctetString(uniqueId),
                DERSequence(sw.toTypedArray()),
                DERSequence(tee.toTypedArray()),
            )
        return Extension(ATTESTATION_OID, false, DEROctetString(DERSequence(keyDesc).encoded))
    }

    // persisted so the unique_id stays stable across reboots; ephemeral fallback if unwritable
    private val hbk: ByteArray by lazy {
        val file = File("/data/adb/tricky_store/hbk")
        if (file.exists() && file.length() == 32L) {
            file.readBytes()
        } else {
            val k = ByteArray(32).also { SecureRandom().nextBytes(it) }
            file.parentFile?.mkdirs()
            file.writeBytes(k)
            k
        }
    }

    // counter advances every ~30 days, so later keys get a different unique_id like real hardware
    private fun computeUniqueId(creationTimeMs: Long, aaidDer: ByteArray): ByteArray {
        val temporalCounter = creationTimeMs / 2592000000L
        val message = ByteBuffer.allocate(8 + aaidDer.size + 1).putLong(temporalCounter).put(aaidDer).put(0x00).array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hbk, "HmacSHA256"))
        return mac.doFinal(message).copyOf(16)
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
                    info.signingInfo?.signingCertificateHistory?.forEach { sig ->
                        signatures.add(md.digest(sig.toByteArray()))
                    }
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
