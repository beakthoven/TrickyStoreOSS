/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.content.pm.PackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.Tag
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import android.util.Pair
import io.github.beakthoven.TrickyStoreOSS.*
import io.github.beakthoven.TrickyStoreOSS.core.config.Config
import io.github.beakthoven.TrickyStoreOSS.core.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import android.os.Build

object CertificateHacker {
    
    private val ATTESTATION_OID = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    
    private val certificateFactory: CertificateFactory by lazy {
        try {
            CertificateFactory.getInstance("X.509")
        } catch (t: Throwable) {
            Logger.e("Failed to initialize certificate factory", t)
            throw RuntimeException("Cannot initialize certificate factory", t)
        }
    }
    
    data class KeyBox(
        val pemKeyPair: PEMKeyPair,
        val keyPair: KeyPair,
        val certificates: List<Certificate>
    )
    
    data class KeyIdentifier(
        val alias: String,
        val uid: Int
    )
    
    sealed class ParseResult<out T> {
        data class Success<T>(val data: T) : ParseResult<T>()
        data class Error(val message: String, val cause: Throwable? = null) : ParseResult<Nothing>()
    }
    
    sealed class HackResult<out T> {
        data class Success<T>(val data: T) : HackResult<T>()
        data class Error(val message: String, val cause: Throwable? = null) : HackResult<Nothing>()
    }
    
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
        var attestationChallenge: ByteArray? = null,
        var brand: ByteArray? = null,
        var device: ByteArray? = null,
        var product: ByteArray? = null,
        var manufacturer: ByteArray? = null,
        var model: ByteArray? = null,
        var imei1: ByteArray? = null,
        var imei2: ByteArray? = null,
        var meid: ByteArray? = null,
        var serialno: ByteArray? = null
    ) {
        
        constructor(params: Array<KeyParameter>) : this() {
            parseKeyParameters(params)
        }
        
        private fun parseKeyParameters(params: Array<KeyParameter>) {
            params.forEach { param ->
                Logger.d("Processing key parameter: ${param.tag}")
                val value = param.value
                
                when (param.tag) {
                    Tag.KEY_SIZE -> keySize = value.integer
                    Tag.ALGORITHM -> algorithm = value.algorithm
                    Tag.CERTIFICATE_SERIAL -> certificateSerial = BigInteger(value.blob)
                    Tag.CERTIFICATE_NOT_BEFORE -> certificateNotBefore = Date(value.dateTime)
                    Tag.CERTIFICATE_NOT_AFTER -> certificateNotAfter = Date(value.dateTime)
                    Tag.CERTIFICATE_SUBJECT -> certificateSubject = X500Name(X500Principal(value.blob).name)
                    Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = BigInteger(value.blob)
                    Tag.EC_CURVE -> {
                        ecCurve = value.ecCurve
                        ecCurveName = getEcCurveName(ecCurve)
                    }
                    Tag.PURPOSE -> purpose.add(value.keyPurpose)
                    Tag.DIGEST -> digest.add(value.digest)
                    Tag.ATTESTATION_CHALLENGE -> attestationChallenge = value.blob
                    Tag.ATTESTATION_ID_BRAND -> brand = value.blob
                    Tag.ATTESTATION_ID_DEVICE -> device = value.blob
                    Tag.ATTESTATION_ID_PRODUCT -> product = value.blob
                    Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = value.blob
                    Tag.ATTESTATION_ID_MODEL -> model = value.blob
                    Tag.ATTESTATION_ID_IMEI -> imei1 = value.blob
                    Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = value.blob
                    Tag.ATTESTATION_ID_MEID -> meid = value.blob
                }
            }
        }
        
        fun setEcCurveName(curveSize: Int) {
            ecCurveName = when (curveSize) {
                224 -> "secp224r1"
                256 -> "secp256r1"
                384 -> "secp384r1"
                521 -> "secp521r1"
                else -> "secp256r1"
            }
        }
        
        companion object {
            private fun getEcCurveName(curve: Int): String = when (curve) {
                EcCurve.CURVE_25519 -> "CURVE_25519"
                EcCurve.P_224 -> "secp224r1"
                EcCurve.P_256 -> "secp256r1"
                EcCurve.P_384 -> "secp384r1"
                EcCurve.P_521 -> "secp521r1"
                else -> throw IllegalArgumentException("Unknown EC curve: $curve")
            }
        }
        
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            
            other as KeyGenParameters
            
            return keySize == other.keySize &&
                    algorithm == other.algorithm &&
                    certificateSerial == other.certificateSerial &&
                    certificateNotBefore == other.certificateNotBefore &&
                    certificateNotAfter == other.certificateNotAfter &&
                    certificateSubject == other.certificateSubject &&
                    rsaPublicExponent == other.rsaPublicExponent &&
                    ecCurve == other.ecCurve &&
                    ecCurveName == other.ecCurveName &&
                    purpose == other.purpose &&
                    digest == other.digest &&
                    attestationChallenge.contentEquals(other.attestationChallenge) &&
                    brand.contentEquals(other.brand) &&
                    device.contentEquals(other.device) &&
                    product.contentEquals(other.product) &&
                    manufacturer.contentEquals(other.manufacturer) &&
                    model.contentEquals(other.model) &&
                    imei1.contentEquals(other.imei1) &&
                    imei2.contentEquals(other.imei2) &&
                    meid.contentEquals(other.meid) &&
                    serialno.contentEquals(other.serialno)
        }
        
        override fun hashCode(): Int {
            var result = keySize
            result = 31 * result + algorithm
            result = 31 * result + (certificateSerial?.hashCode() ?: 0)
            result = 31 * result + (certificateNotBefore?.hashCode() ?: 0)
            result = 31 * result + (certificateNotAfter?.hashCode() ?: 0)
            result = 31 * result + (certificateSubject?.hashCode() ?: 0)
            result = 31 * result + (rsaPublicExponent?.hashCode() ?: 0)
            result = 31 * result + ecCurve
            result = 31 * result + (ecCurveName?.hashCode() ?: 0)
            result = 31 * result + purpose.hashCode()
            result = 31 * result + digest.hashCode()
            result = 31 * result + (attestationChallenge?.contentHashCode() ?: 0)
            result = 31 * result + (brand?.contentHashCode() ?: 0)
            result = 31 * result + (device?.contentHashCode() ?: 0)
            result = 31 * result + (product?.contentHashCode() ?: 0)
            result = 31 * result + (manufacturer?.contentHashCode() ?: 0)
            result = 31 * result + (model?.contentHashCode() ?: 0)
            result = 31 * result + (imei1?.contentHashCode() ?: 0)
            result = 31 * result + (imei2?.contentHashCode() ?: 0)
            result = 31 * result + (meid?.contentHashCode() ?: 0)
            result = 31 * result + (serialno?.contentHashCode() ?: 0)
            return result
        }
    }
    
    private val keyboxes = ConcurrentHashMap<String, KeyBox>()
    private val leafAlgorithms = ConcurrentHashMap<KeyIdentifier, String>()
    

    
    fun hasKeyboxes(): Boolean = keyboxes.isNotEmpty()
    
    private data class Digest(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Digest
            return digest.contentEquals(other.digest)
        }
        
        override fun hashCode(): Int = digest.contentHashCode()
    }

    fun String.sanitizeXml(): String {
        var content = this

        val boms = listOf(
            "\uFEFF",
            "\uFFFE",
            "\u0000\uFEFF"
        )
        content = content.trimStart()
        for (bom in boms) {
            content = content.removePrefix(bom)
        }
        content = content.trimStart()

        return content.trimEnd()
    }
    
    fun readFromXml(xmlData: String?) {
        keyboxes.clear()
        leafAlgorithms.clear()
        
        if (xmlData == null) {
            Logger.i("Clearing all keyboxes")
            return
        }
        
        try {
            val xmlParser = XmlParser(xmlData.sanitizeXml())
            
            val numberOfKeyboxesResult = xmlParser.obtainPath("AndroidAttestation.NumberOfKeyboxes")
            val numberOfKeyboxes = when (numberOfKeyboxesResult) {
                is XmlParser.ParseResult.Success -> numberOfKeyboxesResult.attributes["text"]?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid number of keyboxes")
                is XmlParser.ParseResult.Error -> throw Exception(numberOfKeyboxesResult.message, numberOfKeyboxesResult.cause)
            }
            
            repeat(numberOfKeyboxes) { i ->
                processKeybox(xmlParser, i)
            }
            
            Logger.i("Successfully updated $numberOfKeyboxes keyboxes")
        } catch (t: Throwable) {
            Logger.e("Error loading XML file (keyboxes cleared)", t)
        }
    }
    
    private fun processKeybox(xmlParser: XmlParser, index: Int) {
        try {
            val algorithmResult = xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index]")
            val keyboxAlgorithm = when (algorithmResult) {
                is XmlParser.ParseResult.Success -> algorithmResult.attributes["algorithm"]
                    ?: throw IllegalArgumentException("Missing algorithm attribute")
                is XmlParser.ParseResult.Error -> throw Exception(algorithmResult.message, algorithmResult.cause)
            }
            
            val privateKeyResult = xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index].PrivateKey")
            val privateKeyContent = when (privateKeyResult) {
                is XmlParser.ParseResult.Success -> privateKeyResult.attributes["text"]
                    ?: throw IllegalArgumentException("Missing private key text")
                is XmlParser.ParseResult.Error -> throw Exception(privateKeyResult.message, privateKeyResult.cause)
            }
            
            val numberOfCertificatesResult = xmlParser.obtainPath(
                "AndroidAttestation.Keybox.Key[$index].CertificateChain.NumberOfCertificates"
            )
            val numberOfCertificates = when (numberOfCertificatesResult) {
                is XmlParser.ParseResult.Success -> numberOfCertificatesResult.attributes["text"]?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid number of certificates")
                is XmlParser.ParseResult.Error -> throw Exception(numberOfCertificatesResult.message, numberOfCertificatesResult.cause)
            }
            
            val certificateChain = mutableListOf<Certificate>()
            repeat(numberOfCertificates) { j ->
                val certResult = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[$index].CertificateChain.Certificate[$j]"
                )
                val certContent = when (certResult) {
                    is XmlParser.ParseResult.Success -> certResult.attributes["text"]
                        ?: throw IllegalArgumentException("Missing certificate text")
                    is XmlParser.ParseResult.Error -> throw Exception(certResult.message, certResult.cause)
                }
                
                when (val certParseResult = CertificateUtils.parseCertificate(certContent)) {
                    is CertificateUtils.ParseResult.Success -> certificateChain.add(certParseResult.data)
                    is CertificateUtils.ParseResult.Error -> throw Exception(certParseResult.message, certParseResult.cause)
                }
            }
            
            val pemKeyPair = when (val keyParseResult = CertificateUtils.parseKeyPair(privateKeyContent)) {
                is CertificateUtils.ParseResult.Success -> keyParseResult.data
                is CertificateUtils.ParseResult.Error -> throw Exception(keyParseResult.message, keyParseResult.cause)
            }
            
            val keyPair = CertificateUtils.convertPemToKeyPair(pemKeyPair)
            
            val algorithmName = when (keyboxAlgorithm.lowercase()) {
                "ecdsa" -> KeyProperties.KEY_ALGORITHM_EC
                "rsa" -> KeyProperties.KEY_ALGORITHM_RSA
                else -> keyboxAlgorithm
            }
            
            keyboxes[algorithmName] = KeyBox(pemKeyPair, keyPair, certificateChain)
            
        } catch (t: Throwable) {
            Logger.e("Error processing keybox $index", t)
            throw t
        }
    }
    
    fun hackCertificateChain(certificateChain: Array<Certificate>?): Array<Certificate> {
        if (certificateChain == null) {
            throw UnsupportedOperationException("Certificate chain is null!")
        }
        
        return try {
            val leaf = certificateFactory.generateCertificate(
                ByteArrayInputStream(certificateChain[0].encoded)
            ) as X509Certificate
            
            val extensionBytes = leaf.getExtensionValue(ATTESTATION_OID.id)
                ?: return certificateChain // No attestation extension, return original

            val leafHolder = X509CertificateHolder(leaf.encoded)
            val extension = leafHolder.getExtension(ATTESTATION_OID)
            val sequence = ASN1Sequence.getInstance(extension.extnValue.octets)
            val encodables = sequence.toArray()
            val teeEnforced = encodables[7] as ASN1Sequence
            
            val vector = ASN1EncodableVector()
            var rootOfTrust: ASN1Encodable? = null
            
            teeEnforced.forEach { element ->
                val taggedObject = element as ASN1TaggedObject
                if (taggedObject.tagNo == 704) {
                    rootOfTrust = taggedObject.baseObject.toASN1Primitive()
                } else {
                    vector.add(taggedObject)
                }
            }
            
            val keybox = keyboxes[leaf.publicKey.algorithm]
                ?: throw UnsupportedOperationException("Unsupported algorithm: ${leaf.publicKey.algorithm}")
            
            val certificates = LinkedList(keybox.certificates)
            val builder = X509v3CertificateBuilder(
                X509CertificateHolder(certificates[0].encoded).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo
            )
            
            val signer = JcaContentSignerBuilder(leaf.sigAlgName).build(keybox.keyPair.private)
            
            val hackedExtension = createHackedAttestationExtension(rootOfTrust, vector, encodables)
            builder.addExtension(hackedExtension)
            
            leafHolder.extensions.extensionOIDs.forEach { oid ->
                if (oid.id != ATTESTATION_OID.id) {
                    builder.addExtension(leafHolder.getExtension(oid))
                }
            }
            
            certificates.addFirst(JcaX509CertificateConverter().getCertificate(builder.build(signer)))
            certificates.toTypedArray()
        } catch (t: Throwable) {
            Logger.e("Failed to hack certificate chain", t)
            certificateChain
        }
    }
    
    fun hackCACertificateChain(caList: ByteArray?, alias: String, uid: Int): ByteArray {
        if (caList == null) {
            throw UnsupportedOperationException("CA list is null!")
        }
        
        return try {
            val key = KeyIdentifier(alias, uid)
            val algorithm = leafAlgorithms.remove(key)
                ?: throw UnsupportedOperationException("No algorithm found for key $key")
            
            val keybox = keyboxes[algorithm]
                ?: throw UnsupportedOperationException("Unsupported algorithm: $algorithm")
            
            CertificateUtils.run { keybox.certificates.toByteArray() } ?: caList
        } catch (t: Throwable) {
            Logger.e("Failed to hack CA certificate chain", t)
            caList
        }
    }
    
    fun hackUserCertificate(certificate: ByteArray?, alias: String, uid: Int): ByteArray {
        if (certificate == null) {
            throw UnsupportedOperationException("Leaf certificate is null!")
        }
        
        return try {
            val leaf = certificateFactory.generateCertificate(
                ByteArrayInputStream(certificate)
            ) as X509Certificate
            
            val extensionBytes = leaf.getExtensionValue(ATTESTATION_OID.id)
                ?: return certificate // No attestation extension, return original
            
            val keyIdentifier = KeyIdentifier(alias, uid)
            leafAlgorithms[keyIdentifier] = leaf.publicKey.algorithm
            
            val leafHolder = X509CertificateHolder(leaf.encoded)
            val extension = leafHolder.getExtension(ATTESTATION_OID)
            val sequence = ASN1Sequence.getInstance(extension.extnValue.octets)
            val encodables = sequence.toArray()
            val teeEnforced = encodables[7] as ASN1Sequence
            
            val vector = ASN1EncodableVector()
            var rootOfTrust: ASN1Encodable? = null
            
            teeEnforced.forEach { element ->
                val taggedObject = element as ASN1TaggedObject
                if (taggedObject.tagNo == 704) {
                    rootOfTrust = taggedObject.baseObject.toASN1Primitive()
                } else {
                    vector.add(taggedObject)
                }
            }
            
            val keybox = keyboxes[leaf.publicKey.algorithm]
                ?: throw UnsupportedOperationException("Unsupported algorithm: ${leaf.publicKey.algorithm}")
            
            val builder = X509v3CertificateBuilder(
                X509CertificateHolder(keybox.certificates[0].encoded).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo
            )
            
            val signer = JcaContentSignerBuilder(leaf.sigAlgName).build(keybox.keyPair.private)
            
            val hackedExtension = createHackedAttestationExtension(rootOfTrust, vector, encodables)
            builder.addExtension(hackedExtension)
            
            leafHolder.extensions.extensionOIDs.forEach { oid ->
                if (oid.id != ATTESTATION_OID.id) {
                    builder.addExtension(leafHolder.getExtension(oid))
                }
            }

            JcaX509CertificateConverter().getCertificate(builder.build(signer)).encoded
        } catch (t: Throwable) {
            Logger.e("Failed to hack user certificate", t)
            certificate
        }
    }
    
    fun generateKeyPair(params: KeyGenParameters): KeyPair? = runCatching {
        when (params.algorithm) {
            Algorithm.EC -> {
                Logger.d("Generating EC keypair of size ${params.keySize}")
                buildECKeyPair(params)
            }
            Algorithm.RSA -> {
                Logger.d("Generating RSA keypair of size ${params.keySize}")
                buildRSAKeyPair(params)
            }
            else -> {
                Logger.e("Unsupported algorithm: ${params.algorithm}")
                null
            }
        }
    }.onFailure { 
        Logger.e("Failed to generate key pair", it) 
    }.getOrNull()
    
    fun generateChain(uid: Int, params: KeyGenParameters, keyPair: KeyPair, securityLevel: Int = 1): List<ByteArray>? = runCatching {
        val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null

        val issuer = X509CertificateHolder(keybox.certificates[0].encoded).subject
        val leaf = buildCertificate(keyPair, keybox, params, issuer, uid, securityLevel)
        
        val chain = buildList {
            add(leaf)
            addAll(keybox.certificates)
        }
        
        CertificateUtils.run { chain.toByteArrayList() }
    }.onFailure { 
        Logger.e("Failed to generate certificate chain", it) 
    }.getOrNull()
    
    fun generateKeyPair(
        uid: Int,
        descriptor: KeyDescriptor,
        attestKeyDescriptor: KeyDescriptor?,
        params: KeyGenParameters,
        securityLevel: Int = 1
    ): Pair<KeyPair, List<Certificate>>? = runCatching {
        Logger.i("Requested KeyPair with alias: ${descriptor.alias}")
        
        val hasAttestKey = attestKeyDescriptor != null
        if (hasAttestKey) {
            Logger.i("Requested KeyPair with attestKey: ${attestKeyDescriptor?.alias}")
        }
        
        val keyPair = generateKeyPair(params) ?: return null
        val keybox = getKeyboxForAlgorithm(params.algorithm) ?: return null
        
        val (signingKeyPair, issuer) = if (hasAttestKey) {
            getAttestationKeyInfo(uid, attestKeyDescriptor!!)?.let { 
                it.first to it.second 
            } ?: (keybox.keyPair to X509CertificateHolder(keybox.certificates[0].encoded).subject)
        } else {
            keybox.keyPair to X509CertificateHolder(keybox.certificates[0].encoded).subject
        }
        
        val leaf = buildCertificate(keyPair, keybox, params, issuer, uid, securityLevel, signingKeyPair)
        val chain = buildList {
            add(leaf)
            if (!hasAttestKey) {
                addAll(keybox.certificates)
            }
        }
        
        Logger.d("Successfully generated certificate for alias: ${descriptor.alias}")
        Pair(keyPair, chain)
    }.onFailure { 
        Logger.e("Failed to generate key pair with certificates", it) 
    }.getOrNull()
    
    private fun buildECKeyPair(params: KeyGenParameters): KeyPair {
        setupBouncyCastle()
        val spec = ECGenParameterSpec(params.ecCurveName)
        val keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME)
        keyPairGenerator.initialize(spec)
        return keyPairGenerator.generateKeyPair()
    }
    
    private fun buildRSAKeyPair(params: KeyGenParameters): KeyPair {
        setupBouncyCastle()
        val spec = RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent)
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
        keyPairGenerator.initialize(spec)
        return keyPairGenerator.generateKeyPair()
    }
    
    private fun setupBouncyCastle() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
    }
    
    private fun mapAlgorithmToName(algorithm: Int): String? = when (algorithm) {
        Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC
        Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
        else -> {
            Logger.e("Unsupported algorithm: $algorithm")
            null
        }
    }

    private fun getKeyboxForAlgorithm(algorithm: Int): KeyBox? {
        val algorithmName = mapAlgorithmToName(algorithm) ?: return null
        return keyboxes[algorithmName]
    }
    
    private fun getAttestationKeyInfo(uid: Int, attestKeyDescriptor: KeyDescriptor): Pair<KeyPair, X500Name>? {
        Logger.d("Looking for attestation key: uid=$uid alias=${attestKeyDescriptor.alias}")
        
        val keyInfo = SecurityLevelInterceptor.getKeyPairs(uid, attestKeyDescriptor.alias)
        return if (keyInfo != null) {
            val issuer = X509CertificateHolder(keyInfo.second[0].encoded).subject
            Pair(keyInfo.first, issuer)
        } else {
            Logger.e("Attestation key info not found, falling back to default keybox")
            null
        }
    }
    
    private fun createHackedAttestationExtension(
        originalRootOfTrust: ASN1Encodable?,
        vector: ASN1EncodableVector,
        originalEncodables: Array<ASN1Encodable>
    ): Extension {
        val verifiedBootKey = bootKey
        var verifiedBootHash: ByteArray? = null
        
        try {
            if (originalRootOfTrust is ASN1Sequence) {
                verifiedBootHash = CertificateUtils.getByteArrayFromAsn1(originalRootOfTrust.getObjectAt(3))
            }
        } catch (t: Throwable) {
            Logger.e("Failed to get verified boot hash from original, using generated", t)
        }
        
        if (verifiedBootHash == null) {
            verifiedBootHash = bootHash
        }
        
        val rootOfTrustElements = arrayOf(
            DEROctetString(verifiedBootKey),
            ASN1Boolean.TRUE,
            ASN1Enumerated(0),
            DEROctetString(verifiedBootHash)
        )
        val hackedRootOfTrust = DERSequence(rootOfTrustElements)
        
        vector.add(DERTaggedObject(true, 718, ASN1Integer(vendorPatchLevelLong.toLong())))
        vector.add(DERTaggedObject(true, 719, ASN1Integer(bootPatchLevelLong.toLong())))
        vector.add(DERTaggedObject(true, 706, ASN1Integer(patchLevel.toLong())))
        vector.add(DERTaggedObject(true, 705, ASN1Integer(osVersion.toLong())))
        vector.add(DERTaggedObject(704, hackedRootOfTrust))
        
        val hackEnforced = DERSequence(vector)
        originalEncodables[7] = hackEnforced
        val hackedSequence = DERSequence(originalEncodables)
        val hackedSequenceOctets = DEROctetString(hackedSequence)
        
        return Extension(ATTESTATION_OID, false, hackedSequenceOctets)
    }
    
    private fun buildCertificate(
        keyPair: KeyPair,
        keybox: KeyBox,
        params: KeyGenParameters,
        issuer: X500Name,
        uid: Int,
        securityLevel: Int = 1,
        signingKeyPair: KeyPair = keybox.keyPair
    ): Certificate {
        val builder = JcaX509v3CertificateBuilder(
            issuer,
            params.certificateSerial ?: BigInteger.ONE,
            params.certificateNotBefore ?: Date(),
            params.certificateNotAfter ?: (keybox.certificates[0] as X509Certificate).notAfter,
            params.certificateSubject ?: X500Name("CN=Android KeyStore Key"),
            keyPair.public
        )
        
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign))
        builder.addExtension(createAttestationExtension(params, uid, securityLevel))
        
        val signerAlgorithm = when (params.algorithm) {
            Algorithm.EC -> "SHA256withECDSA"
            Algorithm.RSA -> "SHA256withRSA"
            else -> throw IllegalArgumentException("Unsupported algorithm: ${params.algorithm}")
        }
        val contentSigner = JcaContentSignerBuilder(signerAlgorithm).build(signingKeyPair.private)
        
        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }

    private fun createAttestationExtension(params: KeyGenParameters, uid: Int, securityLevel: Int = 1): Extension {
        try {
            val key = bootKey
            val hash = bootHash
            
            val rootOfTrustEncodables = arrayOf(
                DEROctetString(key),
                ASN1Boolean.TRUE,
                ASN1Enumerated(0),
                DEROctetString(hash)
            )
            val rootOfTrustSeq = DERSequence(rootOfTrustEncodables)
            
            val purpose = DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray())
            val algorithm = ASN1Integer(params.algorithm.toLong())
            val keySize = ASN1Integer(params.keySize.toLong())
            val digest = DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray())
            val ecCurve = ASN1Integer(params.ecCurve.toLong())
            val noAuthRequired = DERNull.INSTANCE
            
            val osVersion = ASN1Integer(io.github.beakthoven.TrickyStoreOSS.osVersion.toLong())
            val osPatchLevel = ASN1Integer(io.github.beakthoven.TrickyStoreOSS.patchLevel.toLong())
            val applicationID = createApplicationId(uid)
            val bootPatchLevel = ASN1Integer(bootPatchLevelLong.toLong())
            val vendorPatchLevel = ASN1Integer(vendorPatchLevelLong.toLong())
            val creationDateTime = ASN1Integer(System.currentTimeMillis())
            val origin = ASN1Integer(0L)
            val moduleHash = DEROctetString(io.github.beakthoven.TrickyStoreOSS.moduleHash)
            
            val teeEnforcedObjects = mutableListOf(
                DERTaggedObject(true, 1, purpose),
                DERTaggedObject(true, 2, algorithm),
                DERTaggedObject(true, 3, keySize),
                DERTaggedObject(true, 5, digest),
                DERTaggedObject(true, 10, ecCurve),
                DERTaggedObject(true, 503, noAuthRequired),
                DERTaggedObject(true, 702, origin),
                DERTaggedObject(true, 704, rootOfTrustSeq),
                DERTaggedObject(true, 705, osVersion),
                DERTaggedObject(true, 706, osPatchLevel),
                DERTaggedObject(true, 718, vendorPatchLevel),
                DERTaggedObject(true, 719, bootPatchLevel),
            )

            if (io.github.beakthoven.TrickyStoreOSS.attestVersion >= 400) {
                teeEnforcedObjects.add(DERTaggedObject(true, 724, moduleHash))
            }
            
            params.brand?.let { teeEnforcedObjects.add(DERTaggedObject(true, 710, DEROctetString(it))) }
            params.device?.let { teeEnforcedObjects.add(DERTaggedObject(true, 711, DEROctetString(it))) }
            params.product?.let { teeEnforcedObjects.add(DERTaggedObject(true, 712, DEROctetString(it))) }
            params.manufacturer?.let { teeEnforcedObjects.add(DERTaggedObject(true, 716, DEROctetString(it))) }
            params.model?.let { teeEnforcedObjects.add(DERTaggedObject(true, 717, DEROctetString(it))) }
            
            params.serialno?.let { teeEnforcedObjects.add(DERTaggedObject(true, 713, DEROctetString(it))) }
            params.imei1?.let { teeEnforcedObjects.add(DERTaggedObject(true, 714, DEROctetString(it))) }
            params.meid?.let { teeEnforcedObjects.add(DERTaggedObject(true, 715, DEROctetString(it))) }

            if (io.github.beakthoven.TrickyStoreOSS.attestVersion >= 300) {
                params.imei2?.let { teeEnforcedObjects.add(DERTaggedObject(true, 723, DEROctetString(it))) }
            }

            teeEnforcedObjects.sortBy { it.tagNo }
            
            val softwareEnforcedObjects = arrayOf<ASN1Encodable>(
                DERTaggedObject(true, 709, applicationID),
                DERTaggedObject(true, 701, creationDateTime)
            )
            
            return Extension(
                ATTESTATION_OID,
                false,
                getAsn1OctetString(teeEnforcedObjects.toTypedArray(), softwareEnforcedObjects, params, securityLevel)
            )
        } catch (t: Throwable) {
            Logger.e("Failed to create attestation extension", t)
            throw t
        }
    }
    

    
    private fun getAsn1OctetString(
        teeEnforcedEncodables: Array<ASN1Encodable>,
        softwareEnforcedEncodables: Array<ASN1Encodable>,
        params: KeyGenParameters,
        securityLevel: Int = 1
    ): ASN1OctetString {
        val attestationVersion = ASN1Integer(io.github.beakthoven.TrickyStoreOSS.attestVersion.toLong())
        val attestationSecurityLevel = ASN1Enumerated(securityLevel)
        val keymasterVersion = ASN1Integer(io.github.beakthoven.TrickyStoreOSS.keymasterVersion.toLong())
        val keymasterSecurityLevel = ASN1Enumerated(securityLevel)
        val attestationChallenge = DEROctetString(params.attestationChallenge ?: ByteArray(0))
        val uniqueId = DEROctetString(ByteArray(0))
        val softwareEnforced = DERSequence(softwareEnforcedEncodables)
        val teeEnforced = DERSequence(teeEnforcedEncodables)
        
        val keyDescriptionEncodables = arrayOf(
            attestationVersion,
            attestationSecurityLevel,
            keymasterVersion,
            keymasterSecurityLevel,
            attestationChallenge,
            uniqueId,
            softwareEnforced,
            teeEnforced
        )
        
        val keyDescriptionSeq = DERSequence(keyDescriptionEncodables)
        return DEROctetString(keyDescriptionSeq.encoded)
    }
    
    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm = Config.getPm() ?: throw IllegalStateException("PackageManager not found!")
        val packages = pm.getPackagesForUid(uid) ?: throw IllegalStateException("No packages for UID $uid")

        val messageDigest = MessageDigest.getInstance("SHA-256")
        val signatures = mutableSetOf<Digest>()

        val packageInfos = packages.map { packageName ->
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES.toLong(), uid / 100000)
            } else {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES, uid / 100000)
            }

            info.signingInfo?.signingCertificateHistory?.forEach { signature ->
                signatures.add(Digest(messageDigest.digest(signature.toByteArray())))
            }

            info
        }

        val packageInfoArray = packageInfos.map { info ->
            DERSequence(
                arrayOf(
                    DEROctetString(info.packageName.toByteArray(StandardCharsets.UTF_8)),
                    ASN1Integer(info.longVersionCode)
                )
            )
        }.toTypedArray()

        val signaturesArray = signatures.map { DEROctetString(it.digest) }.toTypedArray()

        val applicationIdArray = arrayOf(
            DERSet(packageInfoArray),
            DERSet(signaturesArray)
        )

        return DEROctetString(DERSequence(applicationIdArray).encoded)
    }

}