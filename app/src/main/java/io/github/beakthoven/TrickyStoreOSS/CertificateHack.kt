/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.ByteArrayInputStream
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.LinkedList
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

object CertificateHack {
    private val certificateFactory: CertificateFactory by lazy {
        try {
            CertificateFactory.getInstance("X.509")
        } catch (t: Throwable) {
            Logger.e("Failed to initialize certificate factory", t)
            throw RuntimeException("Cannot initialize certificate factory", t)
        }
    }

    data class KeyIdentifier(val alias: String, val uid: Int)

    val leafAlgorithms = ConcurrentHashMap<KeyIdentifier, String>()

    fun patchAuthorizations(authorizations: Array<Authorization>?): Array<Authorization>? {
        if (authorizations == null) return null
        val os = AndroidUtils.patchLevel
        val vendor = AndroidUtils.vendorPatchLevelLong
        val boot = AndroidUtils.bootPatchLevelLong
        return authorizations
            .map { auth ->
                val replacement: Int? =
                    when (auth.keyParameter.tag) {
                        Tag.OS_PATCHLEVEL -> if (os != AndroidUtils.DO_NOT_REPORT) os else null
                        Tag.VENDOR_PATCHLEVEL -> if (vendor != AndroidUtils.DO_NOT_REPORT) vendor else null
                        Tag.BOOT_PATCHLEVEL -> if (boot != AndroidUtils.DO_NOT_REPORT) boot else null
                        else -> null
                    }
                if (replacement != null)
                    Authorization().apply {
                        securityLevel = auth.securityLevel
                        keyParameter =
                            KeyParameter().apply {
                                tag = auth.keyParameter.tag
                                value = KeyParameterValue.integer(replacement)
                            }
                    }
                else auth
            }
            .toTypedArray()
    }

    fun clearLeafAlgorithms() {
        leafAlgorithms.clear()
    }

    private fun hackLeaf(certificateChain: Array<Certificate>): Array<Certificate> {
        val leaf = certificateFactory.generateCertificate(ByteArrayInputStream(certificateChain[0].encoded)) as X509Certificate
        val leafHolder = X509CertificateHolder(leaf.encoded)
        val extension = leafHolder.getExtension(ATTESTATION_OID) ?: return certificateChain
        val encodables = ASN1Sequence.getInstance(extension.extnValue.octets).toArray()
        val teeEnforced = encodables[7] as ASN1Sequence

        var rootOfTrust: ASN1Encodable? = null
        val vector = ASN1EncodableVector()
        teeEnforced.forEach {
            (it as ASN1TaggedObject).let {
                if (it.tagNo == 704) rootOfTrust = it.baseObject.toASN1Primitive() else vector.add(it)
            }
        }

        val algorithm = leaf.publicKey.algorithm
        val keybox =
            KeyBoxUtils.keyboxes[algorithm]
                ?: KeyBoxUtils.keyboxes.entries.firstOrNull()?.value
                ?: throw UnsupportedOperationException("No keybox for algorithm: $algorithm")
        val certs = LinkedList(keybox.certificates)
        val builder =
            X509v3CertificateBuilder(
                X509CertificateHolder(certs[0].encoded).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo,
            )
        builder.addExtension(hackAttestExtension(rootOfTrust, vector, encodables))
        leafHolder.extensions.extensionOIDs.forEach { oid ->
            if (oid.id != ATTESTATION_OID.id) builder.addExtension(leafHolder.getExtension(oid))
        }
        certs.addFirst(
            JcaX509CertificateConverter()
                .getCertificate(builder.build(JcaContentSignerBuilder(leaf.sigAlgName).build(keybox.keyPair.private)))
        )
        return certs.toTypedArray()
    }

    fun hackCertificateChain(certificateChain: Array<Certificate>?): Array<Certificate> {
        if (certificateChain == null) throw UnsupportedOperationException("Certificate chain is null!")
        return try {
            hackLeaf(certificateChain)
        } catch (t: Throwable) {
            Logger.e("Failed to hack certificate chain", t)
            certificateChain
        }
    }

    fun hackCACertificateChain(caList: ByteArray?, alias: String, uid: Int): ByteArray {
        if (caList == null) throw UnsupportedOperationException("CA list is null!")
        return try {
            val algorithm =
                leafAlgorithms.remove(KeyIdentifier(alias, uid))
                    ?: throw UnsupportedOperationException("No algorithm found for key ($alias, $uid)")
            val keybox =
                KeyBoxUtils.keyboxes[algorithm]
                    ?: KeyBoxUtils.keyboxes.entries.firstOrNull()?.value
                    ?: throw UnsupportedOperationException("Unsupported algorithm: $algorithm")
            CertificateUtils.run { keybox.certificates.toByteArray() } ?: caList
        } catch (t: Throwable) {
            Logger.e("Failed to hack CA certificate chain", t)
            caList
        }
    }

    fun hackUserCertificate(certificate: ByteArray?, alias: String, uid: Int): ByteArray {
        if (certificate == null) throw UnsupportedOperationException("Leaf certificate is null!")
        return try {
            val leaf = certificateFactory.generateCertificate(ByteArrayInputStream(certificate)) as X509Certificate
            if (leaf.getExtensionValue(ATTESTATION_OID.id) == null) return certificate
            leafAlgorithms[KeyIdentifier(alias, uid)] = leaf.publicKey.algorithm
            val hacked = hackLeaf(arrayOf(leaf))
            hacked[0].encoded
        } catch (t: Throwable) {
            Logger.e("Failed to hack user certificate", t)
            certificate
        }
    }

    private fun hackAttestExtension(
        originalRootOfTrust: ASN1Encodable?,
        vector: ASN1EncodableVector,
        originalEncodables: Array<ASN1Encodable>,
    ): Extension {
        val verifiedBootKey = AndroidUtils.bootKey
        var verifiedBootHash: ByteArray? = null

        try {
            if (originalRootOfTrust is ASN1Sequence) {
                verifiedBootHash = CertificateUtils.getByteArrayFromAsn1(originalRootOfTrust.getObjectAt(3))
            }
        } catch (t: Throwable) {
            Logger.e("Failed to get verified boot hash from original, using generated", t)
        }

        if (verifiedBootHash == null) {
            verifiedBootHash = AndroidUtils.getBootHashFromProp()
        }

        val rootOfTrustElements =
            arrayOf(DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, ASN1Enumerated(0), DEROctetString(verifiedBootHash))
        val hackedRootOfTrust = DERSequence(rootOfTrustElements)

        val spoofedTags = setOf(704, 705, 706, 718, 719)
        val rebuilt = mutableListOf<ASN1TaggedObject>()
        for (i in 0 until vector.size()) {
            val obj = vector.get(i)
            if (obj is ASN1TaggedObject && obj.tagNo !in spoofedTags) {
                rebuilt.add(obj)
            }
        }
        rebuilt.add(DERTaggedObject(true, 705, ASN1Integer(AndroidUtils.osVersion.toLong())))
        rebuilt.add(DERTaggedObject(true, 706, ASN1Integer(AndroidUtils.patchLevel.toLong())))
        rebuilt.add(DERTaggedObject(true, 718, ASN1Integer(AndroidUtils.vendorPatchLevelLong.toLong())))
        rebuilt.add(DERTaggedObject(true, 719, ASN1Integer(AndroidUtils.bootPatchLevelLong.toLong())))
        rebuilt.add(DERTaggedObject(704, hackedRootOfTrust))
        rebuilt.sortBy { it.tagNo }

        val rebuiltVector = ASN1EncodableVector()
        rebuilt.forEach { rebuiltVector.add(it) }

        val hackEnforced = DERSequence(rebuiltVector)
        originalEncodables[7] = hackEnforced
        val hackedSequence = DERSequence(originalEncodables)
        val hackedSequenceOctets = DEROctetString(hackedSequence)

        return Extension(ATTESTATION_OID, false, hackedSequenceOctets)
    }
}
