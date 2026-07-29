/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.security.keymaster.KeymasterDefs
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader

object CertificateUtils {
    val certificateFactory: CertificateFactory by lazy {
        try {
            CertificateFactory.getInstance("X.509")
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to initialize certificate factory", t)
            throw RuntimeException("Cannot initialize certificate factory", t)
        }
    }

    fun digestName(digest: Int, hyphenated: Boolean): String {
        val suffix =
            when (digest) {
                KeymasterDefs.KM_DIGEST_SHA1 -> "1"
                KeymasterDefs.KM_DIGEST_SHA_2_224 -> "224"
                KeymasterDefs.KM_DIGEST_SHA_2_256 -> "256"
                KeymasterDefs.KM_DIGEST_SHA_2_384 -> "384"
                KeymasterDefs.KM_DIGEST_SHA_2_512 -> "512"
                else -> "256"
            }
        return if (hyphenated) "SHA-$suffix" else "SHA$suffix"
    }

    fun ByteArray?.toCertificate(): X509Certificate? {
        return this?.let { bytes ->
            try {
                certificateFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
            } catch (e: CertificateException) {
                Log.w(TAG, "Couldn't parse certificate in keystore", e)
                null
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun ByteArray?.toCertificates(): Collection<X509Certificate> {
        return this?.let { bytes ->
            try {
                certificateFactory.generateCertificates(ByteArrayInputStream(bytes)) as Collection<X509Certificate>
            } catch (e: CertificateException) {
                Log.w(TAG, "Couldn't parse certificates in keystore", e)
                emptyList()
            }
        } ?: emptyList()
    }

    fun Collection<Certificate>.toByteArray(): ByteArray? {
        val raw = runCatching {
            ByteArrayOutputStream().use { outputStream ->
                forEach { cert -> outputStream.write(cert.encoded) }
                outputStream.toByteArray()
            }
        }
        return raw.onFailure { Log.w(TAG, "Failed to convert certificates to byte array", it) }.getOrNull()
    }

    fun KeyEntryResponse?.getCertificateChain(): Array<Certificate>? {
        val metadata = this?.metadata ?: return null
        val leafCert = metadata.certificate?.toCertificate() ?: return null

        return when (val chainBytes = metadata.certificateChain) {
            null -> arrayOf(leafCert)
            else -> (listOf<Certificate>(leafCert) + chainBytes.toCertificates()).toTypedArray()
        }
    }

    // Certificate parsing utilities
    fun parseKeyPair(keyContent: String): Result<PEMKeyPair> = runCatching {
        PEMParser(StringReader(keyContent.trimLine())).use { parser ->
            (parser.readObject() as? PEMKeyPair) ?: throw IllegalStateException("Invalid PEM key pair format")
        }
    }

    fun parseCertificate(certContent: String): Result<Certificate> = runCatching {
        PemReader(StringReader(certContent.trimLine())).use { reader ->
            val pemObject = reader.readPemObject()
            certificateFactory.generateCertificate(ByteArrayInputStream(pemObject.content))
        }
    }

    fun convertPemToKeyPair(pemKeyPair: PEMKeyPair): KeyPair {
        return JcaPEMKeyConverter().getKeyPair(pemKeyPair)
    }

    @Throws(CertificateParsingException::class)
    fun getByteArrayFromAsn1(asn1Encodable: ASN1Encodable): ByteArray {
        return when (asn1Encodable) {
            is DEROctetString -> asn1Encodable.octets
            else -> throw CertificateParsingException("Expected DEROctetString, got ${asn1Encodable::class.simpleName}")
        }
    }
}

fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching {
        if (chain.isEmpty()) return@runCatching

        certificate = chain[0].encoded

        if (chain.size > 1) {
            ByteArrayOutputStream().use { output ->
                for (i in 1 until chain.size) {
                    output.write(chain[i].encoded)
                }
                certificateChain = output.toByteArray()
            }
        } else {
            certificateChain = null
        }
    }
}

fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching { metadata.putCertificateChain(chain).getOrThrow() }
}
