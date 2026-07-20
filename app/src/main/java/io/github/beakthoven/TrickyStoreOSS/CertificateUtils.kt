/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import android.util.Log
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate

object CertificateUtils {
    private const val TAG = "TrickyStoreOSS"

    sealed class ParseResult<out T> {
        data class Success<T>(val data: T) : ParseResult<T>()
        data class Error(val message: String, val cause: Throwable? = null) : ParseResult<Nothing>()
    }
    
    fun ByteArray?.toCertificate(): X509Certificate? {
        return this?.let { bytes ->
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
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
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificates(ByteArrayInputStream(bytes)) as Collection<X509Certificate>
            } catch (e: CertificateException) {
                Log.w(TAG, "Couldn't parse certificates in keystore", e)
                emptyList()
            }
        } ?: emptyList()
    }
    
    fun Collection<Certificate>.toByteArray(): ByteArray? = runCatching {
        ByteArrayOutputStream().use { outputStream ->
            forEach { cert -> outputStream.write(cert.encoded) }
            outputStream.toByteArray()
        }
    }.onFailure { 
        Log.w(TAG, "Failed to convert certificates to byte array", it) 
    }.getOrNull()
    
    fun Collection<Certificate>.toByteArrayList(): List<ByteArray>? = runCatching {
        map { it.encoded }
    }.onFailure { 
        Log.w(TAG, "Failed to convert certificates to byte array list", it) 
    }.getOrNull()
    
    fun KeyEntryResponse?.getCertificateChain(): Array<Certificate>? {
        val metadata = this?.metadata ?: return null
        val leafCert = metadata.certificate?.toCertificate() ?: return null
        
        return when (val chainBytes = metadata.certificateChain) {
            null -> arrayOf(leafCert)
            else -> {
                val additionalCerts = chainBytes.toCertificates()
                buildList {
                    add(leafCert)
                    addAll(additionalCerts)
                }.toTypedArray()
            }
        }
    }
    
    // Certificate parsing utilities
    fun parseKeyPair(keyContent: String): ParseResult<PEMKeyPair> {
        return try {
            PEMParser(StringReader(keyContent.trimLine())).use { parser ->
                val pemObject = parser.readObject()
                if (pemObject is PEMKeyPair) {
                    ParseResult.Success(pemObject)
                } else {
                    ParseResult.Error("Invalid PEM key pair format")
                }
            }
        } catch (t: Throwable) {
            ParseResult.Error("Failed to parse PEM key pair", t)
        }
    }
    
    fun parseCertificate(certContent: String): ParseResult<Certificate> {
        return try {
            PemReader(StringReader(certContent.trimLine())).use { reader ->
                val pemObject = reader.readPemObject()
                val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
                    ByteArrayInputStream(pemObject.content)
                )
                ParseResult.Success(certificate)
            }
        } catch (t: Throwable) {
            ParseResult.Error("Failed to parse certificate", t)
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
    return runCatching {
        metadata.putCertificateChain(chain).getOrThrow()
    }
}