/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder

val ATTESTATION_OID = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

object AttestUtils {
    data class AttestationData(
        val verifiedBootKey: ByteArray?,
        val verifiedBootHash: ByteArray?,
        val attestVersion: Int?,
        val keymasterVersion: Int?,
        val osVersion: Int?,
        val moduleHash: ByteArray?,
    )

    val TEEStatus: Boolean by lazy { isTEEWorking() }
    val CachedAttestData: AttestationData? by lazy { getAttestData() }

    private val keygen_alias = "TrickyStoreOSS_attest"

    private fun isTEEWorking(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                android.app.ActivityThread.initializeMainlineModules()
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                android.security.keystore2.AndroidKeyStoreProvider.install()
            } else {
                android.security.keystore.AndroidKeyStoreProvider.install()
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }

            val parameterSpec =
                KeyGenParameterSpec.Builder(keygen_alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(false)
                    .build()

            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()

            Log.d(TAG, "TEE check: successful")

            // keyStore.deleteEntry(keygen_alias)
            true
        } catch (e: Exception) {
            Log.w(TAG, "TEE check failure: ${e.message}")
            false
        }
    }

    private fun getAttestCert(): X509Certificate? {
        return if (TEEStatus) {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val certChain = keyStore.getCertificateChain(keygen_alias)
            if (certChain == null || certChain.isEmpty()) {
                null
            } else {
                keyStore.deleteEntry(keygen_alias)
                certChain[0] as X509Certificate
            }
        } else {
            null
        }
    }

    private fun getAttestData(): AttestationData? {
        val leaf: X509Certificate = getAttestCert() ?: return null

        return try {
            val leafHolder = X509CertificateHolder(leaf.encoded)
            val ext = leafHolder.getExtension(ATTESTATION_OID)
            if (ext == null) {
                Log.i(TAG, "No attestation extension found on certificate")
                return null
            }

            val keyDescriptionSeq = ASN1Sequence.getInstance(ext.extnValue.octets)
            val encodables = keyDescriptionSeq.toArray()

            val attestVersion = ASN1Integer.getInstance(encodables[0]).value.toInt()
            val keymasterVersion = ASN1Integer.getInstance(encodables[2]).value.toInt()
            var attestVerifiedBootKey: ByteArray? = null
            var attestVerifiedBootHash: ByteArray? = null
            var attestOSVersion: Int? = null
            var attestModuleHash: ByteArray? = null

            val teeEnforced = ASN1Sequence.getInstance(encodables[7])

            teeEnforced.forEach { element ->
                val tagged = element as ASN1TaggedObject
                when (tagged.tagNo) {
                    704 -> { // Parse Root of Trust
                        val rootOfTrustSeq = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                        if (rootOfTrustSeq.size() >= 4) {
                            attestVerifiedBootKey = ASN1OctetString.getInstance(rootOfTrustSeq.getObjectAt(0)).octets
                            attestVerifiedBootHash = ASN1OctetString.getInstance(rootOfTrustSeq.getObjectAt(3)).octets
                        }
                    }
                    705 -> { // Parse OS Version
                        attestOSVersion =
                            ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).value.toInt()
                    }
                }
            }

            val softwareEnforced = encodables.getOrNull(6) as? ASN1Sequence
            softwareEnforced?.forEach { element ->
                val tagged = element as? ASN1TaggedObject ?: return@forEach
                if (tagged.tagNo == 724) {
                    attestModuleHash = ASN1OctetString.getInstance(tagged.baseObject.toASN1Primitive()).octets
                }
            }

            Log.i(TAG, "Extracted attestationVersion: $attestVersion")
            Log.i(TAG, "Extracted keymasterVersion: $keymasterVersion")
            Log.i(TAG, "Extracted verifiedBootKey: ${attestVerifiedBootKey?.toHex() ?: 0}")
            Log.i(TAG, "Extracted verifiedBootHash: ${attestVerifiedBootHash?.toHex() ?: 0}")
            Log.i(TAG, "Extracted osVersion: $attestOSVersion")

            AttestationData(
                verifiedBootKey = attestVerifiedBootKey,
                verifiedBootHash = attestVerifiedBootHash,
                attestVersion = attestVersion,
                keymasterVersion = keymasterVersion,
                osVersion = attestOSVersion,
                moduleHash = attestModuleHash,
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse attestation data", e)
            null
        }
    }
}
