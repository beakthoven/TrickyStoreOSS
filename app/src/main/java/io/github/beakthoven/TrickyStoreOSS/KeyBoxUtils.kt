/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.security.keystore.KeyProperties
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyBox
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.StringReader
import java.util.Collections
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import org.xmlpull.v1.XmlPullParserFactory

object KeyBoxUtils {
    @Volatile private var keyboxSnapshot: Map<String, KeyBox> = emptyMap()

    val keyboxes: Map<String, KeyBox>
        get() = keyboxSnapshot

    fun hasKeyboxes(): Boolean = keyboxSnapshot.isNotEmpty()

    @Synchronized
    fun readFromXml(xmlData: String?, isCurrent: (() -> Boolean)? = null): Boolean {
        if (xmlData == null) {
            if (isCurrent != null && !isCurrent()) return false
            val previous = keyboxSnapshot
            keyboxSnapshot = emptyMap()
            if (isCurrent != null && !isCurrent()) {
                keyboxSnapshot = previous
                return false
            }
            Logger.i("Cleared keybox snapshot")
            return true
        }

        val parsed = runCatching {
            val parser =
                XmlPullParserFactory.newInstance().newPullParser().apply {
                    setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
                    setInput(StringReader(xmlData.trim()))
                }
            val candidate = LinkedHashMap<String, KeyBox>()
            var rootSeen = false
            var rootClosed = false
            var expectedKeyboxCount: Int? = null
            var keyboxBlockCount = 0
            var keyboxOpen = false
            var keyboxKeyCount = 0
            var keyboxAlgorithm: String? = null
            var privateKeyText: String? = null
            var certificateChainOpen = false
            var expectedCertificateCount: Int? = null
            var certificateChainSeen = false
            val certTexts = ArrayList<String>()
            var keyCount = 0

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.START_TAG -> {
                        val name = parser.name
                        if (rootClosed) throw XmlPullParserException("Unexpected content after keybox document")
                        if (!rootSeen) {
                            if (name != "AndroidAttestation" || parser.depth != 1) {
                                throw XmlPullParserException("Invalid keybox document root")
                            }
                            rootSeen = true
                        } else {
                            when (parser.depth) {
                                2 -> {
                                    when (name) {
                                        "NumberOfKeyboxes" -> {
                                            if (expectedKeyboxCount != null) {
                                                throw XmlPullParserException("Duplicate keybox count")
                                            }
                                            expectedKeyboxCount = readElementText(parser).trim().toIntOrNull()
                                                ?.takeIf { it >= 0 }
                                                ?: throw XmlPullParserException("Invalid keybox count")
                                        }
                                        "Keybox" -> {
                                            if (keyboxOpen) throw XmlPullParserException("Nested keybox element")
                                            keyboxOpen = true
                                            keyboxKeyCount = 0
                                            keyboxBlockCount++
                                        }
                                        else -> throw XmlPullParserException("Invalid keybox document element")
                                    }
                                }
                                3 -> {
                                    if (name != "Key" || !keyboxOpen || keyboxAlgorithm != null) {
                                        throw XmlPullParserException("Invalid keybox element")
                                    }
                                    keyboxAlgorithm = parser.getAttributeValue(null, "algorithm")
                                    privateKeyText = null
                                    certificateChainOpen = false
                                    certificateChainSeen = false
                                    expectedCertificateCount = null
                                    certTexts.clear()
                                }
                                4 -> {
                                    if (keyboxAlgorithm == null) throw XmlPullParserException("Unexpected keybox entry")
                                    when (name) {
                                        "PrivateKey" -> {
                                            if (privateKeyText != null) {
                                                throw XmlPullParserException("Duplicate private key element")
                                            }
                                            privateKeyText = readElementText(parser)
                                        }
                                        "CertificateChain" -> {
                                            if (certificateChainSeen) {
                                                throw XmlPullParserException("Duplicate certificate chain")
                                            }
                                            certificateChainOpen = true
                                            certificateChainSeen = true
                                        }
                                        "Certificate" ->
                                            readElementText(parser).takeIf { it.isNotBlank() }?.let(certTexts::add)
                                        else -> throw XmlPullParserException("Unexpected keybox entry")
                                    }
                                }
                                5 -> {
                                    if (!certificateChainOpen || keyboxAlgorithm == null) {
                                        throw XmlPullParserException("Unexpected certificate chain entry")
                                    }
                                    when (name) {
                                        "NumberOfCertificates" -> {
                                            if (expectedCertificateCount != null) {
                                                throw XmlPullParserException("Duplicate certificate count")
                                            }
                                            expectedCertificateCount = readElementText(parser).trim().toIntOrNull()
                                                ?.takeIf { it >= 0 }
                                                ?: throw XmlPullParserException("Invalid certificate count")
                                        }
                                        "Certificate" ->
                                            readElementText(parser).takeIf { it.isNotBlank() }?.let(certTexts::add)
                                        else -> throw XmlPullParserException("Unexpected certificate chain entry")
                                    }
                                }
                                else -> throw XmlPullParserException("Unexpected keybox element")
                            }
                        }
                    }
                    XmlPullParser.TEXT,
                    XmlPullParser.IGNORABLE_WHITESPACE,
                    XmlPullParser.CDSECT -> {
                        if (!parser.text.isNullOrBlank()) {
                            throw XmlPullParserException("Unexpected text outside keybox entry")
                        }
                    }
                    XmlPullParser.END_TAG -> {
                        when (parser.name) {
                            "NumberOfKeyboxes" -> {
                                if (parser.depth != 2 || expectedKeyboxCount == null) {
                                    throw XmlPullParserException("Unexpected keybox count")
                                }
                            }
                            "NumberOfCertificates" -> {
                                if (parser.depth != 5 || expectedCertificateCount == null) {
                                    throw XmlPullParserException("Unexpected certificate count")
                                }
                            }
                            "Certificate" -> {
                                if (
                                    keyboxAlgorithm == null ||
                                        (parser.depth == 4 && certificateChainSeen) ||
                                        (parser.depth == 5 && !certificateChainOpen) ||
                                        parser.depth !in 4..5
                                ) {
                                    throw XmlPullParserException("Unexpected certificate element")
                                }
                            }
                            "PrivateKey" -> {
                                if (parser.depth != 4 || keyboxAlgorithm == null) {
                                    throw XmlPullParserException("Unexpected private key element")
                                }
                            }
                            "CertificateChain" -> {
                                if (
                                    parser.depth != 4 || !certificateChainOpen ||
                                        expectedCertificateCount != null && expectedCertificateCount != certTexts.size
                                ) {
                                    throw XmlPullParserException("Incomplete certificate chain")
                                }
                                certificateChainOpen = false
                            }
                            "Key" -> {
                                if (
                                    parser.depth != 3 || keyboxAlgorithm == null || !keyboxOpen ||
                                        privateKeyText == null || certTexts.isEmpty() || certificateChainOpen
                                ) {
                                    throw XmlPullParserException("Incomplete keybox entry")
                                }
                                val (algorithm, keybox) = storeKeybox(keyboxAlgorithm, privateKeyText, certTexts)
                                candidate[algorithm] = keybox
                                keyboxKeyCount++
                                keyCount++
                                keyboxAlgorithm = null
                                privateKeyText = null
                                certTexts.clear()
                            }
                            "Keybox" -> {
                                if (
                                    parser.depth != 2 || !keyboxOpen || keyboxAlgorithm != null || keyboxKeyCount == 0
                                ) {
                                    throw XmlPullParserException("Incomplete keybox")
                                }
                                keyboxOpen = false
                            }
                            "AndroidAttestation" -> {
                                if (
                                    parser.depth != 1 || !rootSeen || keyboxOpen || keyboxAlgorithm != null ||
                                        expectedKeyboxCount != null && expectedKeyboxCount != keyboxBlockCount
                                ) {
                                    throw XmlPullParserException("Incomplete keybox document")
                                }
                                rootClosed = true
                            }
                            else -> throw XmlPullParserException("Unexpected keybox closing element")
                        }
                    }
                }
                event = parser.next()
            }
            if (
                !rootSeen || !rootClosed || parser.depth != 0 || keyboxOpen || keyboxAlgorithm != null ||
                    keyCount == 0 || expectedKeyboxCount != null && expectedKeyboxCount != keyboxBlockCount
            ) {
                throw XmlPullParserException("Incomplete keybox document")
            }
            Collections.unmodifiableMap(LinkedHashMap(candidate))
        }

        val candidate = parsed.getOrElse {
            Logger.e("Error loading keybox XML; previous snapshot retained (${it::class.java.simpleName})")
            return false
        }
        if (isCurrent != null && !isCurrent()) return false
        val previous = keyboxSnapshot
        keyboxSnapshot = candidate
        if (isCurrent != null && !isCurrent()) {
            keyboxSnapshot = previous
            return false
        }
        Logger.i("Successfully updated ${candidate.size} keyboxes")
        return true
    }

    private fun readElementText(parser: XmlPullParser): String {
        val sb = StringBuilder()
        var depth = 1
        var ev = parser.next()
        while (depth > 0) {
            when (ev) {
                XmlPullParser.START_TAG -> depth++
                XmlPullParser.END_TAG -> depth--
                XmlPullParser.TEXT,
                XmlPullParser.IGNORABLE_WHITESPACE,
                XmlPullParser.CDSECT -> parser.text?.let(sb::append)
                XmlPullParser.END_DOCUMENT ->
                    throw XmlPullParserException("Unexpected EOF while parsing keybox element")
            }
            if (depth > 0) ev = parser.next()
        }
        return sb.toString()
    }

    private fun storeKeybox(
        attrAlgo: String?,
        privateKeyText: String?,
        certTexts: List<String>,
    ): Pair<String, KeyBox> {
        if (privateKeyText.isNullOrBlank() || certTexts.isEmpty()) {
            throw XmlPullParserException("Keybox entry is missing key material")
        }
        val keyPair = CertificateUtils.convertPemToKeyPair(CertificateUtils.parseKeyPair(privateKeyText).getOrThrow())
        val derived = keyPair.private.algorithm
        val algorithmName =
            when (derived.uppercase()) {
                "ECDSA" -> KeyProperties.KEY_ALGORITHM_EC
                KeyProperties.KEY_ALGORITHM_EC -> KeyProperties.KEY_ALGORITHM_EC
                KeyProperties.KEY_ALGORITHM_RSA -> KeyProperties.KEY_ALGORITHM_RSA
                else -> derived
            }
        val attrNormalized =
            when (attrAlgo?.lowercase()) {
                "ecdsa" -> KeyProperties.KEY_ALGORITHM_EC
                "rsa" -> KeyProperties.KEY_ALGORITHM_RSA
                else -> attrAlgo?.uppercase()
            }
        if (attrNormalized != null && !attrNormalized.equals(derived, ignoreCase = true)) {
            Logger.w("Keybox algorithm attribute disagrees with parsed key; using parsed key")
        }
        val certs = certTexts.map { CertificateUtils.parseCertificate(it).getOrThrow() }
        return algorithmName to KeyBox(keyPair, Collections.unmodifiableList(certs))
    }
}
