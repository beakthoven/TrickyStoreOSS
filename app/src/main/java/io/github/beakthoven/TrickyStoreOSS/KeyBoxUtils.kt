/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.security.keystore.KeyProperties
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyBox
import io.github.beakthoven.TrickyStoreOSS.CertificateHack.clearLeafAlgorithms
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.StringReader
import java.util.concurrent.ConcurrentHashMap
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory

object KeyBoxUtils {
    val keyboxes = ConcurrentHashMap<String, KeyBox>()

    fun hasKeyboxes(): Boolean = keyboxes.isNotEmpty()

    fun readFromXml(xmlData: String?) {
        keyboxes.clear()
        clearLeafAlgorithms()

        if (xmlData == null) {
            Logger.i("Clearing all keyboxes")
            return
        }

        val raw = runCatching {
            val parser =
                XmlPullParserFactory.newInstance().newPullParser().apply {
                    setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
                    setInput(StringReader(xmlData.trim()))
                }
            var keyAlgoAttr: String? = null
            var privateKeyText: String? = null
            val certTexts = ArrayList<String>()
            var keyCount = 0

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.START_TAG ->
                        when (parser.name) {
                            "Key" -> {
                                keyAlgoAttr = parser.getAttributeValue(null, "algorithm")
                                privateKeyText = null
                                certTexts.clear()
                            }
                            "PrivateKey" -> privateKeyText = readElementText(parser)
                            "Certificate" -> readElementText(parser).takeIf { it.isNotBlank() }?.let(certTexts::add)
                        }
                    XmlPullParser.END_TAG ->
                        if (parser.name == "Key") {
                            storeKeybox(keyAlgoAttr, privateKeyText, certTexts)
                            keyCount++
                        }
                }
                event = parser.next()
            }
            Logger.i("Successfully updated $keyCount keyboxes")
        }
        raw.onFailure { Logger.e("Error loading XML file (keyboxes cleared)", it) }
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
                XmlPullParser.IGNORABLE_WHITESPACE -> parser.text?.let(sb::append)
            }
            if (depth > 0) ev = parser.next()
        }
        return sb.toString()
    }

    private fun storeKeybox(attrAlgo: String?, privateKeyText: String?, certTexts: List<String>) {
        val pem = privateKeyText
        if (pem.isNullOrBlank()) return
        val raw = runCatching {
            val keyPair = CertificateUtils.convertPemToKeyPair(CertificateUtils.parseKeyPair(pem).getOrThrow())
            val derived = keyPair.private.algorithm
            val algorithmName =
                when (derived.uppercase()) {
                    "ECDSA" -> KeyProperties.KEY_ALGORITHM_EC
                    KeyProperties.KEY_ALGORITHM_EC -> KeyProperties.KEY_ALGORITHM_EC
                    KeyProperties.KEY_ALGORITHM_RSA -> KeyProperties.KEY_ALGORITHM_RSA
                    else -> derived
                }
            // The AOSP schema uses "ecdsa"/"rsa" as attribute values; Java reports "EC"/"RSA".
            val attrNormalized =
                when (attrAlgo?.lowercase()) {
                    "ecdsa" -> KeyProperties.KEY_ALGORITHM_EC
                    "rsa" -> KeyProperties.KEY_ALGORITHM_RSA
                    else -> attrAlgo?.uppercase()
                }
            if (attrNormalized != null && !attrNormalized.equals(derived, ignoreCase = true)) {
                Logger.w(
                    "Keybox algorithm attribute '$attrAlgo' disagrees with parsed key '$derived'; using parsed key"
                )
            }
            val certs = certTexts.map { CertificateUtils.parseCertificate(it).getOrThrow() }
            keyboxes[algorithmName] = KeyBox(keyPair, certs)
        }
        raw.onFailure { Logger.e("Error processing keybox (algorithm=$attrAlgo)", it) }
    }
}
