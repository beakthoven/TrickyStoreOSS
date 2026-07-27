/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.security.keystore.KeyProperties
import io.github.beakthoven.TrickyStoreOSS.CertificateGen.KeyBox
import io.github.beakthoven.TrickyStoreOSS.CertificateHack.clearLeafAlgorithms
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.IOException
import java.io.StringReader
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import org.xmlpull.v1.XmlPullParserFactory

class XmlParser(private val xmlContent: String) {

    fun obtainPath(path: String): Result<Map<String, String>> = runCatching {
        val factory = XmlPullParserFactory.newInstance()
        val parser = factory.newPullParser()
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
        parser.setInput(StringReader(xmlContent))

        val tags = path.split(".").toTypedArray()
        readData(parser, tags, 0, mutableMapOf())
    }

    @Throws(IOException::class, XmlPullParserException::class)
    private fun readData(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int,
        tagCounts: MutableMap<String, Int>,
    ): Map<String, String> {
        while (parser.next() != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType != XmlPullParser.START_TAG) {
                continue
            }

            val currentTag = parser.name ?: continue
            val targetTag = tags[index]
            val tagParts = targetTag.split("[")
            val baseTagName = tagParts[0]

            if (currentTag == baseTagName) {
                return if (tagParts.size > 1) {
                    handleIndexedTag(parser, tags, index, tagCounts, currentTag, tagParts[1])
                } else {
                    handleRegularTag(parser, tags, index)
                }
            } else {
                skipCurrentElement(parser)
            }
        }

        throw XmlPullParserException("Path not found: ${tags.joinToString(".")}")
    }

    @Throws(IOException::class, XmlPullParserException::class)
    private fun handleIndexedTag(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int,
        tagCounts: MutableMap<String, Int>,
        currentTag: String,
        indexPart: String,
    ): Map<String, String> {
        val targetIndex =
            indexPart.replace("]", "").toIntOrNull() ?: throw XmlPullParserException("Invalid index in tag: $indexPart")

        val currentCount = tagCounts.getOrDefault(currentTag, 0)

        return if (currentCount < targetIndex) {
            tagCounts[currentTag] = currentCount + 1
            readData(parser, tags, index, tagCounts)
        } else {
            if (index == tags.size - 1) {
                readAttributes(parser)
            } else {
                readData(parser, tags, index + 1, tagCounts)
            }
        }
    }

    @Throws(IOException::class, XmlPullParserException::class)
    private fun handleRegularTag(parser: XmlPullParser, tags: Array<String>, index: Int): Map<String, String> {
        return if (index == tags.size - 1) {
            readAttributes(parser)
        } else {
            readData(parser, tags, index + 1, mutableMapOf())
        }
    }

    @Throws(IOException::class, XmlPullParserException::class)
    private fun readAttributes(parser: XmlPullParser): Map<String, String> {
        val attributes = mutableMapOf<String, String>()

        for (i in 0 until parser.attributeCount) {
            val name = parser.getAttributeName(i)
            val value = parser.getAttributeValue(i)
            if (name != null && value != null) {
                attributes[name] = value
            }
        }

        if (parser.next() == XmlPullParser.TEXT) {
            parser.text?.let { text -> attributes["text"] = text }
        }

        return attributes
    }

    @Throws(XmlPullParserException::class, IOException::class)
    private fun skipCurrentElement(parser: XmlPullParser) {
        if (parser.eventType != XmlPullParser.START_TAG) {
            throw IllegalStateException("Parser must be positioned at START_TAG")
        }

        var depth = 1
        while (depth != 0) {
            when (parser.next()) {
                XmlPullParser.END_TAG -> depth--
                XmlPullParser.START_TAG -> depth++
            }
        }
    }
}

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

        try {
            val xmlParser = XmlParser(xmlData.trim())

            val numberOfKeyboxes =
                xmlParser.obtainPath("AndroidAttestation.NumberOfKeyboxes").getOrThrow()["text"]?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid number of keyboxes")

            repeat(numberOfKeyboxes) { i -> processKeybox(xmlParser, i) }

            Logger.i("Successfully updated $numberOfKeyboxes keyboxes")
        } catch (t: Throwable) {
            Logger.e("Error loading XML file (keyboxes cleared)", t)
        }
    }

    private fun processKeybox(xmlParser: XmlParser, index: Int) {
        try {
            val keyboxAlgorithm =
                xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index]").getOrThrow()["algorithm"]
                    ?: throw IllegalArgumentException("Missing algorithm attribute")

            val privateKeyContent =
                xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index].PrivateKey").getOrThrow()["text"]
                    ?: throw IllegalArgumentException("Missing private key text")

            val numberOfCertificates =
                xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index].CertificateChain.NumberOfCertificates")
                    .getOrThrow()["text"]?.toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid number of certificates")

            val certificateChain = mutableListOf<Certificate>()
            repeat(numberOfCertificates) { j ->
                val certContent =
                    xmlParser.obtainPath("AndroidAttestation.Keybox.Key[$index].CertificateChain.Certificate[$j]")
                        .getOrThrow()["text"] ?: throw IllegalArgumentException("Missing certificate text")

                certificateChain.add(CertificateUtils.parseCertificate(certContent).getOrThrow())
            }

            val pemKeyPair = CertificateUtils.parseKeyPair(privateKeyContent).getOrThrow()

            val keyPair = CertificateUtils.convertPemToKeyPair(pemKeyPair)

            val algorithmName =
                when (keyboxAlgorithm.lowercase()) {
                    "ecdsa" -> KeyProperties.KEY_ALGORITHM_EC
                    "rsa" -> KeyProperties.KEY_ALGORITHM_RSA
                    else -> keyboxAlgorithm
                }

            keyboxes[algorithmName] = KeyBox(keyPair, certificateChain)
        } catch (t: Throwable) {
            Logger.e("Error processing keybox $index", t)
            throw t
        }
    }
}
