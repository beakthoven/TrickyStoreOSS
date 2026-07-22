/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.ServiceManager
import android.os.SystemProperties
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.CachedAttestData
import io.github.beakthoven.TrickyStoreOSS.config.CustomPatchLevel
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence

object AndroidUtils {

    const val DO_NOT_REPORT = -1

    val bootKey: ByteArray by lazy {
        getBootKeyFromProp()?.also { Logger.d("Using boot key from ro.boot.vbmeta.public_key_digest: ${it.toHex()}") }
            ?: CachedAttestData?.verifiedBootKey?.takeIfNonZero()?.also {
                Logger.d("Using boot key from cached TEE attestation: ${it.toHex()}")
            }
            ?: persistedBootKey().also { Logger.d("Using persisted random boot key (no AVB key available): ${it.toHex()}") }
    }

    private fun ByteArray.takeIfNonZero(): ByteArray? = takeIf { isNotEmpty() && any { it != 0.toByte() } }

    @OptIn(ExperimentalStdlibApi::class)
    fun getBootKeyFromProp(): ByteArray? {
        val digest = SystemProperties.get("ro.boot.vbmeta.public_key_digest", null) ?: return null
        if (digest.length != 64) return null
        return runCatching { digest.hexToByteArray() }.getOrNull()
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun persistedBootKey(): ByteArray {
        val file = File("/data/adb/tricky_store/boot_key")
        return runCatching {
                if (file.exists()) {
                    file.readText().trim().hexToByteArray()
                } else {
                    file.parentFile?.mkdirs()
                    val key = randomBytes()
                    file.writeText(key.toHex())
                    key
                }
            }
            .getOrElse {
                Logger.e("Failed to persist boot key, using ephemeral random", it)
                randomBytes()
            }
    }

    fun setupBootHash() {
        getBootHashFromProp()?.also { Logger.d("Using boot hash from system property: ${it.toHex()}") }
            ?: getBootHashFromAttestation()?.also {
                Logger.d("Using boot hash from attestation: ${it.toHex()}")
                setBootHashProp(it)
            }
            ?: randomBytes().also {
                Logger.d("Generating random boot hash: ${it.toHex()}")
                setBootHashProp(it)
            }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun getBootHashFromProp(): ByteArray? {
        val digest = SystemProperties.get("ro.boot.vbmeta.digest", null) ?: return null
        Logger.d("System property ro.boot.vbmeta.digest: $digest")

        if (digest.isBlank()) {
            Logger.d("Property is blank")
            return null
        }

        return if (digest.length == 64) digest.hexToByteArray() else null
    }

    private fun getBootHashFromAttestation(): ByteArray? {
        return try {
            CachedAttestData?.verifiedBootHash?.takeIfNonZero()
        } catch (e: Exception) {
            Logger.e("Failed to get boot hash from attestation: ${e.message}")
            null
        }
    }

    private fun setBootHashProp(bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            Logger.d("Setting ro.boot.vbmeta.digest to: $hex")
            SystemProperties.set("ro.boot.vbmeta.digest", hex)
        } catch (e: Exception) {
            Logger.e("Exception setting vbmeta digest: ${e.message}")
        }
    }

    private fun randomBytes(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    val patchLevel: Int
        get() = getCustomPatchLevel("system", false) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(false)

    val patchLevelLong: Int
        get() = getCustomPatchLevel("system", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    val vendorPatchLevelLong: Int
        get() = getCustomPatchLevel("vendor", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    val bootPatchLevelLong: Int
        get() = getCustomPatchLevel("boot", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    private val customPatchLevel: CustomPatchLevel?
        get() = PkgConfig._customPatchLevel

    private fun getCustomPatchLevel(component: String, isLong: Boolean): Int? {
        val config = customPatchLevel ?: return null
        val value =
            when (component) {
                "system" -> config.system ?: config.all
                "vendor" -> config.vendor ?: config.all
                "boot" -> config.boot ?: config.all
                else -> config.all
            } ?: return null

        when {
            value.equals("no", ignoreCase = true) -> return DO_NOT_REPORT
            value.equals("prop", ignoreCase = true) -> return null
        }

        return parsePatchLevelValue(value, component, isLong)
    }

    private fun parsePatchLevelValue(value: String, component: String, isLong: Boolean): Int? {
        val normalized = value.replace("-", "")

        return try {
            when (normalized.length) {
                8 -> {
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    val day = normalized.substring(6, 8).toInt()
                    if (isLong) year * 10000 + month * 100 + day else year * 100 + month
                }
                6 -> {
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    if (isLong) year * 10000 + month * 100 else year * 100 + month
                }
                else -> {
                    Logger.e("Invalid patch level length for $component: $normalized")
                    null
                }
            }
        } catch (e: NumberFormatException) {
            Logger.e("Patch level parse error for $component=$value", e)
            null
        }
    }

    private val osVersionMap =
        mapOf(
            Build.VERSION_CODES.CINNAMON_BUN to 170000,
            Build.VERSION_CODES.BAKLAVA to 160000,
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 150000,
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 140000,
            Build.VERSION_CODES.TIRAMISU to 130000,
            Build.VERSION_CODES.S_V2 to 120100,
            Build.VERSION_CODES.S to 120000,
            Build.VERSION_CODES.R to 110000,
            Build.VERSION_CODES.Q to 100000,
        )

    val osVersion: Int
        get() = CachedAttestData?.osVersion ?: osVersionMap[Build.VERSION.SDK_INT] ?: 170000

    private val attestVersionMap =
        mapOf(
            Build.VERSION_CODES.Q to 4, // Keymaster 4.1
            Build.VERSION_CODES.R to 4, // Keymaster 4.1
            Build.VERSION_CODES.S to 100, // KeyMint 1.0
            Build.VERSION_CODES.S_V2 to 100, // KeyMint 1.0
            Build.VERSION_CODES.TIRAMISU to 200, // KeyMint 2.0
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 300, // KeyMint 3.0
            Build.VERSION_CODES.VANILLA_ICE_CREAM to 300, // KeyMint 3.0
            Build.VERSION_CODES.BAKLAVA to 400, // KeyMint 4.0
            Build.VERSION_CODES.CINNAMON_BUN to 500, // KeyMint 5.0
        )

    val attestVersion: Int
        get() = CachedAttestData?.attestVersion ?: attestVersionMap[Build.VERSION.SDK_INT] ?: 500

    val keymasterVersion: Int
        get() = CachedAttestData?.keymasterVersion ?: if (attestVersion == 4) 41 else attestVersion

    fun String.convertPatchLevel(isLong: Boolean): Int =
        runCatching {
                val parts = split("-")
                when {
                    isLong && parts.size >= 3 -> parts[0].toInt() * 10000 + parts[1].toInt() * 100 + parts[2].toInt()
                    parts.size >= 2 -> parts[0].toInt() * 100 + parts[1].toInt()
                    else -> throw IllegalArgumentException("Invalid patch level format: $this")
                }
            }
            .onFailure { Logger.e("Invalid patch level format: $this", it) }
            .getOrDefault(202404)

    val apexInfos: List<Pair<String, Long>> by lazy {
        runCatching {
                val packageManager = IPackageManager.Stub.asInterface(ServiceManager.getService("package"))
                val packages =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        packageManager.getInstalledPackages(PackageManager.MATCH_APEX.toLong(), 0)
                    } else {
                        @Suppress("DEPRECATION") packageManager.getInstalledPackages(PackageManager.MATCH_APEX, 0)
                    }

                packages.list.map { it.packageName to it.longVersionCode }.sortedBy { it.first }
            }
            .getOrElse {
                Logger.e("Failed to get APEX package information")
                emptyList()
            }
    }

    val moduleHash: ByteArray by lazy {
        runCatching {
                val encodables = apexInfos.flatMap { (packageName, versionCode) ->
                    listOf(DEROctetString(packageName.toByteArray()), ASN1Integer(versionCode))
                }

                val sequence = DERSequence(encodables.toTypedArray())
                MessageDigest.getInstance("SHA-256").digest(sequence.encoded)
            }
            .getOrElse {
                Logger.e("Failed to compute module hash", it)
                ByteArray(32)
            }
    }
}

fun String.trimLine(): String = trim().split("\n").joinToString("\n") { it.trim() }

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
