/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.SystemProperties
import android.security.KeyStore2
import android.security.keystore.KeyStoreManager
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.CachedAttestData
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap

object AndroidUtils {

    const val DO_NOT_REPORT = -1

    val bootKey: ByteArray by lazy {
        getBootKeyFromProp()?.also { Log.d(TAG, "Using boot key from ro.boot.vbmeta.public_key_digest: ${it.toHex()}") }
            ?: CachedAttestData?.verifiedBootKey?.takeIfNonZero()?.also {
                Log.d(TAG, "Using boot key from cached TEE attestation: ${it.toHex()}")
            }
            ?: persistedBootKey().also {
                Log.d(TAG, "Using persisted random boot key (no AVB key available): ${it.toHex()}")
            }
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
                Log.e(TAG, "Failed to persist boot key, using ephemeral random", it)
                randomBytes()
            }
    }

    fun setupBootHash() {
        getBootHashFromProp()?.also { Log.d(TAG, "Using boot hash from system property: ${it.toHex()}") }
            ?: getBootHashFromAttestation()?.also {
                Log.d(TAG, "Using boot hash from attestation: ${it.toHex()}")
                setBootHashProp(it)
            }
            ?: randomBytes().also {
                Log.d(TAG, "Generating random boot hash: ${it.toHex()}")
                setBootHashProp(it)
            }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun getBootHashFromProp(): ByteArray? {
        val digest = SystemProperties.get("ro.boot.vbmeta.digest", null) ?: return null
        Log.d(TAG, "System property ro.boot.vbmeta.digest: $digest")

        if (digest.isBlank()) {
            Log.d(TAG, "Property is blank")
            return null
        }

        return if (digest.length == 64) digest.hexToByteArray() else null
    }

    private fun getBootHashFromAttestation(): ByteArray? {
        return try {
            CachedAttestData?.verifiedBootHash?.takeIfNonZero()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get boot hash from attestation: ${e.message}")
            null
        }
    }

    private fun setBootHashProp(bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            Log.d(TAG, "Setting ro.boot.vbmeta.digest to: $hex")
            SystemProperties.set("ro.boot.vbmeta.digest", hex)
        } catch (e: Exception) {
            Log.e(TAG, "Exception setting vbmeta digest: ${e.message}")
        }
    }

    private fun randomBytes(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    fun patchLevel(uid: Int): Int =
        getCustomPatchLevel(uid, "system", false) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(false)

    fun patchLevelLong(uid: Int): Int =
        getCustomPatchLevel(uid, "system", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    fun vendorPatchLevelLong(uid: Int): Int =
        getCustomPatchLevel(uid, "vendor", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    fun bootPatchLevelLong(uid: Int): Int =
        getCustomPatchLevel(uid, "boot", true) ?: Build.VERSION.SECURITY_PATCH.convertPatchLevel(true)

    // For patching a real keymaster cert: null = device_default (keep the original real value),
    // DO_NOT_REPORT = omit, else = the value to inject. Used by the leaf-hack path so a real,
    // correctly-sourced patch level (e.g. boot from the boot image header) is preserved.
    fun patchLevelOverride(uid: Int): Int? = getCustomPatchLevel(uid, "system", false)

    fun vendorPatchLevelOverride(uid: Int): Int? = getCustomPatchLevel(uid, "vendor", true)

    fun bootPatchLevelOverride(uid: Int): Int? = getCustomPatchLevel(uid, "boot", true)

    private fun getCustomPatchLevel(uid: Int, component: String, isLong: Boolean): Int? {
        val pkg = PkgConfig.packagePatchLevelForUid(uid)
        val global = PkgConfig.globalPatchLevelConfig
        val value =
            when (component) {
                "system" -> pkg?.system ?: pkg?.all ?: global?.system ?: global?.all
                "vendor" -> pkg?.vendor ?: pkg?.all ?: global?.vendor ?: global?.all
                "boot" -> pkg?.boot ?: pkg?.all ?: global?.boot ?: global?.all
                else -> pkg?.all ?: global?.all
            }

        // Unset, or explicit "prop": mirror the system security-patch prop (TrickyStore behavior).
        if (value == null || value.equals("prop", ignoreCase = true))
            return Build.VERSION.SECURITY_PATCH.convertPatchLevel(isLong)

        when {
            value.equals("no", ignoreCase = true) -> return DO_NOT_REPORT
            // device_default: fall back to the device's real per-component value. In the forged
            // path that resolves to the system patch; in the patch path the caller keeps the
            // original keymaster value (null signals "do not touch").
            value.equals("device_default", ignoreCase = true) -> return null
        }

        return parsePatchLevelValue(resolveDateValue(value), component, isLong)
    }

    // ponytail: resolves per-attestation, so date templates stay current without a reload
    private fun resolveDateValue(value: String): String {
        val now = LocalDate.now()
        val y = "%04d".format(now.year)
        val m = "%02d".format(now.monthValue)
        val d = "%02d".format(now.dayOfMonth)
        return value
            .replace("YYYY", y, ignoreCase = true)
            .replace("MM", m, ignoreCase = true)
            .replace("DD", d, ignoreCase = true)
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
                    Log.e(TAG, "Invalid patch level length for $component: $normalized")
                    null
                }
            }
        } catch (e: NumberFormatException) {
            Log.e(TAG, "Patch level parse error for $component=$value", e)
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

    data class AttestationVersions(val attestation: Int, val keymaster: Int)

    private val resolvedVersions = ConcurrentHashMap<Int, AttestationVersions>()

    private fun cachedTeeVersions(securityLevel: Int): AttestationVersions? {
        if (securityLevel != SecurityLevel.TRUSTED_ENVIRONMENT) return null
        val data = CachedAttestData ?: return null
        val attestation = data.attestVersion ?: return null
        val keymaster = data.keymasterVersion ?: return null
        return AttestationVersions(attestation, keymaster)
    }

    private fun keymasterVersionForAttestation(attestationVersion: Int): Int =
        if (attestationVersion == 4) 41 else attestationVersion

    fun attestationVersions(securityLevel: Int): AttestationVersions {
        resolvedVersions[securityLevel]?.let { return it }

        val platformVersions =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                KeyMintVersionResolver.resolve(securityLevel)
            } else {
                null
            }
        val exact = platformVersions ?: cachedTeeVersions(securityLevel)
        if (exact != null) {
            resolvedVersions[securityLevel] = exact
            return exact
        }

        val attestation = attestVersionMap[Build.VERSION.SDK_INT] ?: 500
        return AttestationVersions(attestation, keymasterVersionForAttestation(attestation))
    }

    fun String.convertPatchLevel(isLong: Boolean): Int {
        val raw = runCatching {
            val parts = split("-")
            when {
                isLong && parts.size >= 3 -> parts[0].toInt() * 10000 + parts[1].toInt() * 100 + parts[2].toInt()
                parts.size >= 2 -> parts[0].toInt() * 100 + parts[1].toInt()
                else -> throw IllegalArgumentException("Invalid patch level format: $this")
            }
        }
        return raw.onFailure { Log.e(TAG, "Invalid patch level format: $this", it) }.getOrDefault(202404)
    }

    private val keystore2: KeyStore2 by lazy { KeyStore2.getInstance() }

    fun getSupplementaryAttestationInfo(tag: Int): ByteArray? =
        runCatching { keystore2.getSupplementaryAttestationInfo(tag) }.getOrNull()

    val moduleHash: ByteArray by lazy {
        getSupplementaryAttestationInfo(KeyStoreManager.MODULE_HASH)?.let {
            MessageDigest.getInstance("SHA-256").digest(it)
        } ?: CachedAttestData?.moduleHash ?: ByteArray(32).also { Log.e(TAG, "Failed to source module hash") }
    }
}

fun String.trimLine(): String = trim().split("\n").joinToString("\n") { it.trim() }

@OptIn(ExperimentalStdlibApi::class) fun ByteArray.toHex(): String = toHexString(HexFormat.Default)
