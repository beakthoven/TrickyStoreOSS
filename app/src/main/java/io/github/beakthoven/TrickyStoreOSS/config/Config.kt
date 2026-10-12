/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.config

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.os.IInterface
import android.os.ServiceManager
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.ProbeStatus
import io.github.beakthoven.TrickyStoreOSS.AttestUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

object PkgConfig {
    // volatile immutable map; swapped on reload so binder threads read a consistent snapshot
    @Volatile private var packageModes: Map<String, Mode> = emptyMap()

    enum class Mode {
        AUTO,
        LEAF_HACK,
        GENERATE,
    }

    private val packageNameRegex = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")

    private fun updateTargetPackages(f: File?) {
        val raw = runCatching {
            val modes = mutableMapOf<String, Mode>()
            f?.readLines()?.forEach { line ->
                val n = line.substringBefore('#').trim()
                if (n.isEmpty()) return@forEach
                val mode = when {
                    n.endsWith("!") -> Mode.GENERATE
                    n.endsWith("?") -> Mode.LEAF_HACK
                    else -> Mode.AUTO
                }
                val packageName = when (mode) {
                    Mode.GENERATE, Mode.LEAF_HACK -> n.dropLast(1).trim()
                    Mode.AUTO -> n
                }
                if (packageName.endsWith('!') || packageName.endsWith('?') || !packageNameRegex.matches(packageName)) {
                    Logger.w("ignoring invalid target package entry: $n")
                    return@forEach
                }
                modes[packageName] = mode
            }
            packageModes = modes
            SecurityLevelInterceptor.invalidatePatchedResponses()
            Logger.i("update target packages: $modes")
        }
        raw.onFailure { Logger.e("failed to update target files", it) }
    }

    private data class KeyboxFileState(val exists: Boolean, val length: Long, val modified: Long)

    private fun keyboxFileState(file: File): KeyboxFileState =
        KeyboxFileState(file.exists(), file.length(), file.lastModified())

    private fun updateKeyBox(generation: Long? = null) {
        val raw = runCatching {
            val file = File(root, KEYBOX_FILE)
            val before = keyboxFileState(file)
            val contents = if (before.exists) file.readText() else null
            val current = keyboxFileState(file)
            val isCurrent = {
                val unchanged = runCatching {
                    (generation == null || generation == keyboxReloadGeneration.get()) &&
                        keyboxFileState(file) == current &&
                        (!current.exists || file.readText() == contents)
                }.getOrDefault(false)
                if (!unchanged && generation != null) keyboxReloadPending.set(true)
                unchanged
            }
            if (!isCurrent()) {
                if (generation != null) keyboxReloadPending.set(true)
                return@runCatching
            }
            if (KeyBoxUtils.readFromXml(contents, isCurrent)) {
                SecurityLevelInterceptor.invalidatePatchedResponses()
            } else {
                Logger.e("failed to update keybox; previous snapshot retained")
            }
        }
        raw.onFailure { Logger.e("failed to read keybox file") }
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val TEE_STATUS_FILE = "tee_status"
    private const val PATCHLEVEL_FILE = "security_patch.txt"
    private val root = File(CONFIG_PATH)
    private val keyboxReloadExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ts-keybox-reload").apply { isDaemon = true }
    }
    private val keyboxReloadPending = AtomicBoolean(false)
    private val keyboxReloadScheduled = AtomicBoolean(false)
    private val keyboxReloadGeneration = AtomicLong(0)

    private fun scheduleKeyboxReload() {
        keyboxReloadGeneration.incrementAndGet()
        keyboxReloadPending.set(true)
        if (!keyboxReloadScheduled.compareAndSet(false, true)) return
        keyboxReloadExecutor.execute {
            try {
                while (keyboxReloadPending.getAndSet(false)) {
                    val generation = keyboxReloadGeneration.get()
                    updateKeyBox(generation)
                }
            } finally {
                keyboxReloadScheduled.set(false)
                if (keyboxReloadPending.get()) scheduleKeyboxReload()
            }
        }
    }

    @Volatile private var probe: AttestUtils.ProbeResult? = null

    private fun storeTEEStatus(root: File) {
        val result = AttestUtils.probeResult
        probe = result
        val teeBroken = when (result.status) {
            ProbeStatus.AVAILABLE -> false
            ProbeStatus.FAILED -> true
            ProbeStatus.UNAVAILABLE -> null
        }
        val statusFile = File(root, TEE_STATUS_FILE)
        try {
            statusFile.writeText(
                "status=${result.status}\n" +
                    "category=${result.failureCategory ?: "none"}\n" +
                    "serviceErrorCode=${result.serviceErrorCode ?: "none"}\n" +
                    "teeBroken=${teeBroken ?: "unknown"}",
            )
            Logger.i(
                "TEE status written to $statusFile: status=${result.status}, " +
                    "category=${result.failureCategory ?: "none"}, code=${result.serviceErrorCode ?: "none"}",
            )
        } catch (e: Exception) {
            Logger.e("Failed to write TEE status: ${e.message}")
        }
    }

    private fun currentProbe(): AttestUtils.ProbeResult {
        probe?.let { return it }
        storeTEEStatus(root)
        return probe ?: AttestUtils.probeResult.also { probe = it }
    }

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            when (event) {
                CLOSE_WRITE, MOVED_TO, DELETE, MOVED_FROM -> Unit
                else -> return
            }
            when (path) {
                TARGET_FILE -> updateTargetPackages(File(root, path).takeIf { it.exists() })
                KEYBOX_FILE -> scheduleKeyboxReload()
                PATCHLEVEL_FILE -> updatePatchLevel(File(root, path).takeIf { it.exists() })
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) Logger.e("keybox file not found, please put it to $keybox !")
        updateKeyBox()
        val patchFile = File(root, PATCHLEVEL_FILE)
        updatePatchLevel(if (patchFile.exists()) patchFile else null)
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null
    private val packageManagerDeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                (iPm as? IInterface)?.asBinder()?.unlinkToDeath(this, 0)
                iPm = null
            }
        }

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            val binder = waitAndGetSystemService("package") ?: return null
            binder.linkToDeath(packageManagerDeathRecipient, 0)
            iPm = IPackageManager.Stub.asInterface(binder)
        }
        return iPm
    }

    private fun packagesForUid(uid: Int): Array<String>? =
        runCatching { getPm()?.getPackagesForUid(uid) }
            .onFailure { Logger.e("failed to get packages for uid=$uid", it) }
            .getOrNull()

    fun hasPermissionForUid(uid: Int, permission: String): Boolean {
        val userId = uid / 100000
        return packagesForUid(uid)?.any { pkg ->
            runCatching { getPm()?.checkPermission(permission, pkg, userId) == 0 }.getOrDefault(false)
        } ?: false
    }

    private fun checkNeed(callingUid: Int, targetMode: Mode): Boolean {
        val raw = runCatching {
            val ps = packagesForUid(callingUid) ?: return false
            val result = currentProbe()
            val autoMode = when (result.status) {
                ProbeStatus.AVAILABLE -> Mode.LEAF_HACK
                ProbeStatus.FAILED -> Mode.GENERATE
                ProbeStatus.UNAVAILABLE -> null
            }
            ps.any { pkg ->
                when (packageModes[pkg]) {
                    targetMode -> true
                    Mode.AUTO -> autoMode == targetMode
                    null -> false
                    else -> false
                }
            }
        }
        return raw.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false
    }

    fun needHack(callingUid: Int): Boolean = checkNeed(callingUid, Mode.LEAF_HACK)

    fun needGenerate(callingUid: Int): Boolean = checkNeed(callingUid, Mode.GENERATE)

    @Volatile private var globalPatchLevel: CustomPatchLevel? = null

    @Volatile private var packagePatchLevels: Map<String, CustomPatchLevel> = emptyMap()

    val globalPatchLevelConfig: CustomPatchLevel?
        get() = globalPatchLevel

    fun packagePatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = packagesForUid(uid) ?: return null
        return packages.firstNotNullOfOrNull { packagePatchLevels[it] }
    }

    private val patchSectionRegex = Regex("^\\[([A-Za-z0-9_.-]+)]$")

    fun updatePatchLevel(f: File?) {
        val raw = runCatching {
            if (f == null || !f.exists()) {
                globalPatchLevel = null
                packagePatchLevels = emptyMap()
                SecurityLevelInterceptor.invalidatePatchedResponses()
                return@runCatching
            }
            val contexts = LinkedHashMap<String, MutableList<String>>()
            var current = ""
            f.readLines().forEach { line ->
                val trimmed = line.substringBefore('#').trim()
                if (trimmed.isEmpty()) return@forEach
                patchSectionRegex.find(trimmed)?.let { current = it.groupValues[1] }
                    ?: contexts.getOrPut(current) { mutableListOf() }.add(trimmed)
            }
            val parsed = mutableMapOf<String, CustomPatchLevel>()
            for ((ctx, lines) in contexts) parsePatchContext(lines)?.let { parsed[ctx] = it }
            globalPatchLevel = parsed[""]
            packagePatchLevels = parsed.filterKeys { it.isNotEmpty() }
            SecurityLevelInterceptor.invalidatePatchedResponses()
            Logger.i(
                "loaded patch levels: global=${globalPatchLevel != null}, ${packagePatchLevels.size} package overrides"
            )
        }
        raw.onFailure { Logger.e("failed to update patch level", it) }
    }

    private fun parsePatchContext(lines: List<String>): CustomPatchLevel? {
        if (lines.isEmpty()) return null
        if (lines.size == 1 && '=' !in lines[0]) return CustomPatchLevel(all = lines[0])
        val map = mutableMapOf<String, String>()
        for (line in lines) {
            val idx = line.indexOf('=')
            if (idx > 0) {
                map[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
        }
        val all = map["all"]
        return CustomPatchLevel(
            system = map["system"] ?: all,
            vendor = map["vendor"] ?: all,
            boot = map["boot"] ?: all,
            all = all,
        )
    }

    private fun waitAndGetSystemService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return ServiceManager.waitForService(name)
        }

        var tryCount = 0
        while (tryCount++ < 70) {
            val service = ServiceManager.getService(name)
            if (service != null) {
                Logger.d("Got $name service after $tryCount tries")
                return service
            }
            Thread.sleep(500)
        }

        Logger.e("Failed to get $name service")
        return null
    }
}

data class CustomPatchLevel(
    val system: String? = null,
    val vendor: String? = null,
    val boot: String? = null,
    val all: String? = null,
)
