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
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.TEEStatus
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.interceptors.SecurityLevelInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.TAG
import java.io.File
import java.util.concurrent.ConcurrentHashMap

object PkgConfig {
    // volatile immutable map; swapped on reload so binder threads read a consistent snapshot
    @Volatile private var packageModes: Map<String, Mode> = emptyMap()

    // UID-package set cache
    private val uidPackages = ConcurrentHashMap<Int, Array<String>>()

    enum class Mode {
        AUTO,
        LEAF_HACK,
        GENERATE,
    }

    private fun updateTargetPackages(f: File?) {
        val raw = runCatching {
            val modes = mutableMapOf<String, Mode>()
            f?.readLines()?.forEach {
                if (it.isNotBlank() && !it.startsWith("#")) {
                    val n = it.trim()
                    when {
                        n.endsWith("!") -> modes[n.removeSuffix("!").trim()] = Mode.GENERATE
                        n.endsWith("?") -> modes[n.removeSuffix("?").trim()] = Mode.LEAF_HACK
                        else -> modes[n] = Mode.AUTO
                    }
                }
            }
            packageModes = modes
            Log.i(TAG, "update target packages: $modes")
        }
        raw.onFailure { Log.e(TAG, "failed to update target files", it) }
    }

    private fun updateKeyBox(f: File?) {
        val raw = runCatching {
            KeyBoxUtils.readFromXml(f?.readText())
            SecurityLevelInterceptor.cleanupAll()
        }
        raw.onFailure { Log.e(TAG, "failed to update keybox", it) }
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val TEE_STATUS_FILE = "tee_status"
    private const val PATCHLEVEL_FILE = "security_patch.txt"
    private val root = File(CONFIG_PATH)

    @Volatile private var teeBroken: Boolean? = null

    private fun storeTEEStatus(root: File) {
        val statusFile = File(root, TEE_STATUS_FILE)
        teeBroken = !TEEStatus
        try {
            statusFile.writeText("teeBroken=${teeBroken}")
            Log.i(TAG, "TEE status written to $statusFile: teeBroken=$teeBroken")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write TEE status: ${e.message}")
        }
    }

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f =
                when (event) {
                    CLOSE_WRITE,
                    MOVED_TO -> File(root, path)
                    DELETE,
                    MOVED_FROM -> null
                    else -> return
                }
            when (path) {
                TARGET_FILE -> updateTargetPackages(f)
                KEYBOX_FILE -> updateKeyBox(f)
                PATCHLEVEL_FILE -> updatePatchLevel(f)
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Log.e(TAG, "target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) {
            Log.e(TAG, "keybox file not found, please put it to $keybox !")
        } else {
            updateKeyBox(keybox)
        }
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
                uidPackages.clear()
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

    fun hasPermissionForUid(uid: Int, permission: String): Boolean {
        val userId = uid / 100000
        return (uidPackages.getOrPut(uid) { getPm()?.getPackagesForUid(uid) ?: return false }).any { pkg ->
            runCatching { getPm()?.checkPermission(permission, pkg, userId) == 0 }.getOrDefault(false)
        }
    }

    private fun checkNeed(callingUid: Int, targetMode: Mode, autoPredicate: Boolean): Boolean {
        val raw = runCatching {
            val ps =
                uidPackages.getOrPut(callingUid) {
                    // PM gone: don't cache, so the next call retries
                    getPm()?.getPackagesForUid(callingUid) ?: return false
                }
            if (teeBroken == null) storeTEEStatus(root)
            for (pkg in ps) {
                when (packageModes[pkg]) {
                    targetMode -> return true
                    Mode.AUTO -> if (autoPredicate) return true
                    else -> {}
                }
            }
            return false
        }
        return raw.onFailure { Log.e(TAG, "failed to get packages", it) }.getOrNull() ?: false
    }

    fun needHack(callingUid: Int): Boolean = checkNeed(callingUid, Mode.LEAF_HACK, teeBroken == false)

    fun needGenerate(callingUid: Int): Boolean = checkNeed(callingUid, Mode.GENERATE, teeBroken == true)

    @Volatile private var globalPatchLevel: CustomPatchLevel? = null

    @Volatile private var packagePatchLevels: Map<String, CustomPatchLevel> = emptyMap()

    val globalPatchLevelConfig: CustomPatchLevel?
        get() = globalPatchLevel

    fun packagePatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = uidPackages.getOrPut(uid) { getPm()?.getPackagesForUid(uid) ?: return null }
        return packages.firstNotNullOfOrNull { packagePatchLevels[it] }
    }

    private val patchSectionRegex = Regex("^\\[([A-Za-z0-9_.-]+)]$")

    fun updatePatchLevel(f: File?) {
        val raw = runCatching {
            if (f == null || !f.exists()) {
                globalPatchLevel = null
                packagePatchLevels = emptyMap()
                return@runCatching
            }
            val contexts = LinkedHashMap<String, MutableList<String>>()
            var current = ""
            f.readLines().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                patchSectionRegex.find(trimmed)?.let { current = it.groupValues[1] }
                    ?: contexts.getOrPut(current) { mutableListOf() }.add(trimmed)
            }
            val parsed = mutableMapOf<String, CustomPatchLevel>()
            for ((ctx, lines) in contexts) parsePatchContext(lines)?.let { parsed[ctx] = it }
            globalPatchLevel = parsed[""]
            packagePatchLevels = parsed.filterKeys { it.isNotEmpty() }
            Log.i(
                TAG,
                "loaded patch levels: global=${globalPatchLevel != null}, ${packagePatchLevels.size} package overrides",
            )
        }
        raw.onFailure { Log.e(TAG, "failed to update patch level", it) }
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
                Log.d(TAG, "Got $name service after $tryCount tries")
                return service
            }
            Thread.sleep(500)
        }

        Log.e(TAG, "Failed to get $name service")
        return null
    }
}

data class CustomPatchLevel(
    val system: String? = null,
    val vendor: String? = null,
    val boot: String? = null,
    val all: String? = null,
)
