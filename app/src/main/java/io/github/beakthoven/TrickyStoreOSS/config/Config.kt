/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.config

import android.content.pm.IPackageManager
import android.os.FileObserver
import android.os.IBinder
import android.os.IInterface
import android.os.Process
import android.os.ServiceManager
import io.github.beakthoven.TrickyStoreOSS.AttestUtils.TEEStatus
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import java.io.File

object PkgConfig {
    private val hackPackages = mutableSetOf<String>()
    private val generatePackages = mutableSetOf<String>()
    private val packageModes = mutableMapOf<String, Mode>()

    enum class Mode {
        AUTO, LEAF_HACK, GENERATE
    }

    private fun updateTargetPackages(f: File?) = runCatching {
        hackPackages.clear()
        generatePackages.clear()
        packageModes.clear()
        f?.readLines()?.forEach {
            if (it.isNotBlank() && !it.startsWith("#")) {
                val n = it.trim()
                when {
                    n.endsWith("!") -> {
                        val pkg = n.removeSuffix("!").trim()
                        generatePackages.add(pkg)
                        packageModes[pkg] = Mode.GENERATE
                    }
                    n.endsWith("?") -> {
                        val pkg = n.removeSuffix("?").trim()
                        hackPackages.add(pkg)
                        packageModes[pkg] = Mode.LEAF_HACK
                    }
                    else -> {
                        // Auto mode
                        packageModes[n] = Mode.AUTO
                    }
                }
            }
        }
        Logger.i("update hack packages: $hackPackages, generate packages=$generatePackages, packageModes=$packageModes")
    }.onFailure {
        Logger.e("failed to update target files", it)
    }

    private fun updateKeyBox(f: File?) = runCatching {
        KeyBoxUtils.readFromXml(f?.readText())
    }.onFailure {
        Logger.e("failed to update keybox", it)
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val TEE_STATUS_FILE = "tee_status"
    private const val PATCHLEVEL_FILE = "security_patch.txt"
    private val root = File(CONFIG_PATH)

    @Volatile
    private var teeBroken: Boolean? = null

    private fun storeTEEStatus(root: File) {
        val statusFile = File(root, TEE_STATUS_FILE)
        teeBroken = !TEEStatus
        try {
            statusFile.writeText("teeBroken=${teeBroken}")
            Logger.i("TEE status written to $statusFile: teeBroken=$teeBroken") 
        } catch (e: Exception) {
            Logger.e("Failed to write TEE status: ${e.message}")
        }
    }

    private fun loadTEEStatus(root: File) {
        val statusFile = File(root, TEE_STATUS_FILE)
        if (statusFile.exists()) {
            val line = statusFile.readText().trim()
            teeBroken = line == "teeBroken=true"
        } else {
            teeBroken = null
        }
    }

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f = when (event) {
                CLOSE_WRITE, MOVED_TO -> File(root, path)
                DELETE, MOVED_FROM -> null
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
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) {
            Logger.e("keybox file not found, please put it to $keybox !")
        } else {
            updateKeyBox(keybox)
        }
        storeTEEStatus(root)
        val patchFile = File(root, PATCHLEVEL_FILE)
        updatePatchLevel(if (patchFile.exists()) patchFile else null)
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null
    private val packageManagerDeathRecipient = object : IBinder.DeathRecipient {
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

    fun needHack(callingUid: Int): Boolean = kotlin.runCatching {
        val ps = getPm()?.getPackagesForUid(callingUid) ?: return false
        if (teeBroken == null) loadTEEStatus(root)
        for (pkg in ps) {
            when (packageModes[pkg]) {
                Mode.LEAF_HACK -> return true
                Mode.AUTO -> {
                    if (teeBroken == false) return true
                }
                else -> {}
            }
        }
        return false
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun needGenerate(callingUid: Int): Boolean = kotlin.runCatching {
        val ps = getPm()?.getPackagesForUid(callingUid) ?: return false
        if (teeBroken == null) loadTEEStatus(root)
        for (pkg in ps) {
            when (packageModes[pkg]) {
                Mode.GENERATE -> return true
                Mode.AUTO -> {
                    if (teeBroken == true) return true
                }
                else -> {}
            }
        }
        return false
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    private fun getTargetPackages(): Set<String> {
        return (hackPackages + generatePackages + packageModes.keys).toSet()
    }

    fun getTargetPackageUids(): Set<Int> {
        val result = mutableSetOf<Int>()
        val pm = getPm() ?: return emptySet()
        val flags = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) 0L else 0
        val userId = Process.myUid() / 100000

        getTargetPackages().forEach { pkg ->
            kotlin.runCatching {
                val appInfo = pm.getApplicationInfo(pkg, flags, userId)
                if (appInfo != null) {
                    result.add(appInfo.uid)
                    Logger.d("Got UID ${appInfo.uid} for package: $pkg")
                } else {
                    Logger.e("ApplicationInfo is null for package: $pkg")
                }
            }.onFailure {
                Logger.e("Failed to get UID for package: $pkg", it)
            }
        }

        return result
    }

    @Volatile
    var _customPatchLevel: CustomPatchLevel? = null

    fun updatePatchLevel(f: File?) = runCatching {
        if (f == null || !f.exists()) {
            _customPatchLevel = null
            return@runCatching
        }
        val lines = f.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        if (lines.isEmpty()) {
            _customPatchLevel = null
            return@runCatching
        }
        if (lines.size == 1 && !lines[0].contains("=")) {
            _customPatchLevel = CustomPatchLevel(all = lines[0])
            return@runCatching
        }
        val map = mutableMapOf<String, String>()
        for (line in lines) {
            val idx = line.indexOf('=')
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase()
                val value = line.substring(idx + 1).trim()
                map[key] = value
            }
        }
        val all = map["all"]
        _customPatchLevel = CustomPatchLevel(
            system = map["system"] ?: all,
            vendor = map["vendor"] ?: all,
            boot = map["boot"] ?: all,
            all = all
        )
    }.onFailure {
        Logger.e("failed to update patch level", it)
    }

    private fun waitAndGetSystemService(name: String): IBinder? {
        var tryCount = 0

        while (tryCount++ < 70) {
            val service = ServiceManager.getService(name)
            if (service != null) return service
            Logger.e("Package manager is null, waiting for 500ms")
            Thread.sleep(500)
        }

        return null
    }
}

data class CustomPatchLevel(
    val system: String? = null,
    val vendor: String? = null,
    val boot: String? = null,
    val all: String? = null
)
