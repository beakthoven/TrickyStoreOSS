/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyPermission
import android.system.keystore2.ResponseCode
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.createTypedObjectReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.errorReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.successReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.typedReply
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : BaseKeystoreInterceptor() {
    private fun transactCode(name: String, default: Int = -1): Int =
        try {
            getTransactCode(IKeystoreService.Stub::class.java, name)
        } catch (e: Exception) {
            default
        }

    private val getKeyEntryTransaction = transactCode("getKeyEntry")
    private val deleteKeyTransaction = transactCode("deleteKey")
    private val updateSubcomponentTransaction = transactCode("updateSubcomponent")
    private val listEntriesTransaction = transactCode("listEntries")
    private val listEntriesBatchedTransaction = transactCode("listEntriesBatched")
    private val grantTransaction = transactCode("grant")
    private val ungrantTransaction = transactCode("ungrant")
    private val domainGrant: Int =
        try {
            Class.forName("android.system.keystore2.Domain").getField("GRANT").getInt(null)
        } catch (e: Exception) {
            1
        }

    override val interceptedCodes: IntArray by lazy {
        intArrayOf(
            getKeyEntryTransaction,
            deleteKeyTransaction,
            updateSubcomponentTransaction,
            listEntriesTransaction,
            listEntriesBatchedTransaction,
            grantTransaction,
            ungrantTransaction,
        ).filter { it >= 0 }.toIntArray()
    }

    private const val MIN_KEY_DESCRIPTOR_BYTES = 28
    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTrickyStoreOSS.so entry"

    override fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        setupSecurityLevelInterceptors(service, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IBinder, backdoor: IBinder) {
        val ks = IKeystoreService.Stub.asInterface(service)

        val tee = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT) }.getOrNull()
        if (tee != null) {
            Logger.i("Registering for TEE SecurityLevel: $tee")
            val interceptor = SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
            registerBinderInterceptor(backdoor, tee.asBinder(), interceptor)
            interceptor.loadPersistedKeys()
        } else {
            Logger.i("No TEE SecurityLevel found")
        }

        val strongBox = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.STRONGBOX) }.getOrNull()
        if (strongBox != null) {
            Logger.i("Registering for StrongBox SecurityLevel: $strongBox")
            val interceptor = SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX)
            registerBinderInterceptor(backdoor, strongBox.asBinder(), interceptor)
            interceptor.loadPersistedKeys()
        } else {
            Logger.i("No StrongBox SecurityLevel found")
        }
    }

    override fun onPreTransact(target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel): Result {
        if (code == deleteKeyTransaction) {
            val result =
                kotlin
                    .runCatching {
                        data.enforceInterface(IKeystoreService.DESCRIPTOR)
                        if (data.dataAvail() < MIN_KEY_DESCRIPTOR_BYTES) return@runCatching null
                        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                        Logger.d("deleteKey pre-hook: uid=$callingUid alias=${keyDescriptor?.alias} domain=${keyDescriptor?.domain}")
                        if (keyDescriptor != null) {
                            val alias = keyDescriptor.alias
                            if (alias != null) {
                                val key = SecurityLevelInterceptor.Key(callingUid, alias)
                                val isSoftware = SecurityLevelInterceptor.keys.containsKey(key) &&
                                    !SecurityLevelInterceptor.skipLeafHacks.containsKey(key)
                                SecurityLevelInterceptor.cleanupKey(callingUid, alias)
                                Logger.d("deleteKey pre-hook: cleaned up uid=$callingUid alias=$alias")
                                if (isSoftware) return@runCatching successReply()
                            }
                        }
                        null
                    }
                    .onFailure { Logger.e("deleteKey pre-hook parse failed", it) }
                    .getOrNull()
            if (result != null) return result
            return Continue
        }

        if (code == updateSubcomponentTransaction) {
            val result =
                kotlin
                    .runCatching {
                        data.enforceInterface(IKeystoreService.DESCRIPTOR)
                        if (data.dataAvail() < MIN_KEY_DESCRIPTOR_BYTES) return@runCatching null
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching null
                    val publicCert = data.createByteArray()
                    val certificateChain = data.createByteArray()
                    var key = SecurityLevelInterceptor.resolveKey(callingUid, keyDescriptor)
                    if (key == null && keyDescriptor.nspace != 0L) {
                        val grant = SecurityLevelInterceptor.grants[keyDescriptor.nspace]
                        if (grant != null && grant.granteeUid == callingUid) {
                            if (grant.accessVector and KeyPermission.UPDATE == 0)
                                return@runCatching errorReply(ResponseCode.PERMISSION_DENIED, "UPDATE permission not granted")
                            if (SecurityLevelInterceptor.keys.containsKey(grant.key) ||
                                SecurityLevelInterceptor.patchedResponses.containsKey(grant.key)) key = grant.key
                        }
                    }
                    if (key != null && (SecurityLevelInterceptor.keys.containsKey(key) ||
                            SecurityLevelInterceptor.patchedResponses.containsKey(key))) {
                            SecurityLevelInterceptor.updateKeyCertChain(key, publicCert, certificateChain)
                            Logger.i("updateSubcomponent: updated TSOSS cert chain for uid=$callingUid alias=${key.alias}")
                            return@runCatching successReply()
                        }
                        if (key != null) {
                            SecurityLevelInterceptor.patchedResponses.remove(key)
                            SecurityLevelInterceptor.skipLeafHacks.remove(key)
                            Logger.i(
                                "Invalidated cached response for uid=$callingUid alias=${key.alias} after updateSubcomponent"
                            )
                        } else {
                            Logger.i("updateSubcomponent: could not resolve alias for nspace=${keyDescriptor.nspace}")
                        }
                        null
                    }
                    .onFailure { Logger.e("updateSubcomponent pre-hook parse failed", it) }
                    .getOrNull()
            if (result != null) return result
            return Continue
        }

        if (code == grantTransaction && grantTransaction >= 0 && KeyBoxUtils.hasKeyboxes()) {
            return kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    if (data.dataAvail() < MIN_KEY_DESCRIPTOR_BYTES) return@runCatching Skip
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching Skip
                    val granteeUid = data.readInt()
                    val accessVector = data.readInt() // KeyPermission bitmap (GET_INFO=4, USE=256, …)
                    val key = SecurityLevelInterceptor.resolveKey(callingUid, keyDescriptor)
                    if (key != null && (SecurityLevelInterceptor.keys.containsKey(key) ||
                            SecurityLevelInterceptor.patchedResponses.containsKey(key))) {
                        val grantId = java.security.SecureRandom().nextLong()
                        SecurityLevelInterceptor.grants[grantId] =
                            SecurityLevelInterceptor.GrantInfo(callingUid, granteeUid, key, accessVector)
                        val grantDescriptor = KeyDescriptor()
                        grantDescriptor.domain = domainGrant
                        grantDescriptor.nspace = grantId
                        grantDescriptor.alias = null
                        Logger.i(
                            "grant: created TSOSS grant grantId=$grantId for uid=$callingUid alias=${key.alias} granteeUid=$granteeUid"
                        )
                        return@runCatching typedReply(grantDescriptor)
                    }
                    Skip
                }
                .onFailure { Logger.e("grant pre-hook failed uid=$callingUid", it) }
                .getOrNull() ?: Skip
        }

        if (code == ungrantTransaction && ungrantTransaction >= 0) {
            return kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    if (data.dataAvail() < MIN_KEY_DESCRIPTOR_BYTES) return@runCatching Skip
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching Skip
                    val granteeUid = data.readInt()
                    val key = SecurityLevelInterceptor.resolveKey(callingUid, keyDescriptor)
                    if (key != null && (SecurityLevelInterceptor.keys.containsKey(key) ||
                            SecurityLevelInterceptor.patchedResponses.containsKey(key))) {
                        val removed = SecurityLevelInterceptor.grants.entries
                            .removeIf { (_, g) -> g.key == key && g.granteeUid == granteeUid }
                        Logger.d("ungrant: ${if (removed) "removed" else "no"} TSOSS grant for uid=$callingUid alias=${key.alias} granteeUid=$granteeUid")
                        return@runCatching successReply()
                    }
                    Skip
                }
                .onFailure { Logger.e("ungrant pre-hook failed", it) }
                .getOrNull() ?: Skip
        }

        if (code == getKeyEntryTransaction && KeyBoxUtils.hasKeyboxes()) {
            return kotlin
                .runCatching {
                    Logger.d("intercept pre  $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    if (data.dataAvail() < MIN_KEY_DESCRIPTOR_BYTES) {
                        Logger.w("getKeyEntry: parcel too small (${data.dataAvail()}B), forwarding")
                        return@runCatching Skip
                    }
                    val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching Skip
                    val aliasLabel = descriptor.alias ?: "<nspace=${descriptor.nspace}>"
                    if (descriptor.nspace != 0L) {
                        val grant = SecurityLevelInterceptor.grants[descriptor.nspace]
                        if (grant != null && grant.granteeUid == callingUid) {
                            if (grant.accessVector and KeyPermission.GET_INFO == 0) {
                                Logger.i(
                                    "Grant getKeyEntry denied: grantee uid=$callingUid lacks GET_INFO for grantId=${descriptor.nspace} accessVector=${grant.accessVector}"
                                )
                                return@runCatching errorReply(ResponseCode.PERMISSION_DENIED, "GET_INFO permission not granted")
                            }
                            val response = SecurityLevelInterceptor.keys[grant.key]?.response
                                ?: SecurityLevelInterceptor.patchedResponses[grant.key]
                            if (response != null) {
                                Logger.i(
                                    "Serving TSOSS grant key for grantee uid=$callingUid grantId=${descriptor.nspace} ownerUid=${grant.ownerUid} alias=${grant.key.alias}"
                                )
                                return@runCatching safeTypedObjectReply(response, "grant")
                            }
                        }
                    }
                    when {
                        PkgConfig.needGenerate(callingUid) -> {
                            val response = SecurityLevelInterceptor.findGeneratedKey(callingUid, descriptor)?.response
                            if (response != null) {
                                Logger.d("Found generated response for uid=$callingUid alias=$aliasLabel")
                                safeTypedObjectReply(response, "generate")
                            } else {
                                Logger.e("No generated response found for uid=$callingUid alias=$aliasLabel")
                                Skip
                            }
                        }
                        PkgConfig.needHack(callingUid) -> {
                            if (SecurityLevelInterceptor.shouldSkipLeafHackFor(callingUid, descriptor)) {
                                Logger.i("skip leaf hack for uid=$callingUid alias=$aliasLabel")
                                val response = SecurityLevelInterceptor.findGeneratedKey(callingUid, descriptor)?.response
                                if (response != null) {
                                    Logger.d("Found generated response for uid=$callingUid alias=$aliasLabel")
                                    safeTypedObjectReply(response, "skipLeafHack")
                                } else {
                                    Logger.d("No generated response found for uid=$callingUid alias=$aliasLabel")
                                    Continue
                                }
                            } else {
                                val patched = SecurityLevelInterceptor.resolvePatchedResponse(callingUid, descriptor)
                                if (patched != null) {
                                    Logger.i("Serving cached patched response for uid=$callingUid alias=$aliasLabel")
                                    safeTypedObjectReply(patched, "patched")
                                } else {
                                    Logger.d("proceeding with leaf hack for uid=$callingUid alias=$aliasLabel")
                                    Continue
                                }
                            }
                        }
                        else -> Skip
                    }
                }
                .onFailure { Logger.e("getKeyEntry pre-hook failed uid=$callingUid", it) }
                .getOrNull() ?: Skip
        }
        if (
            listEntriesTransaction >= 0 &&
                (code == listEntriesTransaction || code == listEntriesBatchedTransaction) &&
                KeyBoxUtils.hasKeyboxes() &&
                (PkgConfig.needGenerate(callingUid) || PkgConfig.needHack(callingUid))
        ) {
            return Continue
        }
        return Skip
    }

    private fun safeTypedObjectReply(response: KeyEntryResponse, label: String): Result {
        val reply = kotlin.runCatching { createTypedObjectReply(response) }.getOrNull()
        if (reply != null) return reply
        Logger.e("Failed to serialize KeyEntryResponse ($label), falling through to real keystore")
        return Continue
    }

    private fun mergeListEntries(callingUid: Int, code: Int, data: Parcel, reply: Parcel, resultCode: Int): Result =
        kotlin
            .runCatching {
                if (resultCode != 0) return@runCatching Skip
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val domain = data.readInt()
                data.readLong()
                val batched = code == listEntriesBatchedTransaction
                val startPastAlias = if (batched) data.readString() else null
                if (domain != 0) return@runCatching Skip
                if (reply.hasException()) return@runCatching Skip
                val existing = reply.createTypedArray(KeyDescriptor.CREATOR) ?: emptyArray<KeyDescriptor?>()
                val existingAliases = existing.mapNotNull { it?.alias }.toMutableSet()
                val toAdd = ArrayList<KeyDescriptor>()
                for (k in SecurityLevelInterceptor.keys.keys.filter { it.uid == callingUid }) {
                    val alias = k.alias
                    if (batched && startPastAlias != null && alias <= startPastAlias) continue
                    if (alias in existingAliases) continue
                    val kd = KeyDescriptor()
                    kd.domain = 0
                    kd.nspace = callingUid.toLong()
                    kd.alias = alias
                    toAdd.add(kd)
                    existingAliases.add(alias)
                }
                if (toAdd.isEmpty()) return@runCatching Skip
                val merged: Array<KeyDescriptor> = (existing.filterNotNull() + toAdd).sortedBy { it.alias ?: "" }.toTypedArray()
                val p = Parcel.obtain()
                p.writeNoException()
                p.writeTypedArray(merged, 0)
                Logger.i("listEntries${if (batched) "Batched" else ""}: merged ${toAdd.size} TSOSS alias(es) for uid=$callingUid")
                OverrideReply(0, p)
            }
            .onFailure { Logger.e("listEntries merge failed uid=$callingUid", it) }
            .getOrNull() ?: Skip

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): Result {
        if (target != keystore || reply == null) return Skip

        if (
            listEntriesTransaction >= 0 &&
                (code == listEntriesTransaction || code == listEntriesBatchedTransaction) &&
                KeyBoxUtils.hasKeyboxes() &&
                (PkgConfig.needGenerate(callingUid) || PkgConfig.needHack(callingUid))
        ) {
            return mergeListEntries(callingUid, code, data, reply, resultCode)
        }

        if (code == deleteKeyTransaction && resultCode == 0) {
            kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    if (keyDescriptor != null) {
                        val alias = keyDescriptor.alias
                        if (alias != null) {
                            SecurityLevelInterceptor.cleanupKey(callingUid, alias)
                        }
                    }
                }
                .onFailure { Logger.e("deleteKey cleanup failed", it) }
            return Skip
        }

        if (code == updateSubcomponentTransaction && resultCode == 0) {
            kotlin
                .runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    if (keyDescriptor != null) {
                        val alias =
                            keyDescriptor.alias
                                ?: SecurityLevelInterceptor.keysByNspace[keyDescriptor.nspace]?.takeIf { it.uid == callingUid }
                                    ?.alias
                        if (alias != null) {
                            val k = SecurityLevelInterceptor.Key(callingUid, alias)
                            SecurityLevelInterceptor.patchedResponses.remove(k)
                            SecurityLevelInterceptor.skipLeafHacks.remove(k)
                            Logger.i("Invalidated cached response for uid=$callingUid alias=$alias after updateSubcomponent")
                        }
                    }
                }
                .onFailure { Logger.e("updateSubcomponent cleanup failed", it) }
            return Skip
        }

        if (reply.hasException()) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")

        if (code == getKeyEntryTransaction) {
            try {
                data.enforceInterface("android.system.keystore2.IKeystoreService")
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)
                if (response != null) {
                    val cachedKey = response.metadata?.key?.nspace?.takeIf { it != 0L }
                        ?.let { SecurityLevelInterceptor.keysByNspace[it] }
                    val cached = cachedKey?.let { SecurityLevelInterceptor.patchedResponses[it] }
                    if (cached != null) return createTypedObjectReply(cached)
                    val chain = CertificateUtils.run { response.getCertificateChain() }
                    if (chain != null) {
                        val newChain = CertificateHack.hackCertificateChain(chain)
                        response.putCertificateChain(newChain).getOrThrow()
                        response.metadata?.authorizations = CertificateHack.patchAuthorizations(response.metadata?.authorizations)
                        if (cachedKey != null) SecurityLevelInterceptor.patchedResponses[cachedKey] = response
                        Logger.d("Hacked certificate for uid=$callingUid")
                        return createTypedObjectReply(response)
                    } else {
                        p.recycle()
                    }
                } else {
                    p.recycle()
                }
            } catch (t: Throwable) {
                Logger.w(
                    "getKeyEntry post-hook chain patch failed for uid=$callingUid pid=$callingPid; serving unpatched real chain",
                    t,
                )
                p.recycle()
            }
        }
        return Skip
    }
}
