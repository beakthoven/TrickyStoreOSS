// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <android/binder.h>
#include <binder/Binder.h>
#include <binder/Common.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <sys/ioctl.h>
#include <utils/StrongPointer.h>

#include <algorithm>
#include <map>
#include <memory>
#include <queue>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "logging.hpp"

extern "C" {
#include <plti.h>
}

using namespace android;

namespace {
namespace intercept_constants {
constexpr uint32_t kRegisterInterceptor = 1;

constexpr uint32_t kPreTransact = 1;
constexpr uint32_t kPostTransact = 2;

constexpr uint32_t kActionSkip = 1;
constexpr uint32_t kActionContinue = 2;
constexpr uint32_t kActionOverrideReply = 3;
constexpr uint32_t kActionOverrideData = 4;

constexpr uint32_t kBackdoorCode = 0xdeadbeef;

// AIDL user codes stay under this; system protocol codes (PING/INTERFACE/DUMP/...) sit above
constexpr uint32_t kMaxUserTransactionCode = 0x00ffffff;
} // namespace intercept_constants
} // namespace

class BinderInterceptor : public BBinder {
    struct InterceptorRegistration {
        wp<IBinder> target_binder{};
        sp<IBinder> interceptor_binder;
        std::vector<uint32_t> codes;

        InterceptorRegistration() = default;
        InterceptorRegistration(wp<IBinder> target, sp<IBinder> interceptor)
            : target_binder(std::move(target)), interceptor_binder(std::move(interceptor)) {}
    };
    using RwLock = std::shared_mutex;
    using WriteGuard = std::unique_lock<RwLock>;
    using ReadGuard = std::shared_lock<RwLock>;

    mutable RwLock interceptor_registry_lock_;
    std::map<wp<IBinder>, InterceptorRegistration> interceptor_registry_{};

public:
    status_t onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) override;

    bool handleInterceptedTransaction(sp<BBinder> target_binder, uint32_t transaction_code, const Parcel &request_data,
                                      Parcel *reply_data, uint32_t transaction_flags, status_t &result);

    bool shouldInterceptTransaction(const wp<BBinder> &target_binder, uint32_t code) const;

private:
    status_t handleRegisterInterceptor(const android::Parcel &data);

    template <typename ParcelWriter>
    status_t writeInterceptorCallData(ParcelWriter &writer, sp<BBinder> target_binder, uint32_t transaction_code,
                                      uint32_t transaction_flags, const Parcel &data) const;

    status_t validateInterceptorResponse(const Parcel &response, int32_t &action_type) const;
};

static sp<BinderInterceptor> g_binder_interceptor = nullptr;

struct ThreadTransactionInfo {
    uint32_t transaction_code;
    wp<BBinder> target_binder;

    ThreadTransactionInfo() = default;
    ThreadTransactionInfo(uint32_t code, wp<BBinder> target) : transaction_code(code), target_binder(std::move(target)) {}
};

thread_local std::queue<ThreadTransactionInfo> g_thread_transaction_queue;

class BinderStub : public BBinder {
    status_t onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) override {
        LOGD("BinderStub transaction: %u", code);

        if (g_thread_transaction_queue.empty()) {
            LOGW("No pending transaction info for stub");
            return UNKNOWN_TRANSACTION;
        }

        auto transaction_info = g_thread_transaction_queue.front();
        g_thread_transaction_queue.pop();

        if (transaction_info.target_binder == nullptr && transaction_info.transaction_code == intercept_constants::kBackdoorCode &&
            reply != nullptr) {
            LOGD("Backdoor access requested - providing interceptor reference");
            reply->writeStrongBinder(g_binder_interceptor);
            return OK;
        }

        if (auto promoted_target = transaction_info.target_binder.promote()) {
            LOGD("Processing intercepted transaction");
            status_t result;
            if (!g_binder_interceptor->handleInterceptedTransaction(promoted_target, transaction_info.transaction_code, data, reply,
                                                                    flags, result)) {
                LOGD("Forwarding to original binder");
                result = promoted_target->transact(transaction_info.transaction_code, data, reply, flags);
            }
            return result;
        } else {
            LOGE("Failed to promote weak reference to target binder");
            return DEAD_OBJECT;
        }
    }
};

static sp<BinderStub> g_binder_stub = nullptr;

int (*original_ioctl_function)(int fd, int request, ...) = nullptr;

namespace {
bool processBinderTransaction(binder_transaction_data *transaction_data) {
    if (!transaction_data || transaction_data->target.ptr == 0) {
        return false;
    }

    bool should_intercept = false;
    ThreadTransactionInfo transaction_info{};

    if (transaction_data->code == intercept_constants::kBackdoorCode && transaction_data->sender_euid == 0) {
        transaction_info.transaction_code = intercept_constants::kBackdoorCode;
        transaction_info.target_binder = nullptr;
        should_intercept = true;
        LOGD("Backdoor transaction detected from root user");
    } else if (transaction_data->code > intercept_constants::kMaxUserTransactionCode) {
        // system protocol code (PING/INTERFACE/DUMP/...): skip the registry lookup
        return false;
    } else {
        auto *weak_ref = reinterpret_cast<RefBase::weakref_type *>(transaction_data->target.ptr);
        if (weak_ref->attemptIncStrong(nullptr)) {
            auto *target_binder = reinterpret_cast<BBinder *>(transaction_data->cookie);
            auto weak_binder = wp<BBinder>::fromExisting(target_binder);

            if (g_binder_interceptor->shouldInterceptTransaction(weak_binder, transaction_data->code)) {
                transaction_info.transaction_code = transaction_data->code;
                transaction_info.target_binder = weak_binder;
                should_intercept = true;
                LOGD("Interception required for transaction code=%u target=%p", transaction_data->code, target_binder);
            }
            target_binder->decStrong(nullptr);
        }
    }

    if (should_intercept) {
        LOGD("Redirecting transaction through stub");
        transaction_data->target.ptr = reinterpret_cast<uintptr_t>(g_binder_stub->getWeakRefs());
        transaction_data->cookie = reinterpret_cast<uintptr_t>(g_binder_stub.get());
        transaction_data->code = intercept_constants::kBackdoorCode;
        g_thread_transaction_queue.push(std::move(transaction_info));
    }

    return should_intercept;
}

void processBinderWriteRead(const binder_write_read &write_read_data) {
    if (write_read_data.read_buffer == 0 || write_read_data.read_size == 0 || write_read_data.read_consumed <= sizeof(uint32_t)) {
        return;
    }

    LOGD("Processing binder read buffer: ptr=%p size=%zu consumed=%zu", reinterpret_cast<void *>(write_read_data.read_buffer),
         write_read_data.read_size, write_read_data.read_consumed);

    auto buffer_ptr = write_read_data.read_buffer;
    auto remaining_bytes = write_read_data.read_consumed;

    // bail early on a lone non-transaction command; multi-command buffers may still hold a txn
    {
        auto first_cmd = *reinterpret_cast<const uint32_t *>(buffer_ptr);
        if (first_cmd != BR_TRANSACTION && first_cmd != BR_TRANSACTION_SEC_CTX) {
            if (remaining_bytes == sizeof(uint32_t) + _IOC_SIZE(first_cmd)) {
                return;
            }
        }
    }

    while (remaining_bytes > 0) {
        if (remaining_bytes < sizeof(uint32_t)) {
            LOGE("Insufficient bytes for command header: %llu", static_cast<unsigned long long>(remaining_bytes));
            break;
        }

        auto command = *reinterpret_cast<const uint32_t *>(buffer_ptr);
        buffer_ptr += sizeof(uint32_t);
        remaining_bytes -= sizeof(uint32_t);

        auto command_size = _IOC_SIZE(command);
        LOGD("Processing binder command: %u (size: %u)", command, command_size);

        if (remaining_bytes < command_size) {
            LOGE("Insufficient bytes for command data: %llu < %u", static_cast<unsigned long long>(remaining_bytes), command_size);
            break;
        }

        if (command == BR_TRANSACTION_SEC_CTX || command == BR_TRANSACTION) {
            binder_transaction_data *transaction_data = nullptr;

            if (command == BR_TRANSACTION_SEC_CTX) {
                LOGD("Processing BR_TRANSACTION_SEC_CTX");
                auto *secctx_data = reinterpret_cast<const binder_transaction_data_secctx *>(buffer_ptr);
                transaction_data = const_cast<binder_transaction_data *>(&secctx_data->transaction_data);
            } else {
                LOGD("Processing BR_TRANSACTION");
                transaction_data = reinterpret_cast<binder_transaction_data *>(buffer_ptr);
            }

            if (transaction_data) {
                processBinderTransaction(transaction_data);
            } else {
                LOGE("Failed to extract transaction data");
            }
        }

        buffer_ptr += command_size;
        remaining_bytes -= command_size;
    }
}
} // namespace

int intercepted_ioctl_function(int fd, int request, ...) {
    va_list args;
    va_start(args, request);
    auto *argument = va_arg(args, void *);
    va_end(args);

    auto result = original_ioctl_function(fd, request, argument);

    if (result >= 0 && request == BINDER_WRITE_READ && argument) {
        const auto &write_read_data = *static_cast<const binder_write_read *>(argument);
        processBinderWriteRead(write_read_data);
    }

    return result;
}

bool BinderInterceptor::shouldInterceptTransaction(const wp<BBinder> &target_binder, uint32_t code) const {
    ReadGuard guard{interceptor_registry_lock_};
    auto it = interceptor_registry_.find(target_binder);
    if (it == interceptor_registry_.end()) return false;
    const auto &codes = it->second.codes;
    return codes.empty() || std::find(codes.begin(), codes.end(), code) != codes.end();
}

status_t BinderInterceptor::onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) {
    switch (code) {
    case intercept_constants::kRegisterInterceptor:
        return handleRegisterInterceptor(data);
    default:
        return UNKNOWN_TRANSACTION;
    }
}

status_t BinderInterceptor::handleRegisterInterceptor(const android::Parcel &data) {
    sp<IBinder> target_binder, interceptor_binder;

    if (data.readStrongBinder(&target_binder) != OK) {
        LOGE("Failed to read target binder from registration data");
        return BAD_VALUE;
    }

    if (!target_binder->localBinder()) {
        LOGE("Target binder is not a local binder");
        return BAD_VALUE;
    }

    if (data.readStrongBinder(&interceptor_binder) != OK) {
        LOGE("Failed to read interceptor binder from registration data");
        return BAD_VALUE;
    }

    int32_t count = 0;
    if (data.readInt32(&count) != OK) {
        LOGE("Failed to read transaction-code allow-list count");
        return BAD_VALUE;
    }
    if (count < 0) count = 0;
    std::vector<uint32_t> codes;
    codes.reserve(static_cast<size_t>(count));
    for (int32_t i = 0; i < count; ++i) {
        uint32_t c = 0;
        if (data.readUint32(&c) != OK) {
            LOGE("Failed to read transaction code #%d from registration data", i);
            return BAD_VALUE;
        }
        codes.push_back(c);
    }

    {
        WriteGuard write_guard{interceptor_registry_lock_};
        wp<IBinder> weak_target = target_binder;

        auto iterator = interceptor_registry_.lower_bound(weak_target);
        if (iterator == interceptor_registry_.end() || iterator->first != weak_target) {
            iterator =
                interceptor_registry_.emplace_hint(iterator, weak_target, InterceptorRegistration{weak_target, interceptor_binder});
        } else {
            iterator->second.interceptor_binder = interceptor_binder;
        }
        iterator->second.codes = std::move(codes);

        LOGI("Registered interceptor for binder %p (%zu codes)", target_binder.get(), iterator->second.codes.size());
        return OK;
    }
}

bool BinderInterceptor::handleInterceptedTransaction(sp<BBinder> target_binder, uint32_t transaction_code, const Parcel &request_data,
                                                     Parcel *reply_data, uint32_t transaction_flags, status_t &result) {
#define VALIDATE_STATUS(expr)                                   \
    do {                                                        \
        auto __result = (expr);                                 \
        if (__result != OK) {                                   \
            LOGE("Operation failed: " #expr " = %d", __result); \
            return false;                                       \
        }                                                       \
    } while (0)

    sp<IBinder> interceptor_binder;
    {
        ReadGuard read_guard{interceptor_registry_lock_};
        auto iterator = interceptor_registry_.find(target_binder);
        if (iterator == interceptor_registry_.end()) {
            LOGE("No interceptor found for target binder %p", target_binder.get());
            return false;
        }
        interceptor_binder = iterator->second.interceptor_binder;
    }

    LOGD("Intercepting transaction: binder=%p code=%u flags=%u reply=%s", target_binder.get(), transaction_code, transaction_flags,
         reply_data ? "true" : "false");

    Parcel pre_request_data, pre_response_data, modified_request_data;

    VALIDATE_STATUS(writeInterceptorCallData(pre_request_data, target_binder, transaction_code, transaction_flags, request_data));
    VALIDATE_STATUS(interceptor_binder->transact(intercept_constants::kPreTransact, pre_request_data, &pre_response_data));

    int32_t pre_action_type;
    VALIDATE_STATUS(validateInterceptorResponse(pre_response_data, pre_action_type));

    LOGD("Pre-transaction action type: %d", pre_action_type);

    switch (pre_action_type) {
    case intercept_constants::kActionSkip:
        return false;

    case intercept_constants::kActionOverrideReply:
        result = pre_response_data.readInt32();
        if (reply_data) {
            size_t reply_size = pre_response_data.readUint64();
            VALIDATE_STATUS(reply_data->appendFrom(&pre_response_data, pre_response_data.dataPosition(), reply_size));
        }
        return true;

    case intercept_constants::kActionOverrideData: {
        size_t data_size = pre_response_data.readUint64();
        VALIDATE_STATUS(modified_request_data.appendFrom(&pre_response_data, pre_response_data.dataPosition(), data_size));
        break;
    }

    case intercept_constants::kActionContinue:
    default:
        VALIDATE_STATUS(modified_request_data.appendFrom(&request_data, 0, request_data.dataSize()));
        break;
    }

    result = target_binder->transact(transaction_code, modified_request_data, reply_data, transaction_flags);

    Parcel post_request_data, post_response_data;

    VALIDATE_STATUS(post_request_data.writeStrongBinder(target_binder));
    VALIDATE_STATUS(post_request_data.writeUint32(transaction_code));
    VALIDATE_STATUS(post_request_data.writeUint32(transaction_flags));
    VALIDATE_STATUS(post_request_data.writeInt32(IPCThreadState::self()->getCallingUid()));
    VALIDATE_STATUS(post_request_data.writeInt32(IPCThreadState::self()->getCallingPid()));
    VALIDATE_STATUS(post_request_data.writeInt32(result));
    VALIDATE_STATUS(post_request_data.writeUint64(request_data.dataSize()));
    VALIDATE_STATUS(post_request_data.appendFrom(&request_data, 0, request_data.dataSize()));

    size_t reply_size = reply_data ? reply_data->dataSize() : 0;
    VALIDATE_STATUS(post_request_data.writeUint64(reply_size));
    LOGD("Transaction sizes: request=%zu reply=%zu", request_data.dataSize(), reply_size);

    if (reply_data && reply_size > 0) {
        VALIDATE_STATUS(post_request_data.appendFrom(reply_data, 0, reply_size));
    }

    VALIDATE_STATUS(interceptor_binder->transact(intercept_constants::kPostTransact, post_request_data, &post_response_data));

    int32_t post_action_type;
    VALIDATE_STATUS(validateInterceptorResponse(post_response_data, post_action_type));

    LOGD("Post-transaction action type: %d", post_action_type);

    if (post_action_type == intercept_constants::kActionOverrideReply) {
        result = post_response_data.readInt32();
        if (reply_data) {
            size_t new_reply_size = post_response_data.readUint64();
            reply_data->freeData();
            VALIDATE_STATUS(reply_data->appendFrom(&post_response_data, post_response_data.dataPosition(), new_reply_size));
            LOGD("Reply overridden: original_size=%zu new_size=%zu", reply_size, new_reply_size);
        }
    }

    return true;

#undef VALIDATE_STATUS
}

template <typename ParcelWriter>
status_t BinderInterceptor::writeInterceptorCallData(ParcelWriter &writer, sp<BBinder> target_binder, uint32_t transaction_code,
                                                     uint32_t transaction_flags, const Parcel &data) const {
    auto status = writer.writeStrongBinder(target_binder);
    if (status != OK)
        return status;

    status = writer.writeUint32(transaction_code);
    if (status != OK)
        return status;

    status = writer.writeUint32(transaction_flags);
    if (status != OK)
        return status;

    status = writer.writeInt32(IPCThreadState::self()->getCallingUid());
    if (status != OK)
        return status;

    status = writer.writeInt32(IPCThreadState::self()->getCallingPid());
    if (status != OK)
        return status;

    status = writer.writeUint64(data.dataSize());
    if (status != OK)
        return status;

    return writer.appendFrom(&data, 0, data.dataSize());
}

status_t BinderInterceptor::validateInterceptorResponse(const Parcel &response, int32_t &action_type) const {
    auto status = response.readInt32(&action_type);
    if (status != OK) {
        LOGE("Failed to read action type from interceptor response");
        return status;
    }

    switch (action_type) {
    case intercept_constants::kActionSkip:
    case intercept_constants::kActionContinue:
    case intercept_constants::kActionOverrideReply:
    case intercept_constants::kActionOverrideData:
        return OK;
    default:
        LOGE("Invalid action type from interceptor: %d", action_type);
        return BAD_VALUE;
    }
}

namespace {
constexpr std::string_view kBinderLibraryName = "libbinder.so";
constexpr std::string_view kIoctlFunctionName = "ioctl";
struct plti g_plti_ctx;
} // namespace

bool initializeBinderInterception() {
    g_binder_interceptor = sp<BinderInterceptor>::make();
    g_binder_stub = sp<BinderStub>::make();

    if (!g_binder_interceptor || !g_binder_stub) {
        LOGE("Failed to create binder interceptor components");
        return false;
    }

    plti_init(&g_plti_ctx);

    if (!plti_add_lib(&g_plti_ctx, kBinderLibraryName.data())) {
        LOGE("Failed to find %s via dl_iterate_phdr", kBinderLibraryName.data());
        g_binder_interceptor.clear();
        g_binder_stub.clear();
        return false;
    }

    if (!plti_add_hook(&g_plti_ctx, kBinderLibraryName.data(), kIoctlFunctionName.data(),
                       reinterpret_cast<void *>(intercepted_ioctl_function),
                       reinterpret_cast<void **>(&original_ioctl_function))) {
        LOGE("Failed to hook %s in %s", kIoctlFunctionName.data(), kBinderLibraryName.data());
        g_binder_interceptor.clear();
        g_binder_stub.clear();
        return false;
    }

    LOGI("Binder interception initialized successfully");
    return true;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
bool entry(void *library_handle) {
    LOGI("TrickyStore binder interceptor loaded (handle: %p)", library_handle);

    bool success = initializeBinderInterception();
    if (success) {
        LOGI("Binder interception entry point completed successfully");
    } else {
        LOGE("Binder interception initialization failed");
    }

    return success;
}
