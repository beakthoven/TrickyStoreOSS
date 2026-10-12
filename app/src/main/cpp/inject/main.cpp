// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <android/dlext.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cinttypes>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "logging.hpp"
#include "maps.hpp"
#include "utils.hpp"

using namespace std::string_literals;

namespace inject {

namespace constants {
constexpr size_t kMagicLength = 16;
constexpr size_t kMaxPathLength = 4096;
constexpr const char *kSystemFileContext = "u:object_r:system_file:s0";
constexpr const char *kLibcModule = "libc.so";
constexpr const char *kLibdlModule = "libdl.so";
} // namespace constants

class SavedRegistersGuard {
public:
    SavedRegistersGuard(int pid, const struct user_regs_struct &regs, bool &detach_allowed)
        : pid_(pid), regs_(regs), detach_allowed_(detach_allowed) {}

    ~SavedRegistersGuard() {
        if (active_ && !restore()) {
            detach_allowed_ = false;
            LOGE("Failed to restore original registers; leaving target stopped");
        }
    }

    bool restore() {
        if (!active_)
            return true;
        if (!set_regs(pid_, regs_))
            return false;
        active_ = false;
        return true;
    }

private:
    int pid_;
    struct user_regs_struct regs_;
    bool &detach_allowed_;
    bool active_ = true;
};

class RemoteFdGuard {
public:
    RemoteFdGuard(int pid, int fd, uintptr_t close_addr, struct user_regs_struct &regs, int *pending_signal)
        : pid_(pid), fd_(fd), close_addr_(close_addr), regs_(regs), pending_signal_(pending_signal) {}

    ~RemoteFdGuard() {
        if (fd_ >= 0 && !(pending_signal_ && *pending_signal_))
            close();
    }

    bool close() {
        if (fd_ < 0)
            return true;
        if (pending_signal_ && *pending_signal_) {
            LOGE("Leaving remote fd %d open because the target has an unexpected signal stop", fd_);
            return false;
        }
        if (!close_addr_) {
            LOGE("Cannot close remote fd %d: close() was not resolved", fd_);
            return false;
        }
        int fd = fd_;
        std::vector<uintptr_t> args = {static_cast<uintptr_t>(fd)};
        auto result = remote_call(pid_, regs_, close_addr_, 0, args, pending_signal_);
        if (!result || *result != 0) {
            LOGE("Failed to close remote fd %d", fd);
            return false;
        }
        fd_ = -1;
        return true;
    }

    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

private:
    int pid_;
    int fd_;
    uintptr_t close_addr_;
    struct user_regs_struct &regs_;
    int *pending_signal_;
};

static std::optional<int> transfer_fd_to_remote(int pid, const char *lib_path, struct user_regs_struct &regs,
                                                const std::vector<ts::MapInfo> &local_map, const std::vector<ts::MapInfo> &remote_map,
                                                int *pending_signal) {
    if (!set_sockcreate_con(constants::kSystemFileContext)) {
        LOGE("Failed to set socket creation context");
        return std::nullopt;
    }

    UniqueFd local_socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (local_socket == -1) {
        PLOGE("create local socket");
        return std::nullopt;
    }

    if (setfilecon(lib_path, constants::kSystemFileContext) == -1) {
        PLOGE("set context of lib");
    }

    UniqueFd local_lib_fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (local_lib_fd == -1) {
        PLOGE("open lib: %s", lib_path);
        return std::nullopt;
    }

    struct RemoteFunctions {
        void *socket_addr;
        void *bind_addr;
        void *recvmsg_addr;
        void *close_addr;
        void *errno_addr;
    } funcs{};

    funcs.socket_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "socket");
    funcs.bind_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "bind");
    funcs.recvmsg_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "recvmsg");
    funcs.close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close");
    funcs.errno_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "__errno");

    if (!funcs.socket_addr || !funcs.bind_addr || !funcs.recvmsg_addr || !funcs.close_addr) {
        LOGE("Failed to resolve required libc functions");
        return std::nullopt;
    }
    std::vector<uintptr_t> args;
    auto get_remote_errno = [&]() -> std::optional<int> {
        if (!funcs.errno_addr)
            return std::nullopt;
        args.clear();
        auto addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.errno_addr), 0, args, pending_signal);
        if (!addr || *addr == 0)
            return std::nullopt;
        int err = 0;
        if (read_proc(pid, *addr, &err, sizeof(err)) != sizeof(err))
            return std::nullopt;
        return err;
    };
    auto log_remote_failure = [&](const char *operation) {
        auto remote_errno = get_remote_errno();
        if (remote_errno)
            LOGE("%s failed with remote errno %d: %s", operation, *remote_errno, strerror(*remote_errno));
        else
            LOGE("%s failed; remote errno unavailable", operation);
    };

    args = {AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0};
    auto socket_result = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.socket_addr), 0, args, pending_signal);
    if (!socket_result) {
        LOGE("Remote socket call failed");
        return std::nullopt;
    }
    int remote_fd = static_cast<int>(static_cast<intptr_t>(*socket_result));
    if (remote_fd == -1) {
        log_remote_failure("remote socket creation");
        return std::nullopt;
    }
    RemoteFdGuard remote_socket_guard(pid, remote_fd, reinterpret_cast<uintptr_t>(funcs.close_addr), regs, pending_signal);

    auto magic = generateMagic(constants::kMagicLength);
    struct sockaddr_un sock_addr{.sun_family = AF_UNIX, .sun_path = {0}};
    memcpy(sock_addr.sun_path + 1, magic.c_str(), magic.size());
    socklen_t addr_len = sizeof(sock_addr.sun_family) + 1 + magic.size();

    auto remote_addr = push_memory(pid, regs, &sock_addr, sizeof(sock_addr));
    if (!remote_addr)
        return std::nullopt;
    args = {static_cast<uintptr_t>(remote_fd), remote_addr, static_cast<uintptr_t>(addr_len)};
    auto bind_result = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.bind_addr), 0, args, pending_signal);
    if (!bind_result) {
        LOGE("Remote bind call failed");
        return std::nullopt;
    }
    if (static_cast<intptr_t>(*bind_result) == -1) {
        log_remote_failure("remote bind");
        return std::nullopt;
    }
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = {0};
    auto remote_cmsgbuf = push_memory(pid, regs, &cmsgbuf, sizeof(cmsgbuf));
    if (!remote_cmsgbuf)
        return std::nullopt;

    struct msghdr msg_hdr{};
    msg_hdr.msg_control = reinterpret_cast<void *>(remote_cmsgbuf);
    msg_hdr.msg_controllen = sizeof(cmsgbuf);
    auto remote_hdr = push_memory(pid, regs, &msg_hdr, sizeof(msg_hdr));
    if (!remote_hdr)
        return std::nullopt;

    args = {static_cast<uintptr_t>(remote_fd), remote_hdr, MSG_WAITALL};
    if (!remote_pre_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.recvmsg_addr), 0, args)) {
        LOGE("Failed to start remote recvmsg call");
        return std::nullopt;
    }

    msg_hdr.msg_control = &cmsgbuf;
    msg_hdr.msg_name = &sock_addr;
    msg_hdr.msg_namelen = addr_len;

    auto *cmsg = CMSG_FIRSTHDR(&msg_hdr);
    if (!cmsg) {
        LOGE("Failed to prepare fd control message");
        return std::nullopt;
    }
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *reinterpret_cast<int *>(CMSG_DATA(cmsg)) = local_lib_fd;

    if (sendmsg(local_socket, &msg_hdr, 0) == -1) {
        PLOGE("Failed to send fd to remote process");
        return std::nullopt;
    }

    auto recvmsg_result = remote_post_call(pid, regs, 0, pending_signal);
    if (!recvmsg_result) {
        LOGE("Remote recvmsg call failed");
        return std::nullopt;
    }
    if (static_cast<intptr_t>(*recvmsg_result) == -1) {
        log_remote_failure("remote recvmsg");
        return std::nullopt;
    }

    if (read_proc(pid, remote_cmsgbuf, &cmsgbuf, sizeof(cmsgbuf)) != sizeof(cmsgbuf)) {
        LOGE("Failed to read control message from remote process; transferred fd is unknown and cannot be cleaned up safely");
        return std::nullopt;
    }

    cmsg = CMSG_FIRSTHDR(&msg_hdr);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        LOGE("Invalid control message received from remote process; transferred fd is unknown and cannot be cleaned up safely");
        return std::nullopt;
    }

    int transferred_fd = *reinterpret_cast<int *>(CMSG_DATA(cmsg));
    if (transferred_fd < 0) {
        LOGE("SCM_RIGHTS control message contained an invalid fd");
        return std::nullopt;
    }
    LOGD("Successfully transferred fd %d to remote process", transferred_fd);
    RemoteFdGuard transferred_fd_guard(pid, transferred_fd, reinterpret_cast<uintptr_t>(funcs.close_addr), regs, pending_signal);
    if (!remote_socket_guard.close())
        return std::nullopt;
    return transferred_fd_guard.release();
}

static std::string get_remote_dlerror(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                      const std::vector<ts::MapInfo> &remote_map, uintptr_t libc_return_addr, int *pending_signal) {
    auto dlerror_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlerror");
    if (!dlerror_addr) {
        return "Failed to find dlerror function";
    }

    std::vector<uintptr_t> args;
    auto dlerror_str_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlerror_addr), libc_return_addr, args, pending_signal);
    if (!dlerror_str_addr || *dlerror_str_addr == 0) {
        return "dlerror returned null or remote call failed";
    }

    auto strlen_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "strlen");
    if (!strlen_addr) {
        return "Failed to find strlen function";
    }

    args = {*dlerror_str_addr};
    auto dlerror_len = remote_call(pid, regs, reinterpret_cast<uintptr_t>(strlen_addr), libc_return_addr, args, pending_signal);
    if (!dlerror_len || *dlerror_len == 0 || *dlerror_len > 1024) {
        return "Invalid dlerror string length or remote call failed";
    }

    std::string err(*dlerror_len + 1, 0);
    if (read_proc(pid, *dlerror_str_addr, err.data(), *dlerror_len) != static_cast<ssize_t>(*dlerror_len)) {
        return "Failed to read dlerror string";
    }
    err.resize(*dlerror_len);
    return err;
}

static std::optional<uintptr_t> remote_dlopen(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                              const std::vector<ts::MapInfo> &remote_map, int lib_fd, const char *lib_path,
                                              uintptr_t libc_return_addr, int *pending_signal) {
    auto dlopen_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "android_dlopen_ext");
    if (!dlopen_addr) {
        LOGW("Failed to find android_dlopen_ext in %s,", constants::kLibdlModule);
        return std::nullopt;
    }

    android_dlextinfo dlext_info{};
    dlext_info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    dlext_info.library_fd = lib_fd;

    uintptr_t remote_info = push_memory(pid, regs, &dlext_info, sizeof(dlext_info));
    uintptr_t remote_path = push_string(pid, regs, lib_path);
    if (!remote_info || !remote_path)
        return std::nullopt;

    std::vector<uintptr_t> args = {remote_path, RTLD_NOW, remote_info};
    auto remote_handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlopen_addr), libc_return_addr, args, pending_signal);
    if (!remote_handle) {
        LOGE("Remote dlopen call failed");
        return std::nullopt;
    }
    if (*remote_handle == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr, pending_signal);
        LOGW("Primary dlopen failed for library: %s, dlerror: %s", lib_path, error_msg.c_str());
        return std::nullopt;
    }

    LOGD("Successfully loaded library with handle: %p", reinterpret_cast<void *>(*remote_handle));
    return *remote_handle;
}

static std::optional<uintptr_t> remote_find_entry(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                                  const std::vector<ts::MapInfo> &remote_map, uintptr_t remote_handle,
                                                  const char *entry_name, uintptr_t libc_return_addr, int *pending_signal) {
    auto dlsym_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlsym");
    if (!dlsym_addr) {
        LOGE("Failed to find dlsym in %s", constants::kLibdlModule);
        return std::nullopt;
    }

    uintptr_t remote_symbol = push_string(pid, regs, entry_name);
    if (!remote_symbol)
        return std::nullopt;

    std::vector<uintptr_t> args = {remote_handle, remote_symbol};
    auto entry_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlsym_addr), libc_return_addr, args, pending_signal);
    if (!entry_addr) {
        LOGE("Remote dlsym call failed");
        return std::nullopt;
    }
    if (*entry_addr == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr, pending_signal);
        LOGE("Failed to find entry symbol '%s' in remote library, dlerror: %s", entry_name, error_msg.c_str());
        return std::nullopt;
    }

    LOGD("Found entry point at: %p", reinterpret_cast<void *>(*entry_addr));
    return *entry_addr;
}

static std::optional<bool> remote_call_entry(int pid, struct user_regs_struct &regs, uintptr_t entry_addr, uintptr_t remote_handle,
                                             uintptr_t libc_return_addr, int *pending_signal) {
    std::vector<uintptr_t> args = {remote_handle};
    auto result = remote_call(pid, regs, entry_addr, libc_return_addr, args, pending_signal);
    if (!result)
        return std::nullopt;

    LOGD("Entry point called with result: %p", reinterpret_cast<void *>(*result));
    return *result != 0;
}

class PtraceAttachment {
public:
    PtraceAttachment(int target_pid, int &detach_signal, const bool &detach_allowed)
        : pid_(target_pid), attached_(false), detach_signal_(detach_signal), detach_allowed_(detach_allowed) {
        if (ptrace(PTRACE_ATTACH, pid_, 0, 0) == -1) {
            PLOGE("Failed to attach to process %d", pid_);
            return;
        }
        attached_ = true;
        LOGD("Successfully attached to process %d", pid_);
    }

    ~PtraceAttachment() {
        if (!attached_)
            return;
        if (detach_failed_) {
            LOGE("Leaving process %d stopped after detach failure", pid_);
        } else if (!detach()) {
            LOGE("Leaving process %d stopped because automatic detach failed", pid_);
        }
    }

    bool is_attached() const {
        return attached_;
    }

    bool detach() {
        if (!attached_)
            return true;
        if (!detach_allowed_) {
            LOGE("Cannot detach process %d because register restoration failed", pid_);
            detach_failed_ = true;
            return false;
        }
        if (ptrace(PTRACE_DETACH, pid_, 0, reinterpret_cast<void *>(static_cast<intptr_t>(detach_signal_))) == -1) {
            PLOGE("Failed to detach from process %d", pid_);
            detach_failed_ = true;
            return false;
        }
        attached_ = false;
        LOGD("Successfully detached from process %d", pid_);
        return true;
    }

    PtraceAttachment(const PtraceAttachment &) = delete;
    PtraceAttachment &operator=(const PtraceAttachment &) = delete;

private:
    int pid_;
    bool attached_;
    int &detach_signal_;
    const bool &detach_allowed_;
    bool detach_failed_ = false;
};

bool inject_library(int pid, const char *lib_path, const char *entry_name) {
    LOGI("Starting injection of %s (entry: %s) into process %d", lib_path, entry_name, pid);

    int pending_signal = 0;
    bool detach_allowed = true;
    PtraceAttachment ptrace_guard(pid, pending_signal, detach_allowed);
    if (!ptrace_guard.is_attached()) {
        return false;
    }

    int status;
    if (!wait_for_trace(pid, &status, __WALL)) {
        LOGE("Failed to wait for trace");
        return false;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        LOGE("Process stopped for unexpected reason: %s", parse_status(status).c_str());
        if (WIFSTOPPED(status))
            pending_signal = WSTOPSIG(status);
        return false;
    }

    struct user_regs_struct current_regs{}, backup_regs{};
    if (!get_regs(pid, current_regs)) {
        LOGE("Failed to get process registers");
        return false;
    }
    backup_regs = current_regs;
    SavedRegistersGuard registers_guard(pid, backup_regs, detach_allowed);
    LOGD("Process stopped and registers backed up");

    auto remote_map = ts::MapInfo::Scan(std::to_string(pid));
    auto local_map = ts::MapInfo::Scan();

    auto libc_return_addr = find_module_return_addr(remote_map, constants::kLibcModule);
    if (!libc_return_addr) {
        LOGE("Failed to find return address for %s", constants::kLibcModule);
        return false;
    }
    LOGD("Found libc return address: %p", libc_return_addr);

    auto close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close");
    if (!close_addr) {
        LOGE("Failed to find close in %s", constants::kLibcModule);
        return false;
    }

    auto lib_fd_opt = transfer_fd_to_remote(pid, lib_path, current_regs, local_map, remote_map, &pending_signal);
    if (!lib_fd_opt) {
        LOGE("Failed to transfer library fd to remote process");
        return false;
    }
    int lib_fd = *lib_fd_opt;
    RemoteFdGuard library_fd_guard(pid, lib_fd, reinterpret_cast<uintptr_t>(close_addr), current_regs, &pending_signal);

    auto handle_opt = remote_dlopen(pid, current_regs, local_map, remote_map, lib_fd, lib_path,
                                    reinterpret_cast<uintptr_t>(libc_return_addr), &pending_signal);
    if (!handle_opt) {
        LOGE("Failed to load library in remote process");
        return false;
    }
    uintptr_t remote_handle = *handle_opt;

    auto entry_opt = remote_find_entry(pid, current_regs, local_map, remote_map, remote_handle, entry_name,
                                       reinterpret_cast<uintptr_t>(libc_return_addr), &pending_signal);
    if (!entry_opt) {
        LOGE("Failed to find entry point in remote library");
        return false;
    }
    uintptr_t entry_addr = *entry_opt;

    auto entry_result = remote_call_entry(pid, current_regs, entry_addr, remote_handle, reinterpret_cast<uintptr_t>(libc_return_addr),
                                          &pending_signal);
    if (!entry_result) {
        LOGE("Failed to call entry point");
        return false;
    }
    if (!*entry_result) {
        LOGE("Remote entry point rejected initialization");
        return false;
    }

    if (!library_fd_guard.close())
        return false;

    if (!registers_guard.restore()) {
        LOGE("Failed to restore original registers");
        return false;
    }
    if (!ptrace_guard.detach()) {
        LOGE("Library injection completed, but target detach failed");
        return false;
    }

    LOGI("Library injection completed successfully");
    return true;
}

} // namespace inject

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <pid> <lib_path> <entry_name>\n", argv[0]);
        fprintf(stderr, "  pid       - Target process ID\n");
        fprintf(stderr, "  lib_path  - Path to shared library to inject\n");
        fprintf(stderr, "  entry_name - Entry point symbol name in library\n");
        return EXIT_FAILURE;
    }

    char *endptr;
    long pid_long = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) {
        fprintf(stderr, "Error: Invalid PID '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }
    int pid = static_cast<int>(pid_long);

    char resolved_path[inject::constants::kMaxPathLength];
    if (realpath(argv[2], resolved_path) == nullptr) {
        fprintf(stderr, "Error: Failed to resolve library path '%s': %s\n", argv[2], strerror(errno));
        return EXIT_FAILURE;
    }

    if (access(resolved_path, R_OK) != 0) {
        fprintf(stderr, "Error: Library file '%s' is not readable: %s\n", resolved_path, strerror(errno));
        return EXIT_FAILURE;
    }

    const char *entry_name = argv[3];
    if (strlen(entry_name) == 0) {
        fprintf(stderr, "Error: Entry name cannot be empty\n");
        return EXIT_FAILURE;
    }

    LOGI("TrickyStore injector starting...");
    bool success = inject::inject_library(pid, resolved_path, entry_name);

    if (success) {
        LOGI("Injection completed successfully");
        return EXIT_SUCCESS;
    } else {
        LOGE("Injection failed");
        return EXIT_FAILURE;
    }
}
