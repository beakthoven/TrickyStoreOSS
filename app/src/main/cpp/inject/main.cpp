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
constexpr const char *kEntrySymbol = "entry";
} // namespace constants

class RemoteLibraryHandle {
public:
    RemoteLibraryHandle(int pid, int fd, uintptr_t handle) : pid_(pid), fd_(fd), handle_(handle) {}

    ~RemoteLibraryHandle() {
        if (fd_ != -1) {
            struct user_regs_struct regs{};
            std::vector<ts::MapInfo> local_map, remote_map;
            if (get_regs(pid_, regs)) {
                local_map = ts::MapInfo::Scan();
                remote_map = ts::MapInfo::Scan(std::to_string(pid_));
                if (auto close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close")) {
                    std::vector<uintptr_t> args = {static_cast<uintptr_t>(fd_)};
                    remote_call(pid_, regs, reinterpret_cast<uintptr_t>(close_addr), 0, args);
                }
            }
        }
    }

    RemoteLibraryHandle(const RemoteLibraryHandle &) = delete;
    RemoteLibraryHandle &operator=(const RemoteLibraryHandle &) = delete;
    RemoteLibraryHandle(RemoteLibraryHandle &&other) noexcept : pid_(other.pid_), fd_(other.fd_), handle_(other.handle_) {
        other.fd_ = -1;
        other.handle_ = 0;
    }

    uintptr_t handle() const {
        return handle_;
    }
    int fd() const {
        return fd_;
    }

private:
    int pid_;
    int fd_;
    uintptr_t handle_;
};

static std::optional<int> transfer_fd_to_remote(int pid, const char *lib_path, struct user_regs_struct &regs,
                                                const std::vector<ts::MapInfo> &local_map,
                                                const std::vector<ts::MapInfo> &remote_map) {
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
    auto get_remote_errno = [&]() -> int {
        if (!funcs.errno_addr)
            return 0;
        args.clear();
        auto addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.errno_addr), 0, args);
        int err = 0;
        if (!read_proc(pid, addr, &err, sizeof(err)))
            return 0;
        return err;
    };

    auto close_remote = [&](int fd) {
        args = {static_cast<uintptr_t>(fd)};
        if (remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.close_addr), 0, args) != 0) {
            LOGE("Failed to close remote fd: %d", fd);
        }
    };

    args = {AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0};
    int remote_fd = static_cast<int>(remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.socket_addr), 0, args));
    if (remote_fd == -1) {
        errno = get_remote_errno();
        PLOGE("remote socket creation failed");
        return std::nullopt;
    }

    auto magic = generateMagic(constants::kMagicLength);
    struct sockaddr_un sock_addr{.sun_family = AF_UNIX, .sun_path = {0}};
    memcpy(sock_addr.sun_path + 1, magic.c_str(), magic.size());
    socklen_t addr_len = sizeof(sock_addr.sun_family) + 1 + magic.size();

    auto remote_addr = push_memory(pid, regs, &sock_addr, sizeof(sock_addr));
    args = {static_cast<uintptr_t>(remote_fd), remote_addr, static_cast<uintptr_t>(addr_len)};
    auto bind_result = remote_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.bind_addr), 0, args);
    if (bind_result == static_cast<uintptr_t>(-1)) {
        errno = get_remote_errno();
        PLOGE("remote bind failed");
        close_remote(remote_fd);
        return std::nullopt;
    }
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = {0};
    auto remote_cmsgbuf = push_memory(pid, regs, &cmsgbuf, sizeof(cmsgbuf));

    struct msghdr msg_hdr{};
    msg_hdr.msg_control = reinterpret_cast<void *>(remote_cmsgbuf);
    msg_hdr.msg_controllen = sizeof(cmsgbuf);
    auto remote_hdr = push_memory(pid, regs, &msg_hdr, sizeof(msg_hdr));

    args = {static_cast<uintptr_t>(remote_fd), remote_hdr, MSG_WAITALL};
    if (!remote_pre_call(pid, regs, reinterpret_cast<uintptr_t>(funcs.recvmsg_addr), 0, args)) {
        LOGE("Failed to start remote recvmsg call");
        close_remote(remote_fd);
        return std::nullopt;
    }

    msg_hdr.msg_control = &cmsgbuf;
    msg_hdr.msg_name = &sock_addr;
    msg_hdr.msg_namelen = addr_len;

    {
        auto *cmsg = CMSG_FIRSTHDR(&msg_hdr);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        *reinterpret_cast<int *>(CMSG_DATA(cmsg)) = local_lib_fd;
    }

    if (sendmsg(local_socket, &msg_hdr, 0) == -1) {
        PLOGE("Failed to send fd to remote process");
        close_remote(remote_fd);
        return std::nullopt;
    }

    auto recvmsg_result = static_cast<ssize_t>(remote_post_call(pid, regs, 0));
    if (recvmsg_result == -1) {
        errno = get_remote_errno();
        PLOGE("Remote recvmsg failed");
        close_remote(remote_fd);
        return std::nullopt;
    }

    if (read_proc(pid, remote_cmsgbuf, &cmsgbuf, sizeof(cmsgbuf)) != sizeof(cmsgbuf)) {
        LOGE("Failed to read control message from remote process");
        close_remote(remote_fd);
        return std::nullopt;
    }

    auto *cmsg = CMSG_FIRSTHDR(&msg_hdr);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        LOGE("Invalid control message received from remote process");
        close_remote(remote_fd);
        return std::nullopt;
    }

    int transferred_fd = *reinterpret_cast<int *>(CMSG_DATA(cmsg));
    LOGD("Successfully transferred fd %d to remote process", transferred_fd);
    close_remote(remote_fd);
    return transferred_fd;
}

static std::string get_remote_dlerror(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                     const std::vector<ts::MapInfo> &remote_map, uintptr_t libc_return_addr) {
    auto dlerror_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlerror");
    if (!dlerror_addr) {
        return "Failed to find dlerror function";
    }

    std::vector<uintptr_t> args;
    auto dlerror_str_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlerror_addr), libc_return_addr, args);
    if (dlerror_str_addr == 0) {
        return "dlerror returned null";
    }

    auto strlen_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "strlen");
    if (!strlen_addr) {
        return "Failed to find strlen function";
    }

    args.clear();
    args.push_back(dlerror_str_addr);
    auto dlerror_len = remote_call(pid, regs, reinterpret_cast<uintptr_t>(strlen_addr), libc_return_addr, args);
    if (dlerror_len <= 0 || dlerror_len > 1024) {
        return "Invalid dlerror string length";
    }

    std::string err;
    err.resize(dlerror_len + 1, 0);
    if (read_proc(pid, dlerror_str_addr, err.data(), dlerror_len) != dlerror_len) {
        return "Failed to read dlerror string";
    }
    err.resize(dlerror_len);
    return err;
}

static std::optional<uintptr_t> remote_dlopen(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                              const std::vector<ts::MapInfo> &remote_map, int lib_fd, const char *lib_path,
                                              uintptr_t libc_return_addr) {
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

    std::vector<uintptr_t> args = {remote_path, RTLD_NOW, remote_info};
    uintptr_t remote_handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlopen_addr), libc_return_addr, args);

    if (remote_handle == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr);
        LOGW("Primary dlopen failed for library: %s, dlerror: %s", lib_path, error_msg.c_str());
        return std::nullopt;
    }

    LOGD("Successfully loaded library with handle: %p", reinterpret_cast<void *>(remote_handle));
    return remote_handle;
}

static std::optional<uintptr_t> remote_find_entry(int pid, struct user_regs_struct &regs, const std::vector<ts::MapInfo> &local_map,
                                                  const std::vector<ts::MapInfo> &remote_map, uintptr_t remote_handle,
                                                  uintptr_t libc_return_addr) {
    auto dlsym_addr = find_func_addr(local_map, remote_map, constants::kLibdlModule, "dlsym");
    if (!dlsym_addr) {
        LOGE("Failed to find dlsym in %s", constants::kLibdlModule);
        return std::nullopt;
    }

    uintptr_t remote_symbol = push_string(pid, regs, constants::kEntrySymbol);

    std::vector<uintptr_t> args = {remote_handle, remote_symbol};
    uintptr_t entry_addr = remote_call(pid, regs, reinterpret_cast<uintptr_t>(dlsym_addr), libc_return_addr, args);

    if (entry_addr == 0) {
        std::string error_msg = get_remote_dlerror(pid, regs, local_map, remote_map, libc_return_addr);
        LOGE("Failed to find entry symbol '%s' in remote library, dlerror: %s", constants::kEntrySymbol, error_msg.c_str());
        return std::nullopt;
    }

    LOGD("Found entry point at: %p", reinterpret_cast<void *>(entry_addr));
    return entry_addr;
}

static bool remote_call_entry(int pid, struct user_regs_struct &regs, uintptr_t entry_addr, uintptr_t remote_handle,
                              uintptr_t libc_return_addr) {
    std::vector<uintptr_t> args = {remote_handle};
    uintptr_t result = remote_call(pid, regs, entry_addr, libc_return_addr, args);

    LOGD("Entry point called with result: %p", reinterpret_cast<void *>(result));
    return true;
}

class PtraceAttachment {
public:
    explicit PtraceAttachment(int target_pid) : pid_(target_pid), attached_(false) {
        if (ptrace(PTRACE_ATTACH, pid_, 0, 0) == -1) {
            PLOGE("Failed to attach to process %d", pid_);
            return;
        }
        attached_ = true;
        LOGD("Successfully attached to process %d", pid_);
    }

    ~PtraceAttachment() {
        if (attached_) {
            if (ptrace(PTRACE_DETACH, pid_, 0, 0) == -1) {
                PLOGE("Failed to detach from process %d", pid_);
            } else {
                LOGD("Successfully detached from process %d", pid_);
            }
        }
    }

    bool is_attached() const {
        return attached_;
    }

    PtraceAttachment(const PtraceAttachment &) = delete;
    PtraceAttachment &operator=(const PtraceAttachment &) = delete;

private:
    int pid_;
    bool attached_;
};

bool inject_library(int pid, const char *lib_path, const char *entry_name) {
    LOGI("Starting injection of %s (entry: %s) into process %d", lib_path, entry_name, pid);

    PtraceAttachment ptrace_guard(pid);
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
        return false;
    }

    struct user_regs_struct current_regs{}, backup_regs{};
    if (!get_regs(pid, current_regs)) {
        LOGE("Failed to get process registers");
        return false;
    }
    backup_regs = current_regs;
    LOGD("Process stopped and registers backed up");

    auto remote_map = ts::MapInfo::Scan(std::to_string(pid));
    auto local_map = ts::MapInfo::Scan();

    auto libc_return_addr = find_module_return_addr(remote_map, constants::kLibcModule);
    if (!libc_return_addr) {
        LOGE("Failed to find return address for %s", constants::kLibcModule);
        return false;
    }
    LOGD("Found libc return address: %p", libc_return_addr);

    auto lib_fd_opt = transfer_fd_to_remote(pid, lib_path, current_regs, local_map, remote_map);
    if (!lib_fd_opt) {
        LOGE("Failed to transfer library fd to remote process");
        return false;
    }
    int lib_fd = *lib_fd_opt;

    auto handle_opt =
        remote_dlopen(pid, current_regs, local_map, remote_map, lib_fd, lib_path, reinterpret_cast<uintptr_t>(libc_return_addr));
    if (!handle_opt) {
        LOGE("Failed to load library in remote process");
        return false;
    }
    uintptr_t remote_handle = *handle_opt;

    auto close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close");
    if (close_addr) {
        std::vector<uintptr_t> args = {static_cast<uintptr_t>(lib_fd)};
        if (remote_call(pid, current_regs, reinterpret_cast<uintptr_t>(close_addr), 0, args) != 0) {
            LOGW("Failed to close remote library fd: %d", lib_fd);
        }
    }

    auto entry_opt =
        remote_find_entry(pid, current_regs, local_map, remote_map, remote_handle, reinterpret_cast<uintptr_t>(libc_return_addr));
    if (!entry_opt) {
        LOGE("Failed to find entry point in remote library");
        return false;
    }
    uintptr_t entry_addr = *entry_opt;

    if (!remote_call_entry(pid, current_regs, entry_addr, remote_handle, reinterpret_cast<uintptr_t>(libc_return_addr))) {
        LOGE("Failed to call entry point");
        return false;
    }

    if (!set_regs(pid, backup_regs)) {
        LOGE("Failed to restore original registers");
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
