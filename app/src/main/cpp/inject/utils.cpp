// Copyright 2026 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <array>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "logging.hpp"

namespace {
constexpr size_t kMaxPathLength = 256;
constexpr size_t kMsgBufferSize = 64;
constexpr size_t kStatusBufferSize = 128;
constexpr int kInvalidFd = -1;
constexpr uintptr_t kStackAlignment = 0xf;
constexpr int kMaxArguments = 8;

constexpr std::string_view kRandomChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
} // namespace

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len, bool use_proc_mem) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for write_proc");
        return -1;
    }

    LOGV("Writing %zu bytes to PID %d at address %" PRIxPTR " (use_proc_mem=%s)", len, pid, remote_addr,
         use_proc_mem ? "true" : "false");

    ssize_t bytes_written;

    if (use_proc_mem) {
        char proc_path[kMaxPathLength];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);

        UniqueFd proc_fd = open(proc_path, O_WRONLY | O_CLOEXEC);
        if (proc_fd == kInvalidFd) {
            PLOGE("Failed to open %s", proc_path);
            return -1;
        }

        bytes_written = pwrite(proc_fd, buf, len, static_cast<off_t>(remote_addr));
        if (bytes_written == -1) {
            PLOGE("pwrite failed for address %" PRIxPTR, remote_addr);
        }
    } else {
        struct iovec local_iov = {.iov_base = const_cast<void *>(buf), .iov_len = len};
        struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

        bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (bytes_written == -1) {
            PLOGE("process_vm_writev failed for address %" PRIxPTR, remote_addr);
        }
    }

    if (bytes_written != -1 && static_cast<size_t>(bytes_written) != len) {
        LOGW("Partial write: %zd bytes written, %zu expected", bytes_written, len);
    }

    return bytes_written;
}

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    if (!buf || len == 0) {
        LOGE("Invalid parameters for read_proc");
        return -1;
    }

    LOGV("Reading %zu bytes from PID %d at address %" PRIxPTR, len, pid, remote_addr);

    struct iovec local_iov = {.iov_base = buf, .iov_len = len};
    struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == -1) {
        PLOGE("process_vm_readv failed for address %" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("Partial read: %zd bytes read, %zu expected", bytes_read, len);
    }

    return bytes_read;
}

bool get_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Getting registers for PID %d", pid);

#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to get registers for PID %d", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to get register set for PID %d", pid);
        return false;
    }
#else
#    error "Unsupported architecture for register access"
#endif

    LOGV("Successfully retrieved registers for PID %d", pid);
    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
    LOGV("Setting registers for PID %d", pid);

#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("Failed to set registers for PID %d", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("Failed to set register set for PID %d", pid);
        return false;
    }
#else
#    error "Unsupported architecture for register access"
#endif

    LOGV("Successfully set registers for PID %d", pid);
    return true;
}

void *find_module_base(const std::vector<ts::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        if (map.offset == 0 && map.path.ends_with(module_suffix)) {
            LOGV("Found module base for '%.*s' at %p", static_cast<int>(module_suffix.length()), module_suffix.data(),
                 reinterpret_cast<void *>(map.start));
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGV("Module base not found for suffix '%.*s'", static_cast<int>(module_suffix.length()), module_suffix.data());
    return nullptr;
}

void *find_func_addr(const std::vector<ts::MapInfo> &local_map_info, const std::vector<ts::MapInfo> &remote_map_info,
                     std::string_view module_name, std::string_view function_name) {
    LOGV("Resolving function '%.*s' in module '%.*s'", static_cast<int>(function_name.length()), function_name.data(),
         static_cast<int>(module_name.length()), module_name.data());

    void *lib_handle = dlopen(module_name.data(), RTLD_NOW);
    if (!lib_handle) {
        LOGE("Failed to open library '%.*s': %s", static_cast<int>(module_name.length()), module_name.data(), dlerror());
        return nullptr;
    }

    auto lib_closer = [lib_handle]() {
        dlclose(lib_handle);
    };

    auto *symbol_addr = reinterpret_cast<uint8_t *>(dlsym(lib_handle, function_name.data()));
    if (!symbol_addr) {
        LOGE("Failed to find symbol '%.*s' in library '%.*s': %s", static_cast<int>(function_name.length()), function_name.data(),
             static_cast<int>(module_name.length()), module_name.data(), dlerror());
        lib_closer();
        return nullptr;
    }

    LOGV("Found symbol '%.*s' at local address %p", static_cast<int>(function_name.length()), function_name.data(), symbol_addr);
    lib_closer();

    auto *local_base = reinterpret_cast<uint8_t *>(find_module_base(local_map_info, module_name));
    if (!local_base) {
        LOGE("Failed to find local base address for module '%.*s'", static_cast<int>(module_name.length()), module_name.data());
        return nullptr;
    }

    auto *remote_base = reinterpret_cast<uint8_t *>(find_module_base(remote_map_info, module_name));
    if (!remote_base) {
        LOGE("Failed to find remote base address for module '%.*s'", static_cast<int>(module_name.length()), module_name.data());
        return nullptr;
    }

    ptrdiff_t symbol_offset = symbol_addr - local_base;
    auto *remote_symbol_addr = remote_base + symbol_offset;

    LOGV("Address translation: local_base=%p remote_base=%p offset=%td -> "
         "remote_addr=%p",
         local_base, remote_base, symbol_offset, remote_symbol_addr);

    return remote_symbol_addr;
}

void align_stack(struct user_regs_struct &regs, uintptr_t preserve_bytes) {
    regs.REG_SP = (regs.REG_SP - preserve_bytes) & ~kStackAlignment;
    LOGV("Stack aligned to %" PRIxPTR " (preserved %zu bytes)", static_cast<uintptr_t>(regs.REG_SP), preserve_bytes);
}

uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length) {
    if (!data || length == 0) {
        LOGE("Invalid parameters for push_memory: data=%p, length=%zu", data, length);
        return 0;
    }

    regs.REG_SP -= length;
    align_stack(regs);

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    if (write_proc(pid, stack_addr, data, length) != static_cast<ssize_t>(length)) {
        LOGE("Failed to push %zu bytes to remote stack at %" PRIxPTR, length, stack_addr);
        return 0;
    }

    LOGV("Pushed %zu bytes to remote stack at %" PRIxPTR, length, stack_addr);
    return stack_addr;
}

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    if (!str) {
        LOGE("Null string pointer passed to push_string");
        return 0;
    }

    size_t str_length = strlen(str) + 1;

    regs.REG_SP -= str_length;
    align_stack(regs);

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    if (write_proc(pid, stack_addr, str, str_length) != static_cast<ssize_t>(str_length)) {
        LOGE("Failed to push string '%s' to remote stack", str);
        return 0;
    }

    LOGV("Pushed string '%s' (%zu bytes) to remote stack at %" PRIxPTR, str, str_length, stack_addr);
    return stack_addr;
}

namespace {
#if defined(__x86_64__)
constexpr size_t kMaxRegisterArgs = 6;
void setup_x86_64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    if (args.size() >= 1)
        regs.rdi = args[0];
    if (args.size() >= 2)
        regs.rsi = args[1];
    if (args.size() >= 3)
        regs.rdx = args[2];
    if (args.size() >= 4)
        regs.rcx = args[3];
    if (args.size() >= 5)
        regs.r8 = args[4];
    if (args.size() >= 6)
        regs.r9 = args[5];
}
#elif defined(__i386__)
constexpr size_t kMaxRegisterArgs = 0;
#elif defined(__aarch64__)
constexpr size_t kMaxRegisterArgs = 8;
void setup_aarch64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    for (size_t i = 0; i < std::min(args.size(), kMaxRegisterArgs); i++) {
        regs.regs[i] = args[i];
    }
}
#elif defined(__arm__)
constexpr size_t kMaxRegisterArgs = 4;
void setup_arm_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    for (size_t i = 0; i < std::min(args.size(), kMaxRegisterArgs); i++) {
        regs.uregs[i] = args[i];
    }
}
#endif
} // namespace

bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args) {
    align_stack(regs);

    LOGV("Setting up remote function call to %" PRIxPTR " with %zu arguments", func_addr, args.size());
    for (size_t i = 0; i < args.size(); i++) {
        LOGV("  arg[%zu] = %p", i, reinterpret_cast<void *>(args[i]));
    }

#if defined(__x86_64__)
    setup_x86_64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) {
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for x86_64");
            return false;
        }
    }

    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("Failed to write return address");
        return false;
    }

    regs.REG_IP = func_addr;

#elif defined(__i386__)
    if (args.size() > 0) {
        size_t stack_args_size = args.size() * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data(), stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push arguments for i386");
            return false;
        }
    }

    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("Failed to write return address for i386");
        return false;
    }

    regs.REG_IP = func_addr;

#elif defined(__aarch64__)
    setup_aarch64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) {
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for aarch64");
            return false;
        }
    }

    regs.regs[30] = return_addr;
    regs.REG_IP = func_addr;

#elif defined(__arm__)
    setup_arm_args(regs, args);

    if (args.size() > kMaxRegisterArgs) {
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("Failed to push stack arguments for ARM");
            return false;
        }
    }

    regs.uregs[14] = return_addr;
    regs.REG_IP = func_addr;

    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        regs.REG_IP = regs.REG_IP & ~1;
        regs.uregs[16] = regs.uregs[16] | CPSR_T_MASK;
    } else {
        regs.uregs[16] = regs.uregs[16] & ~CPSR_T_MASK;
    }

#else
#    error "Unsupported architecture for remote function calls"
#endif

    if (!set_regs(pid, regs)) {
        LOGE("Failed to set registers for remote function call");
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        PLOGE("Failed to continue remote process execution");
        return false;
    }

    LOGV("Remote function call initiated successfully");
    return true;
}

uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected_return_addr) {
    LOGV("Waiting for remote function call completion");

    int status;
    while (true) {
        if (!wait_for_trace(pid, &status, __WALL)) {
            LOGE("Failed to wait for remote function completion");
            return 0;
        }

        if (!get_regs(pid, regs)) {
            LOGE("Failed to get registers after remote call");
            return 0;
        }

        int stop_signal = WSTOPSIG(status);
        LOGV("Remote function stopped with signal: %s(%d) at address %p", sigabbrev_np(stop_signal), stop_signal,
             reinterpret_cast<void *>(regs.REG_IP));

        if (stop_signal == SIGSEGV) {
            if (static_cast<uintptr_t>(regs.REG_IP) != expected_return_addr) {
                LOGE("Function returned to unexpected address %p (expected %p)", reinterpret_cast<void *>(regs.REG_IP),
                     reinterpret_cast<void *>(expected_return_addr));

                siginfo_t crash_info;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &crash_info) == 0) {
                    LOGE("Crash details: si_code=%d si_addr=%p", crash_info.si_code, crash_info.si_addr);
                } else {
                    PLOGE("Failed to get crash signal info");
                }
                return 0;
            }

            uintptr_t return_value = regs.REG_RET;
            LOGV("Remote function completed with return value: %p", reinterpret_cast<void *>(return_value));
            return return_value;
        }

        // Suppress benign signals (SIGCHLD from fork, etc.) and keep waiting
        // for the expected SIGSEGV at the return address.
        LOGV("Suppressing %s(%d) during remote call, continuing",
             sigabbrev_np(stop_signal), stop_signal);
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            PLOGE("Failed to continue after signal %s(%d)", sigabbrev_np(stop_signal), stop_signal);
            return 0;
        }
    }
}

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                      std::vector<uintptr_t> &args) {
    if (!remote_pre_call(pid, regs, func_addr, return_addr, args)) {
        LOGE("Failed to prepare remote function call");
        return 0;
    }
    return remote_post_call(pid, regs, return_addr);
}

bool wait_for_trace(int pid, int *status, int flags) {
    if (!status) {
        LOGE("Null status pointer passed to wait_for_trace");
        return false;
    }

    while (true) {
        pid_t result = waitpid(pid, status, flags);
        if (result == -1) {
            if (errno == EINTR) {
                LOGV("waitpid interrupted, retrying");
                continue;
            } else {
                PLOGE("waitpid failed for PID %d", pid);
                return false;
            }
        }

        if (!WIFSTOPPED(*status)) {
            LOGE("Process %d not stopped for trace: %s", pid, parse_status(*status).c_str());
            return false;
        }

        LOGV("Process %d stopped for trace with status: %s", pid, parse_status(*status).c_str());
        return true;
    }
}

std::string parse_status(int status) {
    char status_buf[kStatusBufferSize];

    if (WIFEXITED(status)) {
        snprintf(status_buf, sizeof(status_buf), "0x%x exited with code %d", status, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(status_buf, sizeof(status_buf), "0x%x terminated by signal %s(%d)", status, sigabbrev_np(WTERMSIG(status)),
                 WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        int stop_signal = WSTOPSIG(status);
        snprintf(status_buf, sizeof(status_buf), "0x%x stopped by signal=%s(%d), event=%s", status, sigabbrev_np(stop_signal),
                 stop_signal, parse_ptrace_event(status));
    } else {
        snprintf(status_buf, sizeof(status_buf), "0x%x unknown status", status);
    }

    return std::string(status_buf);
}

void *find_module_return_addr(const std::vector<ts::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        if ((map.perms & PROT_EXEC) == 0 && map.path.ends_with(module_suffix)) {
            LOGV("Found return address region for '%.*s' at %p", static_cast<int>(module_suffix.length()), module_suffix.data(),
                 reinterpret_cast<void *>(map.start));
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGV("No return address region found for module suffix '%.*s'", static_cast<int>(module_suffix.length()), module_suffix.data());
    return nullptr;
}

std::string generateMagic(size_t length) {
    if (length == 0) {
        LOGW("Zero length requested for magic string");
        return "";
    }

    std::mt19937 random_generator{std::random_device{}()};
    std::uniform_int_distribution<size_t> char_distribution(0, kRandomChars.length() - 1);

    std::string magic_string;
    magic_string.reserve(length);

    for (size_t i = 0; i < length; i++) {
        magic_string += kRandomChars[char_distribution(random_generator)];
    }

    LOGV("Generated magic string of length %zu", length);
    return magic_string;
}

int setfilecon(const char *file_path, const char *security_context) {
    if (!file_path || !security_context) {
        LOGE("Invalid parameters for setfilecon: path=%p, context=%p", file_path, security_context);
        return -1;
    }

    size_t context_len = strlen(security_context) + 1;
    int result = syscall(__NR_setxattr, file_path, XATTR_NAME_SELINUX, security_context, context_len, 0);

    if (result == 0) {
        LOGV("Successfully set SELinux context '%s' for file '%s'", security_context, file_path);
    } else {
        PLOGE("Failed to set SELinux context '%s' for file '%s'", security_context, file_path);
    }

    return result;
}

bool set_sockcreate_con(const char *security_context) {
    if (!security_context) {
        LOGE("Null security context passed to set_sockcreate_con");
        return false;
    }

    size_t context_size = strlen(security_context) + 1;

    UniqueFd sockcreate_fd = open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd != kInvalidFd && write(sockcreate_fd, security_context, context_size) == static_cast<ssize_t>(context_size)) {
        LOGV("Successfully set socket creation context via thread-self: '%s'", security_context);
        return true;
    }

    LOGV("Thread-self sockcreate failed, trying process-specific fallback");
    char process_path[kMaxPathLength];
    snprintf(process_path, sizeof(process_path), "/proc/%d/attr/sockcreate", gettid());

    sockcreate_fd = open(process_path, O_WRONLY | O_CLOEXEC);
    if (sockcreate_fd == kInvalidFd || write(sockcreate_fd, security_context, context_size) != static_cast<ssize_t>(context_size)) {
        PLOGE("Failed to set socket creation context via fallback path '%s'", process_path);
        return false;
    }

    LOGV("Successfully set socket creation context via fallback: '%s'", security_context);
    return true;
}
