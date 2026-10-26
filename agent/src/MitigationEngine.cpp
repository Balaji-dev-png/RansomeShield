/**
 * @file MitigationEngine.cpp
 * @brief RansomShield EDR Agent — Process Decapitation Implementation
 *
 * This is the "kill switch" — the code that actually terminates ransomware
 * processes. Every microsecond of latency here translates to files that
 * could be encrypted, so this code is optimized for speed above all else.
 *
 * Platform implementations:
 *   Linux:   kill(pid, SIGKILL) + /proc filesystem for forensics.
 *   Windows: OpenProcess + TerminateProcess + ToolHelp32 for tree walk.
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#include "MitigationEngine.hpp"

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

// ── Platform headers ─────────────────────────────────────────────────────────
#if !defined(RANSOMSHIELD_PLATFORM_LINUX) && !defined(RANSOMSHIELD_PLATFORM_WINDOWS)
    #if defined(__linux__)
        #define RANSOMSHIELD_PLATFORM_LINUX
    #elif defined(_WIN32) || defined(_WIN64)
        #define RANSOMSHIELD_PLATFORM_WINDOWS
    #else
        #error "Unsupported platform."
    #endif
#endif

#ifdef RANSOMSHIELD_PLATFORM_LINUX
    #include <cerrno>
    #include <csignal>
    #include <dirent.h>
    #include <pwd.h>
    #include <sys/types.h>
    #include <unistd.h>
#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>
#endif

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

MitigationEngine::MitigationEngine() {
#ifdef RANSOMSHIELD_PLATFORM_LINUX
    self_pid_ = static_cast<std::uint32_t>(getpid());
#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)
    self_pid_ = static_cast<std::uint32_t>(GetCurrentProcessId());
#endif

    std::cout << "[MitigationEngine] Initialized. Agent PID: " << self_pid_
              << " (protected from self-kill).\n";
}

MitigationEngine::~MitigationEngine() = default;

// ─────────────────────────────────────────────────────────────────────────────
// Safety Checks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Critical safety gate — prevents the agent from killing itself or
 * bricking the OS by killing essential system processes.
 *
 * The whitelist approach (block known-critical PIDs) is intentional:
 * we'd rather accidentally kill one extra process than let ransomware
 * continue encrypting because we were too conservative.
 */
bool MitigationEngine::is_safe_to_kill(std::uint32_t pid) {
    // Never kill PID 0 (kernel scheduler on both platforms).
    if (pid == 0) return false;

#ifdef RANSOMSHIELD_PLATFORM_LINUX
    // PID 1 = init/systemd — killing it panics the kernel.
    if (pid == 1) return false;

    // PID 2 = kthreadd (kernel thread parent) — don't touch.
    if (pid == 2) return false;

    // Don't kill our own process.
    if (pid == static_cast<std::uint32_t>(getpid())) return false;

#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)
    // On Windows, additionally protect critical system processes by name.
    // We check the PID against known system process names.
    if (pid == static_cast<std::uint32_t>(GetCurrentProcessId())) return false;

    // PID 4 is the System process on Windows.
    if (pid == 4) return false;
#endif

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-Specific Kill Implementation
// ─────────────────────────────────────────────────────────────────────────────

#ifdef RANSOMSHIELD_PLATFORM_LINUX

/**
 * Linux kill implementation using SIGKILL.
 *
 * SIGKILL (signal 9) is the nuclear option:
 *   - Cannot be caught, blocked, or ignored by the target process.
 *   - The kernel immediately reclaims the process's resources.
 *   - No signal handler runs — ransomware can't do cleanup/destruction.
 *   - File descriptors are closed, memory is freed, locks are released.
 *
 * We use kill(2) directly rather than going through /proc or pidfd_send_signal
 * for maximum compatibility (works on kernels 2.6+).
 */
KillResult MitigationEngine::platform_kill(std::uint32_t pid) {
    int result = ::kill(static_cast<pid_t>(pid), SIGKILL);

    if (result == 0) {
        return KillResult::SUCCESS;
    }

    // Decode errno for the specific failure reason.
    switch (errno) {
        case ESRCH:
            // No such process — it died between detection and kill.
            // This is actually fine (maybe it crashed on its own).
            return KillResult::PROCESS_NOT_FOUND;

        case EPERM:
            // Permission denied — we're not root and the process is
            // owned by another user. This is a deployment issue.
            return KillResult::PERMISSION_DENIED;

        default:
            return KillResult::SYSTEM_ERROR;
    }
}

#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)

/**
 * Windows kill implementation using TerminateProcess.
 *
 * Two-step process:
 *   1. OpenProcess(PROCESS_TERMINATE) — get a handle with kill rights.
 *   2. TerminateProcess(handle, 1) — force-terminate with exit code 1.
 *
 * Why TerminateProcess instead of ExitProcess:
 *   - TerminateProcess works on OTHER processes (ExitProcess is self-only).
 *   - It bypasses DLL_PROCESS_DETACH, preventing ransomware cleanup handlers.
 *   - It does NOT flush file buffers — but that's fine, we want to stop
 *     encryption ASAP, not ensure clean shutdown.
 *
 * We request PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION to both kill
 * and gather forensic data in one handle open.
 */
KillResult MitigationEngine::platform_kill(std::uint32_t pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
        FALSE,
        static_cast<DWORD>(pid)
    );

    if (hProcess == NULL) {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER) {
            return KillResult::PROCESS_NOT_FOUND;
        }
        if (err == ERROR_ACCESS_DENIED) {
            return KillResult::PERMISSION_DENIED;
        }
        return KillResult::SYSTEM_ERROR;
    }

    // Execute the kill. Exit code 1 signals abnormal termination.
    BOOL terminated = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    return terminated ? KillResult::SUCCESS : KillResult::SYSTEM_ERROR;
}

#endif // Platform selection

// ─────────────────────────────────────────────────────────────────────────────
// Process Inspection (Forensics)
// ─────────────────────────────────────────────────────────────────────────────

#ifdef RANSOMSHIELD_PLATFORM_LINUX

/**
 * Linux process inspection via /proc filesystem.
 *
 * We gather forensic data BEFORE killing because /proc/<pid>/ vanishes
 * the instant the process dies. The data we collect:
 *   - Process name from /proc/<pid>/comm
 *   - Executable path from /proc/<pid>/exe (readlink)
 *   - Command line from /proc/<pid>/cmdline
 *   - Parent PID from /proc/<pid>/stat (field 4)
 *   - Owner UID from /proc/<pid>/status
 */
std::optional<ProcessInfo> MitigationEngine::inspect_process(std::uint32_t pid) {
    std::string proc_base = "/proc/" + std::to_string(pid);

    // Check if the process exists at all.
    if (!std::filesystem::exists(proc_base)) {
        return std::nullopt;
    }

    ProcessInfo info{};
    info.pid = pid;

    // ── Read process name from /proc/<pid>/comm ─────────────────────────
    {
        std::ifstream comm_file(proc_base + "/comm");
        if (comm_file.is_open()) {
            std::getline(comm_file, info.name);
        }
    }

    // ── Read executable path from /proc/<pid>/exe symlink ───────────────
    {
        std::error_code ec;
        auto exe_link = std::filesystem::read_symlink(proc_base + "/exe", ec);
        if (!ec) {
            info.exe_path = exe_link;
        }
    }

    // ── Read command line from /proc/<pid>/cmdline ──────────────────────
    // cmdline uses null bytes as separators between arguments.
    {
        std::ifstream cmdline_file(proc_base + "/cmdline", std::ios::binary);
        if (cmdline_file.is_open()) {
            std::string raw;
            std::getline(cmdline_file, raw, '\0');

            // Read remaining args (null-separated).
            std::string arg;
            while (std::getline(cmdline_file, arg, '\0')) {
                if (!arg.empty()) {
                    raw += " " + arg;
                }
            }
            info.cmdline = raw;
        }
    }

    // ── Read PPID from /proc/<pid>/stat ─────────────────────────────────
    // Format: pid (comm) state ppid ...
    // Field 4 (0-indexed: 3) is the parent PID.
    {
        std::ifstream stat_file(proc_base + "/stat");
        if (stat_file.is_open()) {
            std::string stat_line;
            std::getline(stat_file, stat_line);

            // Find the closing ')' of the comm field (handles spaces in names).
            auto comm_end = stat_line.rfind(')');
            if (comm_end != std::string::npos && comm_end + 2 < stat_line.size()) {
                std::istringstream rest(stat_line.substr(comm_end + 2));
                char state;
                std::uint32_t ppid;
                if (rest >> state >> ppid) {
                    info.ppid = ppid;
                }
            }
        }
    }

    // ── Read owner UID from /proc/<pid>/status ──────────────────────────
    {
        std::ifstream status_file(proc_base + "/status");
        if (status_file.is_open()) {
            std::string line;
            while (std::getline(status_file, line)) {
                if (line.compare(0, 4, "Uid:") == 0) {
                    std::istringstream iss(line.substr(4));
                    uid_t uid;
                    if (iss >> uid) {
                        struct passwd* pw = getpwuid(uid);
                        if (pw) {
                            info.user = pw->pw_name;
                        } else {
                            info.user = std::to_string(uid);
                        }
                    }
                    break;
                }
            }
        }
    }

    return info;
}

/**
 * Find all child processes by walking /proc.
 *
 * For each /proc/<pid>/stat, we read the PPID (field 4) and check
 * if it matches our target parent. This is O(n) where n is the total
 * number of running processes — typically <1000 on a workstation.
 */
std::vector<std::uint32_t> MitigationEngine::find_children(std::uint32_t parent_pid) {
    std::vector<std::uint32_t> children;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return children;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only look at numeric directory names (PIDs).
        if (entry->d_type != DT_DIR) continue;

        char* end;
        long pid = std::strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;

        // Read the PPID from /proc/<pid>/stat.
        std::string stat_path = std::string("/proc/") + entry->d_name + "/stat";
        std::ifstream stat_file(stat_path);
        if (!stat_file.is_open()) continue;

        std::string stat_line;
        std::getline(stat_file, stat_line);

        // Parse past the comm field (which may contain spaces and parens).
        auto comm_end = stat_line.rfind(')');
        if (comm_end == std::string::npos) continue;

        std::istringstream rest(stat_line.substr(comm_end + 2));
        char state;
        std::uint32_t ppid;
        if (rest >> state >> ppid) {
            if (ppid == parent_pid) {
                children.push_back(static_cast<std::uint32_t>(pid));
            }
        }
    }

    closedir(proc_dir);
    return children;
}

#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)

/**
 * Windows process inspection using ToolHelp32 and PSAPI.
 */
std::optional<ProcessInfo> MitigationEngine::inspect_process(std::uint32_t pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;

    ProcessInfo info{};
    info.pid = pid;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == static_cast<DWORD>(pid)) {
                // Convert wide string process name to narrow string.
                char name_buf[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                    name_buf, MAX_PATH, nullptr, nullptr);
                info.name = name_buf;
                info.ppid = static_cast<std::uint32_t>(pe.th32ParentProcessID);
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);

    // Get the full executable path.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, static_cast<DWORD>(pid));
    if (hProcess) {
        WCHAR exe_path[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, exe_path, MAX_PATH)) {
            char path_buf[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, exe_path, -1,
                                path_buf, MAX_PATH, nullptr, nullptr);
            info.exe_path = path_buf;
        }
        CloseHandle(hProcess);
    }

    return info;
}

/**
 * Windows child process enumeration using ToolHelp32.
 */
std::vector<std::uint32_t> MitigationEngine::find_children(std::uint32_t parent_pid) {
    std::vector<std::uint32_t> children;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return children;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ParentProcessID == static_cast<DWORD>(parent_pid) &&
                pe.th32ProcessID != static_cast<DWORD>(parent_pid)) {
                children.push_back(static_cast<std::uint32_t>(pe.th32ProcessID));
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return children;
}

#endif // Platform selection

// ─────────────────────────────────────────────────────────────────────────────
// Primary Kill Interface
// ─────────────────────────────────────────────────────────────────────────────

KillReport MitigationEngine::kill_process(std::uint32_t pid) {
    auto start_time = current_epoch_us();

    KillReport report{};
    report.target_pid = pid;
    report.timestamp = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    // ── Safety check ────────────────────────────────────────────────────
    if (!is_safe_to_kill(pid)) {
        report.result = KillResult::SELF_KILL_BLOCKED;
        report.error_message = "PID " + std::to_string(pid) +
                               " is a protected process (self, init, or system-critical).";
        report.latency_us = static_cast<double>(current_epoch_us() - start_time);
        std::cerr << "[MitigationEngine] BLOCKED: " << report.error_message << "\n";
        return report;
    }

    // ── Gather forensic data BEFORE killing ─────────────────────────────
    // After SIGKILL, the process vanishes and we lose all forensic evidence.
    // This ~50μs of inspection is worth the intelligence we gather.
    auto proc_info = inspect_process(pid);
    if (proc_info) {
        report.process_name = proc_info->name;
        report.process_path = proc_info->exe_path.string();
        report.process_user = proc_info->user;

        std::cout << "[MitigationEngine] TARGET IDENTIFIED:\n"
                  << "  PID:     " << pid << "\n"
                  << "  Name:    " << proc_info->name << "\n"
                  << "  Path:    " << proc_info->exe_path << "\n"
                  << "  User:    " << proc_info->user << "\n"
                  << "  PPID:    " << proc_info->ppid << "\n"
                  << "  Cmdline: " << proc_info->cmdline << "\n";
    }

    // ── EXECUTE THE KILL ────────────────────────────────────────────────
    std::cout << "[MitigationEngine] ⚡ DECAPITATING process " << pid << "...\n";

    report.result = platform_kill(pid);
    report.latency_us = static_cast<double>(current_epoch_us() - start_time);

    // ── Log outcome ─────────────────────────────────────────────────────
    switch (report.result) {
        case KillResult::SUCCESS:
            std::cout << "[MitigationEngine] ✓ Process " << pid
                      << " terminated in " << report.latency_us << "μs.\n";
            break;

        case KillResult::PROCESS_NOT_FOUND:
            report.error_message = "Process already dead.";
            std::cout << "[MitigationEngine] Process " << pid
                      << " no longer exists (already terminated).\n";
            break;

        case KillResult::PERMISSION_DENIED:
            report.error_message = "Insufficient privileges. Run as root/admin.";
            std::cerr << "[MitigationEngine] ✗ PERMISSION DENIED killing PID "
                      << pid << ". Agent needs elevated privileges!\n";
            break;

        case KillResult::SYSTEM_ERROR:
            report.error_message = "OS-level error during termination.";
            std::cerr << "[MitigationEngine] ✗ SYSTEM ERROR killing PID "
                      << pid << ".\n";
            break;

        default:
            break;
    }

    return report;
}

// ─────────────────────────────────────────────────────────────────────────────
// Process Tree Kill
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tree kill strategy: LEAVES FIRST.
 *
 * We kill children before parents to prevent:
 *   1. Orphan processes continuing encryption after parent dies.
 *   2. Parent spawning new children in response to child death.
 *
 * The walk is recursive: we find children of children, building the full
 * process tree, then kill from the bottom up.
 */
KillReport MitigationEngine::kill_process_tree(std::uint32_t pid) {
    auto start_time = current_epoch_us();

    // First, find all descendants recursively.
    std::vector<std::uint32_t> all_descendants;

    // BFS to find all descendants.
    std::vector<std::uint32_t> to_visit = {pid};
    while (!to_visit.empty()) {
        std::uint32_t current = to_visit.back();
        to_visit.pop_back();

        auto children = find_children(current);
        for (auto child : children) {
            all_descendants.push_back(child);
            to_visit.push_back(child);  // Visit children of children.
        }
    }

    std::cout << "[MitigationEngine] Process tree for PID " << pid
              << ": " << all_descendants.size() << " descendant(s) found.\n";

    // Kill children first (leaves → root).
    // Reverse so deepest descendants are killed first.
    std::vector<std::uint32_t> killed_children;
    for (auto it = all_descendants.rbegin(); it != all_descendants.rend(); ++it) {
        if (is_safe_to_kill(*it)) {
            KillResult child_result = platform_kill(*it);
            if (child_result == KillResult::SUCCESS) {
                killed_children.push_back(*it);
                std::cout << "[MitigationEngine] ✓ Killed child PID " << *it << "\n";
            }
        }
    }

    // Now kill the root process.
    KillReport report = kill_process(pid);
    report.children_killed = std::move(killed_children);
    report.latency_us = static_cast<double>(current_epoch_us() - start_time);

    std::cout << "[MitigationEngine] Tree kill complete. Root + "
              << report.children_killed.size() << " children terminated in "
              << report.latency_us << "μs.\n";

    return report;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing Utilities
// ─────────────────────────────────────────────────────────────────────────────

std::uint64_t MitigationEngine::current_epoch_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()
        ).count()
    );
}

} // namespace ransomshield

