/**
 * @file MitigationEngine.hpp
 * @brief RansomShield EDR Agent — Process Decapitation & Response Engine
 *
 * This module implements the "kill switch" — the immediate response action
 * when the EntropyAnalyzer confirms active encryption on a canary file.
 * It performs a hard, non-negotiable process termination using the lowest-level
 * OS primitives available to prevent the ransomware from encrypting any
 * additional files.
 *
 * Why "Decapitation" Instead of Graceful Termination:
 * ───────────────────────────────────────────────────
 * We use SIGKILL (Linux) / TerminateProcess (Windows) — NOT SIGTERM or
 * WM_CLOSE — because:
 *   1. SIGKILL cannot be caught, blocked, or ignored by the process.
 *      Ransomware that traps SIGTERM will continue encrypting.
 *   2. TerminateProcess bypasses DLL_PROCESS_DETACH handlers, preventing
 *      ransomware from triggering destructive cleanup routines.
 *   3. Every millisecond matters: a fast ransomware can encrypt ~1000 files
 *      per second. Waiting for graceful shutdown is unacceptable.
 *
 * The engine also provides process tree killing to handle ransomware that
 * forks child processes (common in Linux variants) or spawns worker threads
 * via CreateRemoteThread (Windows).
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#ifndef RANSOMSHIELD_MITIGATION_ENGINE_HPP
#define RANSOMSHIELD_MITIGATION_ENGINE_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Result Structures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Outcome of a process termination attempt.
 */
enum class KillResult : std::uint8_t {
    SUCCESS,              ///< Process was successfully terminated.
    PROCESS_NOT_FOUND,    ///< PID does not exist (already dead or invalid).
    PERMISSION_DENIED,    ///< Insufficient privileges (need root/admin).
    SYSTEM_ERROR,         ///< OS-level error during termination.
    SELF_KILL_BLOCKED     ///< Attempted to kill our own agent process.
};

/**
 * @brief Detailed report from a kill operation, used for telemetry.
 */
struct KillReport {
    KillResult              result;          ///< Outcome of the kill attempt.
    std::uint32_t           target_pid;      ///< PID that was targeted.
    std::string             process_name;    ///< Name of the terminated process.
    std::string             process_path;    ///< Full executable path (if resolved).
    std::string             process_user;    ///< User context the process ran under.
    std::uint64_t           timestamp;       ///< Unix epoch of the kill action.
    double                  latency_us;      ///< Microseconds from detection to kill.
    std::vector<std::uint32_t> children_killed; ///< Child PIDs also terminated (tree kill).
    std::string             error_message;   ///< OS error string on failure.
};

/**
 * @brief Information about a running process, gathered for forensics.
 */
struct ProcessInfo {
    std::uint32_t           pid;
    std::uint32_t           ppid;            ///< Parent PID.
    std::string             name;            ///< Process name (comm).
    std::filesystem::path   exe_path;        ///< Full path to the executable.
    std::string             user;            ///< Owning user.
    std::string             cmdline;         ///< Full command line.
    std::uint64_t           start_time;      ///< Process start time (epoch).
};

// ─────────────────────────────────────────────────────────────────────────────
// MitigationEngine Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @class MitigationEngine
 * @brief Executes immediate process termination and forensic data collection.
 *
 * Usage in the detection pipeline:
 *
 *   CanaryEvent fires → EntropyAnalyzer says H(X) ≥ 7.2
 *       → MitigationEngine::kill_process(event.pid)
 *       → RollbackCache::restore(event.filepath)
 *       → Telemetry::send(kill_report)
 *
 * The engine is stateless — each kill operation is independent. This is
 * intentional: we don't want any shared state that could be corrupted by
 * a partially-killed ransomware process.
 */
class MitigationEngine {
public:
    MitigationEngine();
    ~MitigationEngine();

    // Non-copyable, non-movable (stateless, but enforces single-instance pattern).
    MitigationEngine(const MitigationEngine&) = delete;
    MitigationEngine& operator=(const MitigationEngine&) = delete;

    // ── Primary Kill Interface ───────────────────────────────────────────

    /**
     * @brief Immediately terminates a process by PID.
     *
     * This is the primary "decapitation" call. It:
     *   1. Validates the PID (not our own, not PID 0/1).
     *   2. Gathers forensic info (name, path, user) BEFORE killing.
     *   3. Issues the hard kill: SIGKILL (Linux) / TerminateProcess (Windows).
     *   4. Returns a KillReport with the outcome and forensic data.
     *
     * Latency target: < 100μs from call to process death.
     *
     * @param pid  The offending process ID to terminate.
     * @return KillReport with outcome and forensic data.
     */
    KillReport kill_process(std::uint32_t pid);

    /**
     * @brief Terminates a process and all of its descendants (tree kill).
     *
     * Critical for ransomware that forks child processes:
     *   - Linux: Walks /proc to find all processes with ppid == target.
     *   - Windows: Creates a snapshot with CreateToolhelp32Snapshot and
     *     walks the process tree.
     *
     * Children are killed FIRST (leaves → root) to prevent orphan processes
     * from continuing encryption.
     *
     * @param pid  The root process ID of the tree to terminate.
     * @return KillReport with the root kill result and children_killed list.
     */
    KillReport kill_process_tree(std::uint32_t pid);

    // ── Process Inspection ───────────────────────────────────────────────

    /**
     * @brief Gathers forensic information about a running process.
     *
     * This is called BEFORE the kill to capture evidence. After SIGKILL,
     * /proc/<pid>/ vanishes and we lose all forensic data.
     *
     * @param pid  The process to inspect.
     * @return ProcessInfo on success, std::nullopt if process doesn't exist.
     */
    static std::optional<ProcessInfo> inspect_process(std::uint32_t pid);

    /**
     * @brief Finds all child PIDs of a given parent process.
     *
     * @param parent_pid  The parent PID to search for.
     * @return Vector of child PIDs (may be empty).
     */
    static std::vector<std::uint32_t> find_children(std::uint32_t parent_pid);

    // ── Safety Checks ────────────────────────────────────────────────────

    /**
     * @brief Checks whether a PID is safe to kill.
     *
     * Returns false for:
     *   - PID 0 (kernel scheduler)
     *   - PID 1 (init/systemd) on Linux
     *   - Our own agent PID
     *   - csrss.exe, lsass.exe, services.exe on Windows (system-critical)
     *
     * @param pid  The PID to validate.
     * @return true if safe to kill, false if it's a protected process.
     */
    static bool is_safe_to_kill(std::uint32_t pid);

private:
    /// Our own PID, cached at construction to prevent self-kill.
    std::uint32_t self_pid_;

    /**
     * @brief Platform-specific: Execute the hard kill syscall.
     *
     * Linux:   kill(pid, SIGKILL)
     * Windows: OpenProcess(PROCESS_TERMINATE) + TerminateProcess(handle, 1)
     *
     * @param pid  The PID to terminate.
     * @return KillResult indicating outcome.
     */
    static KillResult platform_kill(std::uint32_t pid);

    /** @brief Returns the current Unix epoch timestamp in microseconds. */
    static std::uint64_t current_epoch_us();
};

} // namespace ransomshield

#endif // RANSOMSHIELD_MITIGATION_ENGINE_HPP
