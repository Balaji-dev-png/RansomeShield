/**
 * @file RollbackCache.hpp
 * @brief RansomShield EDR Agent — Copy-on-Write Micro-Snapshot Cache
 *
 * This module implements a rolling in-memory snapshot cache for canary files.
 * When the CanaryManager deploys canaries, the RollbackCache stores a pristine
 * copy of each canary's content. If ransomware encrypts a canary and gets
 * killed, the RollbackCache restores the original file from memory — achieving
 * near-instant recovery without relying on disk-based backups.
 *
 * Copy-on-Write Design:
 * ─────────────────────
 * The cache holds the ORIGINAL content of each canary (the "pristine snapshot").
 * When a FILE_MODIFY event fires on a canary:
 *   1. The modified data is read from disk for entropy analysis.
 *   2. If encryption is detected → process is killed.
 *   3. The pristine snapshot is written back to disk, restoring the canary.
 *   4. The canary is re-armed and continues monitoring.
 *
 * This is NOT a general-purpose backup system. It only protects canary files
 * (which are small, ~4KB each). The total memory footprint for 270 canaries
 * is ~1.1MB — negligible for an EDR agent.
 *
 * Memory Management:
 * ──────────────────
 * - Snapshots are stored as contiguous byte vectors (cache-friendly).
 * - The cache uses a hash map for O(1) lookup by file path.
 * - A configurable TTL can age out entries for long-running deployments.
 * - Thread-safe for concurrent access from monitoring and restore threads.
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#ifndef RANSOMSHIELD_ROLLBACK_CACHE_HPP
#define RANSOMSHIELD_ROLLBACK_CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Result Structures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Outcome of a file restoration attempt.
 */
enum class RestoreResult : std::uint8_t {
    SUCCESS,              ///< File was successfully restored from cache.
    SNAPSHOT_NOT_FOUND,   ///< No snapshot exists for this file path.
    WRITE_FAILED,         ///< Could not write the restored file to disk.
    PERMISSION_DENIED,    ///< Insufficient permissions to write to the path.
    PATH_MISSING          ///< Parent directory no longer exists.
};

/**
 * @brief Detailed report from a restore operation, used for telemetry.
 */
struct RestoreReport {
    RestoreResult           result;            ///< Outcome of the restore.
    std::filesystem::path   filepath;          ///< Path that was restored.
    std::size_t             bytes_restored;    ///< Number of bytes written.
    std::uint64_t           snapshot_age_sec;  ///< Age of the snapshot in seconds.
    double                  latency_us;        ///< Microseconds to complete restore.
    std::string             error_message;     ///< Error detail on failure.
};

/**
 * @brief Metadata about a cached snapshot.
 */
struct SnapshotInfo {
    std::filesystem::path   filepath;
    std::size_t             size_bytes;
    std::uint64_t           cached_at;        ///< Unix epoch when snapshot was taken.
    std::uint32_t           restore_count;    ///< How many times this snapshot was restored.
};

// ─────────────────────────────────────────────────────────────────────────────
// RollbackCache Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @class RollbackCache
 * @brief In-memory pristine snapshot cache for canary file restoration.
 *
 * Usage flow:
 *
 *   1. CanaryManager::deploy_canaries()
 *      → RollbackCache::snapshot(path)           // Cache pristine copy
 *
 *   2. Canary event fires → entropy ≥ 7.2
 *      → MitigationEngine::kill_process(pid)     // Kill ransomware
 *      → RollbackCache::restore(path)            // Restore canary
 *
 *   3. Canary is re-armed automatically (content is back to pristine).
 *
 * Thread safety: All public methods are thread-safe. The cache uses a
 * shared_mutex (readers-writer lock) to allow concurrent lookups from
 * multiple monitoring threads while serializing writes.
 */
class RollbackCache {
public:
    // ── Construction ─────────────────────────────────────────────────────

    /**
     * @brief Constructs the RollbackCache.
     * @param max_entries    Maximum number of snapshots to hold. Default 1024.
     * @param ttl_seconds    Time-to-live for snapshots. 0 = no expiry (default).
     */
    explicit RollbackCache(
        std::size_t max_entries = 1024,
        std::uint64_t ttl_seconds = 0
    );

    ~RollbackCache() = default;

    // Non-copyable (owns cache data).
    RollbackCache(const RollbackCache&) = delete;
    RollbackCache& operator=(const RollbackCache&) = delete;

    // Movable.
    RollbackCache(RollbackCache&&) noexcept;
    RollbackCache& operator=(RollbackCache&&) noexcept;

    // ── Snapshot Operations ──────────────────────────────────────────────

    /**
     * @brief Takes a pristine snapshot of a file and stores it in the cache.
     *
     * Reads the file contents into memory. Should be called immediately
     * after deploying a canary file (before any attacker can modify it).
     *
     * @param filepath  Path to the file to snapshot.
     * @return true if the snapshot was successfully taken and cached.
     */
    bool snapshot(const std::filesystem::path& filepath);

    /**
     * @brief Stores a pre-read buffer as the snapshot for a given path.
     *
     * Used when the canary content is already in memory (e.g., right after
     * CanaryManager::write_canary_file generated the content).
     *
     * @param filepath  The file path this snapshot belongs to.
     * @param data      The pristine file content.
     * @param size      Number of bytes.
     * @return true if successfully cached.
     */
    bool snapshot_from_buffer(
        const std::filesystem::path& filepath,
        const std::uint8_t* data,
        std::size_t size
    );

    // ── Restore Operations ───────────────────────────────────────────────

    /**
     * @brief Restores a canary file from its cached pristine snapshot.
     *
     * Writes the cached content back to disk, overwriting whatever the
     * ransomware wrote. After restore, the canary is back to its original
     * state and ready to trip again.
     *
     * The restore is atomic on supported platforms:
     *   - Writes to a temporary file in the same directory.
     *   - Renames the temp file over the target (atomic on POSIX).
     *   - On Windows, uses ReplaceFile() for similar atomicity.
     *
     * @param filepath  Path to restore.
     * @return RestoreReport with outcome details.
     */
    RestoreReport restore(const std::filesystem::path& filepath);

    /**
     * @brief Retrieves the cached snapshot data without restoring to disk.
     *
     * Useful for the EntropyAnalyzer to compare original vs. modified content,
     * or for telemetry to report what changed.
     *
     * @param filepath  Path to look up.
     * @return Pointer to the cached byte vector, or nullptr if not cached.
     *         The pointer is valid until the entry is evicted or the cache
     *         is destroyed. Caller must hold no locks.
     */
    const std::vector<std::uint8_t>* get_snapshot(
        const std::filesystem::path& filepath
    ) const;

    // ── Cache Management ─────────────────────────────────────────────────

    /**
     * @brief Removes a snapshot from the cache.
     * @param filepath  Path to evict.
     * @return true if the entry existed and was removed.
     */
    bool evict(const std::filesystem::path& filepath);

    /** @brief Removes all snapshots from the cache. */
    void clear();

    /** @brief Returns the number of snapshots currently cached. */
    std::size_t size() const;

    /** @brief Returns total bytes consumed by all cached snapshots. */
    std::size_t total_bytes() const;

    /** @brief Returns metadata for all cached snapshots (for telemetry). */
    std::vector<SnapshotInfo> get_cache_info() const;

    /**
     * @brief Evicts snapshots that have exceeded their TTL.
     *
     * Called periodically by the agent's maintenance loop. No-op if
     * ttl_seconds was set to 0 (no expiry).
     *
     * @return Number of entries evicted.
     */
    std::size_t evict_expired();

private:
    /**
     * @brief Internal snapshot entry stored in the cache.
     */
    struct CacheEntry {
        std::vector<std::uint8_t> data;           ///< Pristine file content.
        std::uint64_t             cached_at;      ///< Unix epoch of snapshot.
        std::uint32_t             restore_count;  ///< Number of restorations.
    };

    /// Cache storage: canonical path string → CacheEntry.
    std::unordered_map<std::string, CacheEntry> cache_;

    /// Readers-writer lock for concurrent access.
    mutable std::shared_mutex cache_mutex_;

    /// Maximum number of entries before LRU eviction.
    std::size_t max_entries_;

    /// Time-to-live in seconds (0 = no expiry).
    std::uint64_t ttl_seconds_;

    /** @brief Canonicalizes a path to a stable string key. */
    static std::string make_key(const std::filesystem::path& filepath);

    /** @brief Returns the current Unix epoch in seconds. */
    static std::uint64_t current_epoch();

    /** @brief Returns the current time in microseconds (for latency measurement). */
    static double current_time_us();
};

} // namespace ransomshield

#endif // RANSOMSHIELD_ROLLBACK_CACHE_HPP

