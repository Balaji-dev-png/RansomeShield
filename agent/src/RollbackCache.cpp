/**
 * @file RollbackCache.cpp
 * @brief RansomShield EDR Agent — Copy-on-Write Snapshot Cache Implementation
 *
 * This module provides near-instant file restoration after ransomware encryption.
 * When a canary file is deployed, we cache its pristine content in memory.
 * After the MitigationEngine kills the ransomware process, the RollbackCache
 * writes the original content back to disk, restoring the canary.
 *
 * Restoration is atomic (write-to-temp + rename) to prevent partial writes
 * if the agent itself crashes or is killed during restore.
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#include "RollbackCache.hpp"

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

RollbackCache::RollbackCache(std::size_t max_entries, std::uint64_t ttl_seconds)
    : max_entries_(max_entries)
    , ttl_seconds_(ttl_seconds)
{
    cache_.reserve(max_entries_);
    std::cout << "[RollbackCache] Initialized. Capacity: " << max_entries_
              << " entries, TTL: " << (ttl_seconds_ == 0 ? "unlimited" :
                 std::to_string(ttl_seconds_) + "s") << ".\n";
}

// Move operations: shared_mutex is not movable, so we manually move
// data members and leave the mutex default-constructed.
RollbackCache::RollbackCache(RollbackCache&& other) noexcept
    : max_entries_(other.max_entries_)
    , ttl_seconds_(other.ttl_seconds_)
{
    std::unique_lock lock(other.cache_mutex_);
    cache_ = std::move(other.cache_);
}

RollbackCache& RollbackCache::operator=(RollbackCache&& other) noexcept {
    if (this != &other) {
        std::unique_lock lock1(cache_mutex_);
        std::unique_lock lock2(other.cache_mutex_);
        cache_       = std::move(other.cache_);
        max_entries_ = other.max_entries_;
        ttl_seconds_ = other.ttl_seconds_;
    }
    return *this;
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot Operations
// ─────────────────────────────────────────────────────────────────────────────

bool RollbackCache::snapshot(const std::filesystem::path& filepath) {
    // Read the file content into memory.
    std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        std::cerr << "[RollbackCache] Cannot open file for snapshot: "
                  << filepath << "\n";
        return false;
    }

    auto file_size = static_cast<std::size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> data(file_size);
    ifs.read(reinterpret_cast<char*>(data.data()),
             static_cast<std::streamsize>(file_size));

    if (static_cast<std::size_t>(ifs.gcount()) != file_size) {
        std::cerr << "[RollbackCache] Partial read on: " << filepath << "\n";
        data.resize(static_cast<std::size_t>(ifs.gcount()));
    }

    ifs.close();

    return snapshot_from_buffer(filepath, data.data(), data.size());
}

bool RollbackCache::snapshot_from_buffer(
    const std::filesystem::path& filepath,
    const std::uint8_t* data,
    std::size_t size
) {
    std::string key = make_key(filepath);

    std::unique_lock lock(cache_mutex_);

    // Check capacity — if at max, refuse the entry.
    // (A more sophisticated implementation would use LRU eviction,
    //  but for canary files we should never hit the limit.)
    if (cache_.size() >= max_entries_ && cache_.find(key) == cache_.end()) {
        std::cerr << "[RollbackCache] Cache is full (" << max_entries_
                  << " entries). Cannot snapshot: " << filepath << "\n";
        return false;
    }

    CacheEntry entry{};
    entry.data.assign(data, data + size);
    entry.cached_at = current_epoch();
    entry.restore_count = 0;

    cache_[key] = std::move(entry);

    std::cout << "[RollbackCache] Snapshot cached: " << filepath
              << " (" << size << " bytes).\n";

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Restore Operations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Atomic file restoration strategy:
 *
 *   1. Write pristine content to a TEMPORARY file in the same directory.
 *      Same directory is critical — rename(2) only works within a filesystem.
 *
 *   2. Rename the temp file over the corrupted canary.
 *      On POSIX: rename(2) is atomic at the filesystem level.
 *      On Windows: ReplaceFile() provides similar guarantees.
 *
 * Why atomic?
 *   - If the agent crashes mid-restore, we don't want a half-written file.
 *   - The old (encrypted) file remains intact until the rename succeeds.
 *   - If rename fails, we fall back to direct overwrite (non-atomic but
 *     still restores the content).
 */
RestoreReport RollbackCache::restore(const std::filesystem::path& filepath) {
    double start_us = current_time_us();

    RestoreReport report{};
    report.filepath = filepath;

    std::string key = make_key(filepath);

    // ── Look up the snapshot ────────────────────────────────────────────
    std::unique_lock lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end()) {
        report.result = RestoreResult::SNAPSHOT_NOT_FOUND;
        report.error_message = "No snapshot cached for this path.";
        report.latency_us = current_time_us() - start_us;
        std::cerr << "[RollbackCache] No snapshot found for: " << filepath << "\n";
        return report;
    }

    // Capture snapshot data and metadata while holding the lock.
    const auto& snapshot_data = it->second.data;
    report.bytes_restored = snapshot_data.size();
    report.snapshot_age_sec = current_epoch() - it->second.cached_at;

    // ── Check if the parent directory still exists ──────────────────────
    auto parent = filepath.parent_path();
    if (!std::filesystem::exists(parent)) {
        report.result = RestoreResult::PATH_MISSING;
        report.error_message = "Parent directory no longer exists: " +
                               parent.string();
        report.latency_us = current_time_us() - start_us;
        std::cerr << "[RollbackCache] " << report.error_message << "\n";
        return report;
    }

    // ── Atomic restore: write to temp, then rename ──────────────────────

    // Generate a unique temp filename in the same directory.
    // Using a random suffix to avoid collisions.
    std::random_device rd;
    std::string temp_name = ".ransomshield_restore_" +
                            std::to_string(rd()) + ".tmp";
    std::filesystem::path temp_path = parent / temp_name;

    // Write the pristine content to the temp file.
    {
        std::ofstream ofs(temp_path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            report.result = RestoreResult::PERMISSION_DENIED;
            report.error_message = "Cannot create temp file for restore: " +
                                   temp_path.string();
            report.latency_us = current_time_us() - start_us;
            std::cerr << "[RollbackCache] " << report.error_message << "\n";
            return report;
        }

        ofs.write(reinterpret_cast<const char*>(snapshot_data.data()),
                  static_cast<std::streamsize>(snapshot_data.size()));

        if (ofs.fail()) {
            report.result = RestoreResult::WRITE_FAILED;
            report.error_message = "Failed to write snapshot data to temp file.";
            report.latency_us = current_time_us() - start_us;

            // Clean up the temp file.
            std::error_code ec;
            std::filesystem::remove(temp_path, ec);

            std::cerr << "[RollbackCache] " << report.error_message << "\n";
            return report;
        }

        ofs.flush();
        ofs.close();
    }

    // ── Atomic rename: temp → target ────────────────────────────────────
    {
        std::error_code ec;
        std::filesystem::rename(temp_path, filepath, ec);

        if (ec) {
            // Rename failed — fall back to direct overwrite.
            std::cerr << "[RollbackCache] Atomic rename failed (" << ec.message()
                      << "), falling back to direct overwrite.\n";

            // Remove the temp file.
            std::filesystem::remove(temp_path, ec);

            // Direct overwrite (non-atomic fallback).
            std::ofstream ofs(filepath, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                report.result = RestoreResult::WRITE_FAILED;
                report.error_message = "Both atomic and direct restore failed.";
                report.latency_us = current_time_us() - start_us;
                std::cerr << "[RollbackCache] " << report.error_message << "\n";
                return report;
            }

            ofs.write(reinterpret_cast<const char*>(snapshot_data.data()),
                      static_cast<std::streamsize>(snapshot_data.size()));
            ofs.close();
        }
    }

    // ── Update metadata ─────────────────────────────────────────────────
    it->second.restore_count++;

    report.result = RestoreResult::SUCCESS;
    report.latency_us = current_time_us() - start_us;

    std::cout << "[RollbackCache] ✓ Restored: " << filepath
              << " (" << report.bytes_restored << " bytes, "
              << report.latency_us << "μs, age: "
              << report.snapshot_age_sec << "s).\n";

    return report;
}

const std::vector<std::uint8_t>* RollbackCache::get_snapshot(
    const std::filesystem::path& filepath
) const {
    std::string key = make_key(filepath);

    std::shared_lock lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end()) return nullptr;

    return &it->second.data;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache Management
// ─────────────────────────────────────────────────────────────────────────────

bool RollbackCache::evict(const std::filesystem::path& filepath) {
    std::string key = make_key(filepath);

    std::unique_lock lock(cache_mutex_);
    return cache_.erase(key) > 0;
}

void RollbackCache::clear() {
    std::unique_lock lock(cache_mutex_);
    cache_.clear();
    std::cout << "[RollbackCache] Cache cleared.\n";
}

std::size_t RollbackCache::size() const {
    std::shared_lock lock(cache_mutex_);
    return cache_.size();
}

std::size_t RollbackCache::total_bytes() const {
    std::shared_lock lock(cache_mutex_);

    std::size_t total = 0;
    for (const auto& [key, entry] : cache_) {
        total += entry.data.size();
    }
    return total;
}

std::vector<SnapshotInfo> RollbackCache::get_cache_info() const {
    std::shared_lock lock(cache_mutex_);

    std::vector<SnapshotInfo> infos;
    infos.reserve(cache_.size());

    for (const auto& [key, entry] : cache_) {
        SnapshotInfo info{};
        info.filepath = key;
        info.size_bytes = entry.data.size();
        info.cached_at = entry.cached_at;
        info.restore_count = entry.restore_count;
        infos.push_back(std::move(info));
    }

    return infos;
}

std::size_t RollbackCache::evict_expired() {
    if (ttl_seconds_ == 0) return 0;  // No expiry configured.

    std::unique_lock lock(cache_mutex_);

    auto now = current_epoch();
    std::size_t evicted = 0;

    for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (now - it->second.cached_at > ttl_seconds_) {
            std::cout << "[RollbackCache] Evicting expired snapshot: "
                      << it->first << "\n";
            it = cache_.erase(it);
            ++evicted;
        } else {
            ++it;
        }
    }

    return evicted;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Utilities
// ─────────────────────────────────────────────────────────────────────────────

std::string RollbackCache::make_key(const std::filesystem::path& filepath) {
    // Canonicalize for consistent keys. If canonicalization fails
    // (file doesn't exist yet or was deleted), use the raw path.
    std::error_code ec;
    auto canonical = std::filesystem::canonical(filepath, ec);
    if (ec) {
        // Fallback: use absolute path without resolving symlinks.
        return std::filesystem::absolute(filepath).string();
    }
    return canonical.string();
}

std::uint64_t RollbackCache::current_epoch() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

double RollbackCache::current_time_us() {
    return static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()
        ).count()
    );
}

} // namespace ransomshield
