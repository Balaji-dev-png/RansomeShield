/**
 * @file CanaryManager.hpp
 * @brief RansomShield EDR Agent — Canary File Deployment & Monitoring Manager
 *
 * This header defines the CanaryManager class, the core component responsible for:
 *   1. Deploying multi-tier honeypot "canary" decoy files across standard user
 *      directories (Documents, Downloads, Desktop) on both Linux and Windows.
 *   2. Using a dual-naming strategy with zero-indexed lured extensions that trap
 *      both sequential (ascending) and randomized directory traversal patterns
 *      commonly used by ransomware families.
 *   3. Providing a cross-platform monitoring abstraction layer with platform-specific
 *      hooks (eBPF on Linux, ETW on Windows) that watch for FILE_WRITE/FILE_MODIFY
 *      events on deployed canary files.
 *
 * Design Philosophy:
 *   - The core logic (canary generation, naming strategy, manifest tracking) is
 *     entirely cross-platform using C++17 <filesystem>.
 *   - Platform-specific monitoring is isolated behind a clean interface, with
 *     concrete implementations in platform/{linux,windows}/ translation units.
 *   - Every deployed canary is tracked in an in-memory manifest (hash map) for
 *     O(1) lookup when a filesystem event fires, enabling the entropy analysis
 *     pipeline to kick in immediately without a directory scan.
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#ifndef RANSOMSHIELD_CANARY_MANAGER_HPP
#define RANSOMSHIELD_CANARY_MANAGER_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Metadata record for a single deployed canary file.
 *
 * Every canary we drop on disk gets one of these entries in the in-memory
 * manifest. When a filesystem event fires on a watched path, we do an O(1)
 * lookup into the manifest to confirm it's a canary and pull its metadata
 * for telemetry reporting.
 */
struct CanaryRecord {
    std::filesystem::path filepath;       ///< Absolute path to the canary file.
    std::string           extension;      ///< Original lured extension (e.g., ".docx").
    std::string           naming_tier;    ///< "alpha_first" | "alpha_last" | "numeric" — which naming tier was used.
    std::uint64_t         deployed_at;    ///< Unix epoch timestamp of deployment.
    std::uint64_t         file_size;      ///< Size in bytes of the canary content.
    bool                  tripped;        ///< True if this canary has been accessed/modified.
};

/**
 * @brief Filesystem event types the monitoring layer can report.
 *
 * These map to the underlying OS primitives:
 *   - Linux  (eBPF / fanotify):  FAN_MODIFY, FAN_CLOSE_WRITE
 *   - Windows (ETW):             FileIo Write, FileIo SetInfo
 */
enum class FileEventType : std::uint8_t {
    FILE_WRITE  = 0x01,   ///< Data was written to the file.
    FILE_MODIFY = 0x02,   ///< File metadata or content was modified.
    FILE_RENAME = 0x04,   ///< File was renamed (common ransomware behavior).
    FILE_DELETE = 0x08    ///< File was deleted.
};

/**
 * @brief Payload delivered to the callback when a canary event is detected.
 */
struct CanaryEvent {
    FileEventType         event_type;     ///< What happened to the canary.
    std::filesystem::path filepath;       ///< Which canary was touched.
    std::uint32_t         pid;            ///< PID of the offending process.
    std::string           process_name;   ///< Name/path of the offending process.
    std::uint64_t         timestamp;      ///< Unix epoch when the event was captured.
};

/**
 * @brief Callback signature invoked when a canary file event is detected.
 *
 * The entropy analysis engine will register a callback matching this signature.
 * When a canary event fires, CanaryManager invokes this callback, passing the
 * event to the detection pipeline (entropy calculation → process kill → restore).
 */
using CanaryEventCallback = std::function<void(const CanaryEvent&)>;

// ─────────────────────────────────────────────────────────────────────────────
// CanaryManager Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @class CanaryManager
 * @brief Deploys, tracks, and monitors honeypot canary files across the filesystem.
 *
 * Lifecycle:
 *   1. Construct → configure target directories and naming tiers.
 *   2. deploy_canaries() → drops decoy files to disk and populates the manifest.
 *   3. start_monitoring() → activates OS-specific hooks on deployed canary paths.
 *   4. [runtime] → callbacks fire when ransomware touches a canary.
 *   5. stop_monitoring() → tears down hooks.
 *   6. cleanup_canaries() → removes decoy files from disk (graceful shutdown).
 */
class CanaryManager {
public:
    // ── Construction & Configuration ─────────────────────────────────────

    /**
     * @brief Constructs the CanaryManager.
     * @param custom_dirs  Optional additional directories to deploy canaries into,
     *                     beyond the standard Documents/Downloads/Desktop set.
     */
    explicit CanaryManager(
        std::vector<std::filesystem::path> custom_dirs = {}
    );

    /// Non-copyable (owns OS monitoring handles).
    CanaryManager(const CanaryManager&) = delete;
    CanaryManager& operator=(const CanaryManager&) = delete;

    /// Movable.
    CanaryManager(CanaryManager&&) noexcept;
    CanaryManager& operator=(CanaryManager&&) noexcept;

    ~CanaryManager();

    // ── Canary Deployment ────────────────────────────────────────────────

    /**
     * @brief Deploys all canary files across target directories.
     *
     * For each target directory, this drops canaries using three naming tiers:
     *   - Alpha-First:  Names starting with '_00_', '!_', 'AAA_' to appear at
     *                   the top of ascending-sort directory listings.
     *   - Alpha-Last:   Names starting with 'ZZ_', 'zzz_', '~~~' to appear at
     *                   the bottom, trapping descending traversals.
     *   - Numeric:      Names like '000_', '999_' to catch numeric-sort traversals.
     *
     * Each tier uses high-value lured extensions (.docx, .xlsx, .pdf, .txt,
     * .jpg, .png, .key, .pem, .sql, .csv) that ransomware families prioritize.
     *
     * @return Number of canary files successfully deployed.
     */
    std::size_t deploy_canaries();

    /**
     * @brief Removes all deployed canary files from disk.
     * @return Number of canary files successfully removed.
     */
    std::size_t cleanup_canaries();

    /**
     * @brief Checks if a given path is a tracked canary file.
     * @param path  The filesystem path to check.
     * @return Pointer to the CanaryRecord if it's a canary, nullptr otherwise.
     *
     * Thread-safe. Used by the entropy analysis pipeline when a filesystem
     * event fires to confirm the target is one of our honeypots.
     */
    const CanaryRecord* lookup_canary(const std::filesystem::path& path) const;

    /**
     * @brief Returns a snapshot of all deployed canary records.
     *
     * Used for telemetry reporting — the agent sends the full canary manifest
     * to the backend on startup so the SOC dashboard knows what's deployed.
     */
    std::vector<CanaryRecord> get_manifest() const;

    /**
     * @brief Returns the number of currently deployed canaries.
     */
    std::size_t canary_count() const;

    // ── Monitoring (Platform-Specific) ───────────────────────────────────

    /**
     * @brief Registers a callback for canary file events.
     *
     * This callback is invoked on the monitoring thread when a FILE_WRITE
     * or FILE_MODIFY event is detected on any deployed canary file.
     * The callback should be lightweight — heavy processing (entropy calc,
     * process kill) should be dispatched to a worker thread.
     *
     * @param callback  The function to invoke on canary events.
     */
    void register_event_callback(CanaryEventCallback callback);

    /**
     * @brief Starts the platform-specific filesystem monitoring.
     *
     * On Linux:   Sets up eBPF programs (or falls back to fanotify) to watch
     *             for write/modify events on canary inodes.
     * On Windows: Starts an ETW trace session monitoring FileIo events
     *             filtered to canary file paths.
     *
     * This is non-blocking — monitoring runs on a dedicated background thread.
     *
     * @return true if monitoring was successfully started.
     */
    bool start_monitoring();

    /**
     * @brief Stops the filesystem monitoring and tears down OS hooks.
     */
    void stop_monitoring();

    /**
     * @brief Returns true if the monitoring loop is currently active.
     */
    bool is_monitoring() const;

private:
    // ── Internal Helpers ─────────────────────────────────────────────────

    /**
     * @brief Resolves the standard user directories for the current platform.
     *
     * Linux:   ~/Documents, ~/Downloads, ~/Desktop
     * Windows: %USERPROFILE%\Documents, %USERPROFILE%\Downloads, %USERPROFILE%\Desktop
     *
     * Directories that don't exist are skipped (not created — we don't want
     * to modify the user's filesystem layout beyond dropping canaries).
     */
    std::vector<std::filesystem::path> resolve_target_directories() const;

    /**
     * @brief Generates the canary filenames for a given naming tier.
     *
     * @param tier  One of "alpha_first", "alpha_last", "numeric".
     * @return Vector of filename stems (without directory path).
     */
    std::vector<std::string> generate_canary_names(const std::string& tier) const;

    /**
     * @brief Writes a single canary file to disk with realistic-looking content.
     *
     * The content is not random garbage — it's structured to look like a
     * legitimate file of the given type. This is important because some
     * advanced ransomware families check magic bytes before encrypting.
     *
     * @param filepath   Full path where the canary will be written.
     * @param extension  The file extension (determines content type).
     * @return true if the file was written successfully.
     */
    bool write_canary_file(const std::filesystem::path& filepath,
                           const std::string& extension);

    /**
     * @brief Generates realistic file content based on the extension type.
     *
     * Returns content with valid magic bytes / headers for the file type:
     *   - .docx/.xlsx → ZIP local file header (PK\x03\x04)
     *   - .pdf        → %PDF-1.7 header
     *   - .txt/.csv   → Plausible text data
     *   - .jpg         → JFIF header bytes
     *   - .png         → PNG signature bytes
     *   - .key/.pem   → PEM-like header structure
     *   - .sql         → SQL-looking statements
     *
     * @param extension  The target file extension.
     * @return Vector of bytes representing the file content.
     */
    std::vector<std::uint8_t> generate_content(const std::string& extension) const;

    /**
     * @brief Returns the current Unix epoch timestamp in seconds.
     */
    static std::uint64_t current_epoch();

    // ── Platform-Specific Monitoring (implemented in platform/ TUs) ─────

    /**
     * @brief Platform-specific: Initialize monitoring subsystem.
     *
     * Linux:   Loads eBPF programs, attaches to tracepoints / kprobes.
     * Windows: Creates an ETW trace session with FileIo provider.
     */
    bool platform_init_monitoring();

    /**
     * @brief Platform-specific: Add a file path to the watch set.
     */
    bool platform_watch_file(const std::filesystem::path& filepath);

    /**
     * @brief Platform-specific: Remove a file path from the watch set.
     */
    bool platform_unwatch_file(const std::filesystem::path& filepath);

    /**
     * @brief Platform-specific: Tear down the monitoring subsystem.
     */
    void platform_shutdown_monitoring();

    // ── Member Data ──────────────────────────────────────────────────────

    /**
     * Canary manifest: maps absolute canonical path → CanaryRecord.
     * Using std::string keys for reliable hashing (std::filesystem::path
     * hash support varies across standard library implementations).
     */
    std::unordered_map<std::string, CanaryRecord> manifest_;

    /// Protects manifest_ for concurrent access (monitoring thread + main thread).
    mutable std::mutex manifest_mutex_;

    /// Additional user-specified directories to deploy canaries into.
    std::vector<std::filesystem::path> custom_dirs_;

    /// Registered callback for canary events.
    CanaryEventCallback event_callback_;

    /// Whether the monitoring subsystem is currently active.
    bool monitoring_active_ = false;

    /// High-value file extensions that ransomware families prioritize.
    static const std::vector<std::string> LURED_EXTENSIONS;

    /**
     * Naming tier definitions — each tier is designed to trap a different
     * directory traversal strategy:
     *
     *   alpha_first: Prefixes that sort to the TOP of directory listings.
     *                Targets ransomware that encrypts files in ascending
     *                alphabetical order (most common pattern).
     *
     *   alpha_last:  Prefixes that sort to the BOTTOM of directory listings.
     *                Targets ransomware that uses descending order or
     *                randomized-but-weighted-to-end traversal.
     *
     *   numeric:     Numeric prefixes that catch numeric-sort traversals.
     *                Some ransomware sorts by filename length or numeric value.
     */
    struct NamingTier {
        std::string tier_name;
        std::vector<std::string> prefixes;
    };
    static const std::vector<NamingTier> NAMING_TIERS;
};

} // namespace ransomshield

#endif // RANSOMSHIELD_CANARY_MANAGER_HPP
