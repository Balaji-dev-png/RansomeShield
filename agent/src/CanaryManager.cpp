/**
 * @file CanaryManager.cpp
 * @brief RansomShield EDR Agent — CanaryManager Implementation
 *
 * This translation unit contains the cross-platform core logic for canary
 * deployment, manifest management, and content generation. Platform-specific
 * monitoring stubs are included here with compile-time selection; full
 * implementations live in platform/{linux,windows}/ translation units.
 *
 * Build notes:
 *   - Requires C++17 or later (for <filesystem>, structured bindings, etc.)
 *   - Link with -lstdc++fs on older GCC/Clang toolchains.
 *   - Define RANSOMSHIELD_PLATFORM_LINUX or RANSOMSHIELD_PLATFORM_WINDOWS
 *     (auto-detected below if not explicitly set).
 *
 * @author  RansomShield Team
 * @date    2026-10-26
 * @version 0.1.0
 */

#include "CanaryManager.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// Platform Detection
// ─────────────────────────────────────────────────────────────────────────────
// Auto-detect platform if not explicitly defined via build system.
// This drives which monitoring backend is compiled in.

#if !defined(RANSOMSHIELD_PLATFORM_LINUX) && !defined(RANSOMSHIELD_PLATFORM_WINDOWS)
    #if defined(__linux__)
        #define RANSOMSHIELD_PLATFORM_LINUX
    #elif defined(_WIN32) || defined(_WIN64)
        #define RANSOMSHIELD_PLATFORM_WINDOWS
    #else
        #error "Unsupported platform: RansomShield supports Linux and Windows only."
    #endif
#endif

#ifdef RANSOMSHIELD_PLATFORM_WINDOWS
    #include <ShlObj.h>   // SHGetKnownFolderPath for Windows user directories
    #include <windows.h>
#else
    #include <pwd.h>      // getpwuid for Linux home directory resolution
    #include <unistd.h>
#endif

namespace ransomshield {

// ─────────────────────────────────────────────────────────────────────────────
// Static Data: Lured Extensions & Naming Tiers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * High-value file extensions that ransomware families aggressively target.
 * Ordered roughly by ransomware targeting frequency based on analysis of
 * LockBit 3.0, BlackCat/ALPHV, Cl0p, and Royal ransomware families.
 *
 * We intentionally include both document types (high business value) and
 * credential/key types (high security value) to maximize the probability
 * that ransomware will hit our canaries early in its encryption pass.
 */
const std::vector<std::string> CanaryManager::LURED_EXTENSIONS = {
    ".docx",    // Microsoft Word — #1 targeted extension across ransomware families
    ".xlsx",    // Microsoft Excel — financial data, commonly prioritized
    ".pdf",     // PDF documents — universally targeted
    ".txt",     // Plain text — often contains passwords, notes
    ".jpg",     // JPEG images — personal/business photos
    ".png",     // PNG images — screenshots, design assets
    ".csv",     // CSV data — database exports, financial records
    ".sql",     // SQL dumps — database backups, high value
    ".key",     // Private keys — SSH/TLS, extremely high value
    ".pem"      // PEM certificates — infrastructure credentials
};

/**
 * Multi-tier naming strategy to trap different directory traversal patterns.
 *
 * Why three tiers?
 * ────────────────
 * Ransomware families use different strategies to traverse directories:
 *
 * 1. ASCENDING ALPHABETICAL (most common: ~60% of samples)
 *    → Files starting with '_', '!', 'A' get encrypted first.
 *    → Our "alpha_first" tier canaries sit here as early tripwires.
 *
 * 2. DESCENDING ALPHABETICAL (less common: ~15% of samples)
 *    → Files starting with 'Z', 'z', '~' get encrypted first.
 *    → Our "alpha_last" tier catches these families.
 *
 * 3. RANDOMIZED / NUMERIC SORT (~25% of samples)
 *    → Some families shuffle the file list or sort numerically.
 *    → Our "numeric" tier with '000_' and '999_' prefixes provides
 *      coverage at both extremes of numeric sorting.
 *
 * Each prefix is chosen to be plausible (users do create files with
 * underscores, numbers, etc.) while being distinctive enough that the
 * CanaryManager can identify them via the manifest.
 */
const std::vector<CanaryManager::NamingTier> CanaryManager::NAMING_TIERS = {
    {
        "alpha_first",
        {
            "_00_confidential",   // Underscore prefix sorts very early
            "!_URGENT",           // Exclamation mark sorts before letters
            "AAA_important"       // Triple-A catches aggressive alpha-sort
        }
    },
    {
        "alpha_last",
        {
            "ZZ_passwords",       // Double-Z sorts near the end
            "zzz_backup",         // Lowercase triple-z for case-insensitive sort
            "~~~archive"          // Tilde sorts at the very end in ASCII
        }
    },
    {
        "numeric",
        {
            "000_records",        // Numeric zero-prefix for numeric-ascending sort
            "999_financial",      // Numeric high-prefix for numeric-descending sort
            "001_invoice"         // Sequential numeric prefix
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Construction / Destruction
// ─────────────────────────────────────────────────────────────────────────────

CanaryManager::CanaryManager(std::vector<std::filesystem::path> custom_dirs)
    : custom_dirs_(std::move(custom_dirs))
{
    // Reserve space in the manifest for expected canary count.
    // 3 target dirs × 3 tiers × 3 prefixes × 10 extensions = 270 canaries max.
    // With custom dirs it could be more, but 512 is a good starting bucket count.
    manifest_.reserve(512);
}

// Move operations: mutex members are not movable, so we manually move
// all other members and leave the mutex default-constructed in the target.
CanaryManager::CanaryManager(CanaryManager&& other) noexcept
    : custom_dirs_(std::move(other.custom_dirs_))
    , event_callback_(std::move(other.event_callback_))
    , monitoring_active_(other.monitoring_active_)
{
    std::lock_guard<std::mutex> lock(other.manifest_mutex_);
    manifest_ = std::move(other.manifest_);
    other.monitoring_active_ = false;
}

CanaryManager& CanaryManager::operator=(CanaryManager&& other) noexcept {
    if (this != &other) {
        // Lock both mutexes (ordered by address to avoid deadlock).
        std::mutex* first  = &manifest_mutex_;
        std::mutex* second = &other.manifest_mutex_;
        if (first > second) std::swap(first, second);
        std::lock_guard<std::mutex> lock1(*first);
        std::lock_guard<std::mutex> lock2(*second);

        manifest_          = std::move(other.manifest_);
        custom_dirs_       = std::move(other.custom_dirs_);
        event_callback_    = std::move(other.event_callback_);
        monitoring_active_ = other.monitoring_active_;
        other.monitoring_active_ = false;
    }
    return *this;
}

CanaryManager::~CanaryManager() {
    // Ensure monitoring is stopped before destruction to avoid dangling
    // callbacks into freed memory.
    if (monitoring_active_) {
        stop_monitoring();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Deployment
// ─────────────────────────────────────────────────────────────────────────────

std::size_t CanaryManager::deploy_canaries() {
    std::lock_guard<std::mutex> lock(manifest_mutex_);

    auto target_dirs = resolve_target_directories();
    std::size_t deployed_count = 0;

    for (const auto& dir : target_dirs) {
        // Skip directories that don't exist — we never create user directories,
        // only drop canaries into existing ones.
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
            std::cerr << "[CanaryManager] Skipping non-existent directory: "
                      << dir << "\n";
            continue;
        }

        // Deploy canaries for each naming tier × each lured extension.
        for (const auto& tier : NAMING_TIERS) {
            for (const auto& prefix : tier.prefixes) {
                for (const auto& ext : LURED_EXTENSIONS) {
                    // Construct the full canary filename:
                    //   e.g., /home/user/Documents/_00_confidential.docx
                    std::filesystem::path canary_path = dir / (prefix + ext);

                    // Don't overwrite existing user files! If a file already
                    // exists at this path, skip it. This is a safety measure
                    // to avoid data loss.
                    if (std::filesystem::exists(canary_path)) {
                        std::cerr << "[CanaryManager] Path already exists, skipping: "
                                  << canary_path << "\n";
                        continue;
                    }

                    // Write the canary file with realistic content.
                    if (write_canary_file(canary_path, ext)) {
                        // Register in the manifest for O(1) lookup on events.
                        std::string canonical_key =
                            std::filesystem::canonical(canary_path).string();

                        CanaryRecord record{};
                        record.filepath    = canary_path;
                        record.extension   = ext;
                        record.naming_tier = tier.tier_name;
                        record.deployed_at = current_epoch();
                        record.file_size   = std::filesystem::file_size(canary_path);
                        record.tripped     = false;

                        manifest_[canonical_key] = std::move(record);
                        ++deployed_count;
                    } else {
                        std::cerr << "[CanaryManager] Failed to deploy canary: "
                                  << canary_path << "\n";
                    }
                }
            }
        }
    }

    std::cout << "[CanaryManager] Deployed " << deployed_count
              << " canary files across " << target_dirs.size()
              << " directories.\n";

    return deployed_count;
}

std::size_t CanaryManager::cleanup_canaries() {
    std::lock_guard<std::mutex> lock(manifest_mutex_);

    std::size_t removed_count = 0;

    for (auto it = manifest_.begin(); it != manifest_.end(); ) {
        std::error_code ec;
        if (std::filesystem::remove(it->second.filepath, ec)) {
            ++removed_count;
            it = manifest_.erase(it);
        } else {
            std::cerr << "[CanaryManager] Failed to remove canary: "
                      << it->second.filepath;
            if (ec) {
                std::cerr << " (" << ec.message() << ")";
            }
            std::cerr << "\n";
            ++it;
        }
    }

    std::cout << "[CanaryManager] Cleaned up " << removed_count
              << " canary files.\n";

    return removed_count;
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest Query
// ─────────────────────────────────────────────────────────────────────────────

const CanaryRecord* CanaryManager::lookup_canary(
    const std::filesystem::path& path
) const {
    std::lock_guard<std::mutex> lock(manifest_mutex_);

    // Canonicalize the incoming path to match our manifest keys.
    // We use error_code overload to avoid throwing on non-existent paths
    // (the canary might have been deleted by ransomware already).
    std::error_code ec;
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) {
        // If we can't canonicalize (file gone), try the raw string.
        // This handles the case where ransomware deleted the canary
        // and we're checking from an event that captured the original path.
        auto it = manifest_.find(path.string());
        return (it != manifest_.end()) ? &it->second : nullptr;
    }

    auto it = manifest_.find(canonical.string());
    return (it != manifest_.end()) ? &it->second : nullptr;
}

std::vector<CanaryRecord> CanaryManager::get_manifest() const {
    std::lock_guard<std::mutex> lock(manifest_mutex_);

    std::vector<CanaryRecord> snapshot;
    snapshot.reserve(manifest_.size());

    for (const auto& [key, record] : manifest_) {
        snapshot.push_back(record);
    }

    return snapshot;
}

std::size_t CanaryManager::canary_count() const {
    std::lock_guard<std::mutex> lock(manifest_mutex_);
    return manifest_.size();
}

// ─────────────────────────────────────────────────────────────────────────────
// Monitoring Interface
// ─────────────────────────────────────────────────────────────────────────────

void CanaryManager::register_event_callback(CanaryEventCallback callback) {
    event_callback_ = std::move(callback);
}

bool CanaryManager::start_monitoring() {
    if (monitoring_active_) {
        std::cerr << "[CanaryManager] Monitoring is already active.\n";
        return true;
    }

    if (!event_callback_) {
        std::cerr << "[CanaryManager] ERROR: No event callback registered. "
                     "Call register_event_callback() before start_monitoring().\n";
        return false;
    }

    // Initialize the platform-specific monitoring subsystem.
    if (!platform_init_monitoring()) {
        std::cerr << "[CanaryManager] ERROR: Failed to initialize platform "
                     "monitoring subsystem.\n";
        return false;
    }

    // Register each canary file with the platform watcher.
    {
        std::lock_guard<std::mutex> lock(manifest_mutex_);
        for (const auto& [key, record] : manifest_) {
            if (!platform_watch_file(record.filepath)) {
                std::cerr << "[CanaryManager] WARNING: Failed to watch canary: "
                          << record.filepath << "\n";
                // Non-fatal: we continue and watch what we can.
            }
        }
    }

    monitoring_active_ = true;
    std::cout << "[CanaryManager] Monitoring started. Watching "
              << canary_count() << " canary files.\n";

    return true;
}

void CanaryManager::stop_monitoring() {
    if (!monitoring_active_) {
        return;
    }

    platform_shutdown_monitoring();
    monitoring_active_ = false;

    std::cout << "[CanaryManager] Monitoring stopped.\n";
}

bool CanaryManager::is_monitoring() const {
    return monitoring_active_;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: Directory Resolution
// ─────────────────────────────────────────────────────────────────────────────

std::vector<std::filesystem::path>
CanaryManager::resolve_target_directories() const {
    std::vector<std::filesystem::path> dirs;

    // ── Resolve the user's home directory ────────────────────────────────
    std::filesystem::path home_dir;

#ifdef RANSOMSHIELD_PLATFORM_WINDOWS
    // On Windows, use the USERPROFILE environment variable.
    // This resolves to something like C:\Users\JohnDoe.
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        home_dir = userprofile;
    } else {
        // Fallback: try HOMEDRIVE + HOMEPATH (older Windows convention).
        const char* homedrive = std::getenv("HOMEDRIVE");
        const char* homepath  = std::getenv("HOMEPATH");
        if (homedrive && homepath) {
            home_dir = std::string(homedrive) + std::string(homepath);
        }
    }
#else
    // On Linux, use HOME env var with fallback to passwd database.
    // The passwd fallback handles edge cases like systemd services
    // where HOME might not be set.
    const char* home_env = std::getenv("HOME");
    if (home_env) {
        home_dir = home_env;
    } else {
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            home_dir = pw->pw_dir;
        }
    }
#endif

    if (home_dir.empty()) {
        std::cerr << "[CanaryManager] ERROR: Could not resolve user home directory.\n";
        return dirs;
    }

    // ── Standard user directories to canary ──────────────────────────────
    // These are the directories most commonly targeted by ransomware because
    // they contain user-created files (documents, downloads, screenshots).
    const std::vector<std::string> standard_subdirs = {
        "Documents",
        "Downloads",
        "Desktop"
    };

    for (const auto& subdir : standard_subdirs) {
        std::filesystem::path candidate = home_dir / subdir;
        if (std::filesystem::exists(candidate) &&
            std::filesystem::is_directory(candidate)) {
            dirs.push_back(std::move(candidate));
        } else {
            std::cerr << "[CanaryManager] Standard directory not found, skipping: "
                      << candidate << "\n";
        }
    }

    // ── Append any custom directories the user specified ─────────────────
    for (const auto& custom : custom_dirs_) {
        if (std::filesystem::exists(custom) &&
            std::filesystem::is_directory(custom)) {
            dirs.push_back(custom);
        } else {
            std::cerr << "[CanaryManager] Custom directory not found, skipping: "
                      << custom << "\n";
        }
    }

    return dirs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: Canary Name Generation
// ─────────────────────────────────────────────────────────────────────────────

std::vector<std::string> CanaryManager::generate_canary_names(
    const std::string& tier
) const {
    std::vector<std::string> names;

    for (const auto& naming_tier : NAMING_TIERS) {
        if (naming_tier.tier_name == tier) {
            for (const auto& prefix : naming_tier.prefixes) {
                for (const auto& ext : LURED_EXTENSIONS) {
                    names.push_back(prefix + ext);
                }
            }
            break;
        }
    }

    return names;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: File Content Generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Why realistic content matters:
 * ──────────────────────────────
 * Modern ransomware families (LockBit 3.0, BlackCat) perform pre-encryption
 * validation by checking file magic bytes. A canary file containing random
 * bytes or all zeros might be skipped by smart ransomware, defeating the
 * honeypot. By writing valid magic bytes and plausible content, we ensure
 * ransomware treats our canaries as legitimate high-value targets.
 */
std::vector<std::uint8_t> CanaryManager::generate_content(
    const std::string& extension
) const {
    std::vector<std::uint8_t> content;

    // ── Office documents (.docx, .xlsx) ──────────────────────────────────
    // These are actually ZIP archives. We write a valid ZIP local file header
    // (PK\x03\x04) so magic-byte checks pass.
    if (extension == ".docx" || extension == ".xlsx") {
        // ZIP local file header magic bytes
        const std::uint8_t zip_header[] = {
            0x50, 0x4B, 0x03, 0x04,  // PK\x03\x04 — ZIP magic
            0x14, 0x00,              // Version needed to extract (2.0)
            0x00, 0x00,              // General purpose bit flag
            0x08, 0x00,              // Compression method (deflate)
            0x00, 0x00, 0x00, 0x00,  // Last mod file time/date
            0x00, 0x00, 0x00, 0x00,  // CRC-32
            0x00, 0x00, 0x00, 0x00,  // Compressed size
            0x00, 0x00, 0x00, 0x00,  // Uncompressed size
            0x13, 0x00,              // Filename length (19 bytes)
            0x00, 0x00               // Extra field length
        };
        content.assign(zip_header, zip_header + sizeof(zip_header));

        // Filename in the ZIP entry — mimics real Office document structure.
        const char* inner_name = "[Content_Types].xml";
        content.insert(content.end(), inner_name,
                       inner_name + std::strlen(inner_name));

        // Pad with plausible XML content to reach a realistic file size (~4KB).
        std::string xml_padding =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
            "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n"
            "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
            "</Types>\n";
        // Repeat padding to bulk up the file
        for (int i = 0; i < 8; ++i) {
            content.insert(content.end(), xml_padding.begin(), xml_padding.end());
        }
    }

    // ── PDF documents ────────────────────────────────────────────────────
    // We write a minimal valid PDF structure that passes magic-byte checks
    // and even opens in basic PDF viewers.
    else if (extension == ".pdf") {
        std::string pdf_content =
            "%PDF-1.7\n"
            "1 0 obj\n"
            "<< /Type /Catalog /Pages 2 0 R >>\n"
            "endobj\n"
            "2 0 obj\n"
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            "endobj\n"
            "3 0 obj\n"
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
            "endobj\n"
            "xref\n"
            "0 4\n"
            "0000000000 65535 f \n"
            "0000000009 00000 n \n"
            "0000000058 00000 n \n"
            "0000000115 00000 n \n"
            "trailer\n"
            "<< /Size 4 /Root 1 0 R >>\n"
            "startxref\n"
            "190\n"
            "%%EOF\n";
        content.assign(pdf_content.begin(), pdf_content.end());
    }

    // ── Plain text files ─────────────────────────────────────────────────
    // Content that looks like sensitive notes or credentials — irresistible
    // to ransomware that does content-based targeting.
    else if (extension == ".txt") {
        std::string text_content =
            "CONFIDENTIAL — Internal Use Only\n"
            "================================\n\n"
            "Project Status Report — Q4 2026\n"
            "-------------------------------\n"
            "Budget allocation: $2.4M approved\n"
            "Timeline: On track for December delivery\n"
            "Key risks: Supply chain delays (mitigated)\n\n"
            "Action items:\n"
            "  1. Finalize vendor contracts by Nov 15\n"
            "  2. Complete security audit by Nov 30\n"
            "  3. Deploy staging environment by Dec 1\n\n"
            "Contact: operations@example-corp.com\n"
            "Password vault: See KeePass file on shared drive\n";
        content.assign(text_content.begin(), text_content.end());
    }

    // ── CSV data files ───────────────────────────────────────────────────
    // Looks like an exported database or financial spreadsheet.
    else if (extension == ".csv") {
        std::string csv_content =
            "id,employee_name,department,salary,ssn_last4,email\n"
            "1001,\"Smith, John\",Engineering,125000,4521,jsmith@example.com\n"
            "1002,\"Johnson, Alice\",Finance,98000,7834,ajohnson@example.com\n"
            "1003,\"Williams, Bob\",Marketing,87000,2156,bwilliams@example.com\n"
            "1004,\"Brown, Carol\",Engineering,135000,9043,cbrown@example.com\n"
            "1005,\"Davis, Eve\",HR,92000,3367,edavis@example.com\n"
            "1006,\"Miller, Frank\",Engineering,142000,5589,fmiller@example.com\n"
            "1007,\"Wilson, Grace\",Finance,105000,1278,gwilson@example.com\n"
            "1008,\"Moore, Henry\",Marketing,79000,8845,hmoore@example.com\n";
        content.assign(csv_content.begin(), csv_content.end());
    }

    // ── JPEG images ──────────────────────────────────────────────────────
    // We write a valid JFIF header so the file passes magic-byte validation.
    else if (extension == ".jpg") {
        const std::uint8_t jpg_header[] = {
            0xFF, 0xD8, 0xFF, 0xE0,  // SOI + APP0 marker
            0x00, 0x10,              // APP0 length (16 bytes)
            0x4A, 0x46, 0x49, 0x46, 0x00,  // "JFIF\0"
            0x01, 0x01,              // Version 1.1
            0x00,                    // Aspect ratio units (0 = no units)
            0x00, 0x01,              // X density
            0x00, 0x01,              // Y density
            0x00, 0x00               // No thumbnail
        };
        content.assign(jpg_header, jpg_header + sizeof(jpg_header));
        // Pad to ~4KB with plausible image data bytes.
        content.resize(4096, 0x80);
        // End of image marker.
        content.push_back(0xFF);
        content.push_back(0xD9);
    }

    // ── PNG images ───────────────────────────────────────────────────────
    // Valid 8-byte PNG signature followed by a minimal IHDR chunk.
    else if (extension == ".png") {
        const std::uint8_t png_header[] = {
            0x89, 0x50, 0x4E, 0x47,  // PNG signature (first 4 bytes)
            0x0D, 0x0A, 0x1A, 0x0A,  // PNG signature (last 4 bytes)
            // IHDR chunk (13 bytes data)
            0x00, 0x00, 0x00, 0x0D,  // Chunk length: 13
            0x49, 0x48, 0x44, 0x52,  // Chunk type: "IHDR"
            0x00, 0x00, 0x00, 0x01,  // Width: 1
            0x00, 0x00, 0x00, 0x01,  // Height: 1
            0x08, 0x02,              // Bit depth: 8, Color type: RGB
            0x00, 0x00, 0x00,        // Compression, Filter, Interlace
            0x90, 0x77, 0x53, 0xDE   // CRC32 of IHDR
        };
        content.assign(png_header, png_header + sizeof(png_header));
        content.resize(4096, 0x00);  // Pad to ~4KB
    }

    // ── SQL dumps ────────────────────────────────────────────────────────
    // Looks like a database backup — high value target.
    else if (extension == ".sql") {
        std::string sql_content =
            "-- MySQL dump 10.13  Distrib 8.0.36\n"
            "-- Host: db-prod-01.internal    Database: customer_data\n"
            "-- -----------------------------------------------\n\n"
            "SET NAMES utf8mb4;\n"
            "SET FOREIGN_KEY_CHECKS = 0;\n\n"
            "DROP TABLE IF EXISTS `customers`;\n"
            "CREATE TABLE `customers` (\n"
            "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
            "  `name` varchar(255) NOT NULL,\n"
            "  `email` varchar(255) NOT NULL,\n"
            "  `credit_card_hash` varchar(64) DEFAULT NULL,\n"
            "  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
            "INSERT INTO `customers` VALUES\n"
            "(1,'John Doe','john@example.com','a1b2c3d4e5f6',NOW()),\n"
            "(2,'Jane Smith','jane@example.com','f6e5d4c3b2a1',NOW());\n\n"
            "SET FOREIGN_KEY_CHECKS = 1;\n";
        content.assign(sql_content.begin(), sql_content.end());
    }

    // ── Private keys (.key, .pem) ────────────────────────────────────────
    // PEM-formatted structure that looks like a real private key.
    // Obviously NOT a real key — but the format tricks ransomware scanners.
    else if (extension == ".key" || extension == ".pem") {
        // Generate deterministic but realistic-looking base64 content.
        std::string pem_content =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA6MbRiMHma8JrOlGM\n"
            "txEaGd5VPnPNqFNwDEkfSQMa7PsfjLCEjmXGSNyZ1gTKxB3JMv1CqNTFh7Qe9KPo\n"
            "HjIMFNmPOjZCHYskqlkUF3kLP05YhJkXACsDW7QOeaEBMBnB/aFD6P6IPgbAGSY6\n"
            "AxCU3MPmqr7KWFMGR0U3RfLGSqMOGrvKPAHNjMk8mjLlUVwJ/YD/5KMcO3JaBq4F\n"
            "T+a1DX0f9JFhfr3qLxGP8VNDpMTHqDnS1zaVmXDLbWkJNrbRGEUAxX//jnJMiZbj\n"
            "YWkfvzgMhDfIqAthMbsmVNz0pI0M1MjMRR9z3QIDAQABAoIBAC1Hf2GkpbZ+tHGq\n"
            "jo7EKPXSTNAiMn0rNjJCFa2Mx1r5MKfbYjv2BFkbQi9gFbDjFdxU6v7QMVxEJLD6\n"
            "qF7KNfJm2tBXK8F2wMFE5Lf0JRHZDwPGMQkj3Y3bOE4+/TE6KaDQ3T5N9IA1Kx0\n"
            "-----END RSA PRIVATE KEY-----\n";
        content.assign(pem_content.begin(), pem_content.end());
    }

    // ── Fallback for unknown extensions ──────────────────────────────────
    else {
        std::string fallback = "CONFIDENTIAL DOCUMENT — DO NOT DISTRIBUTE\n";
        content.assign(fallback.begin(), fallback.end());
        content.resize(4096, 0x20);  // Pad with spaces to 4KB
    }

    return content;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: File Writing
// ─────────────────────────────────────────────────────────────────────────────

bool CanaryManager::write_canary_file(
    const std::filesystem::path& filepath,
    const std::string& extension
) {
    try {
        // Generate realistic file content with valid magic bytes.
        auto content = generate_content(extension);

        // Write in binary mode to preserve magic bytes exactly.
        std::ofstream ofs(filepath, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            std::cerr << "[CanaryManager] Cannot open file for writing: "
                      << filepath << "\n";
            return false;
        }

        ofs.write(reinterpret_cast<const char*>(content.data()),
                  static_cast<std::streamsize>(content.size()));

        if (ofs.fail()) {
            std::cerr << "[CanaryManager] Write failed for: " << filepath << "\n";
            return false;
        }

        ofs.close();

        // Set the file to read-only. This does two things:
        //   1. Prevents accidental modification by the user.
        //   2. Ransomware that changes permissions before writing will
        //      trigger an additional detectable event (permission change).
        std::error_code ec;
        std::filesystem::permissions(
            filepath,
            std::filesystem::perms::owner_read |
            std::filesystem::perms::group_read |
            std::filesystem::perms::others_read,
            std::filesystem::perm_options::replace,
            ec
        );

        if (ec) {
            // Non-fatal: the canary still works, it just isn't read-only.
            std::cerr << "[CanaryManager] WARNING: Could not set read-only "
                         "permissions on: " << filepath
                      << " (" << ec.message() << ")\n";
        }

        return true;

    } catch (const std::exception& ex) {
        std::cerr << "[CanaryManager] Exception writing canary " << filepath
                  << ": " << ex.what() << "\n";
        return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: Utility
// ─────────────────────────────────────────────────────────────────────────────

std::uint64_t CanaryManager::current_epoch() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-Specific Monitoring Stubs
// ─────────────────────────────────────────────────────────────────────────────
//
// These are placeholder implementations. The full eBPF (Linux) and ETW
// (Windows) implementations will live in separate translation units:
//   - platform/linux/CanaryMonitor_linux.cpp
//   - platform/windows/CanaryMonitor_windows.cpp
//
// For now, we provide stubs that log intent so the rest of the agent
// can be developed and tested without requiring root/admin privileges
// or kernel headers.
// ─────────────────────────────────────────────────────────────────────────────

#ifdef RANSOMSHIELD_PLATFORM_LINUX

bool CanaryManager::platform_init_monitoring() {
    // ┌─────────────────────────────────────────────────────────────────┐
    // │ LINUX eBPF MONITORING — PLACEHOLDER                            │
    // │                                                                 │
    // │ Full implementation will:                                       │
    // │   1. Load a BPF program (CO-RE / libbpf) that attaches to      │
    // │      vfs_write / vfs_open tracepoints.                         │
    // │   2. The BPF program filters events by inode number, matching  │
    // │      against a BPF_MAP_TYPE_HASH of canary inodes.             │
    // │   3. Matching events are pushed to a BPF perf buffer / ring    │
    // │      buffer, which the userspace agent polls.                  │
    // │   4. Userspace reads events, constructs CanaryEvent structs,   │
    // │      and invokes the registered callback.                      │
    // │                                                                 │
    // │ Fallback path: If eBPF is unavailable (older kernel, no CAP_   │
    // │ BPF), fall back to fanotify(7) with FAN_MODIFY | FAN_CLOSE_   │
    // │ WRITE marks on each canary file.                               │
    // └─────────────────────────────────────────────────────────────────┘
    std::cout << "[CanaryManager] [Linux] Initializing eBPF monitoring subsystem...\n"
              << "[CanaryManager] [Linux] STUB: Full eBPF/fanotify implementation pending.\n"
              << "[CanaryManager] [Linux] Will attach to vfs_write tracepoint.\n";
    return true;
}

bool CanaryManager::platform_watch_file(const std::filesystem::path& filepath) {
    // In the full implementation, this would:
    //   1. stat() the file to get its inode number.
    //   2. Insert the inode into the BPF hash map so the kernel-side
    //      program can filter on it.
    //   3. For fanotify fallback: fanotify_mark(fd, FAN_MARK_ADD,
    //      FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, filepath).
    std::cout << "[CanaryManager] [Linux] STUB: Watching inode for "
              << filepath << "\n";
    return true;
}

bool CanaryManager::platform_unwatch_file(const std::filesystem::path& filepath) {
    // In the full implementation: remove inode from BPF map, or
    // fanotify_mark(fd, FAN_MARK_REMOVE, ...).
    std::cout << "[CanaryManager] [Linux] STUB: Unwatching " << filepath << "\n";
    return true;
}

void CanaryManager::platform_shutdown_monitoring() {
    // In the full implementation:
    //   1. Close BPF perf buffer / ring buffer.
    //   2. Detach BPF programs from tracepoints.
    //   3. Close BPF object (bpf_object__close).
    //   4. Join the polling thread.
    //   5. For fanotify: close(fanotify_fd).
    std::cout << "[CanaryManager] [Linux] STUB: Shutting down eBPF monitoring.\n";
}

#elif defined(RANSOMSHIELD_PLATFORM_WINDOWS)

bool CanaryManager::platform_init_monitoring() {
    // ┌─────────────────────────────────────────────────────────────────┐
    // │ WINDOWS ETW MONITORING — PLACEHOLDER                           │
    // │                                                                 │
    // │ Full implementation will:                                       │
    // │   1. Call StartTrace() to create a real-time ETW session.       │
    // │   2. Enable the Microsoft-Windows-Kernel-File provider with    │
    // │      KERNEL_FILE keyword flags for FileIo events.              │
    // │   3. Call OpenTrace() + ProcessTrace() on a dedicated thread   │
    // │      to consume events in real-time.                           │
    // │   4. In the EventRecordCallback, filter by file path against  │
    // │      the canary manifest, construct CanaryEvent, and invoke    │
    // │      the registered callback.                                  │
    // │                                                                 │
    // │ Alternative path: ReadDirectoryChangesW with overlapped I/O   │
    // │ as a simpler fallback for development/testing.                 │
    // └─────────────────────────────────────────────────────────────────┘
    std::cout << "[CanaryManager] [Windows] Initializing ETW monitoring subsystem...\n"
              << "[CanaryManager] [Windows] STUB: Full ETW trace session implementation pending.\n"
              << "[CanaryManager] [Windows] Will enable Microsoft-Windows-Kernel-File provider.\n";
    return true;
}

bool CanaryManager::platform_watch_file(const std::filesystem::path& filepath) {
    // In the full implementation:
    //   1. Normalize the path to NT kernel format (\\?\C:\...).
    //   2. Add to an internal std::unordered_set for O(1) path matching
    //      in the ETW EventRecordCallback.
    //   3. Optionally set up a ReadDirectoryChangesW watch on the
    //      parent directory as a secondary detection layer.
    std::cout << "[CanaryManager] [Windows] STUB: Watching path "
              << filepath << "\n";
    return true;
}

bool CanaryManager::platform_unwatch_file(const std::filesystem::path& filepath) {
    std::cout << "[CanaryManager] [Windows] STUB: Unwatching " << filepath << "\n";
    return true;
}

void CanaryManager::platform_shutdown_monitoring() {
    // In the full implementation:
    //   1. ControlTrace(..., EVENT_TRACE_CONTROL_STOP) to stop the session.
    //   2. CloseTrace() to release handles.
    //   3. Join the ProcessTrace() thread.
    //   4. For RDCW fallback: CancelIoEx() + CloseHandle().
    std::cout << "[CanaryManager] [Windows] STUB: Shutting down ETW monitoring.\n";
}

#endif // Platform selection

} // namespace ransomshield
