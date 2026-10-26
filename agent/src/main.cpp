/**
 * @file main.cpp
 * @brief RansomShield EDR Agent — Entry Point
 *
 * Full detection pipeline integration:
 *   CanaryManager (deploy) → RollbackCache (snapshot) → Monitor
 *   → CanaryEvent → EntropyAnalyzer (detect) → MitigationEngine (kill)
 *   → RollbackCache (restore) → Telemetry
 */

#include "CanaryManager.hpp"
#include "EntropyAnalyzer.hpp"
#include "MitigationEngine.hpp"
#include "RollbackCache.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <thread>

// Global flag for graceful shutdown on SIGINT/SIGTERM.
static std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    std::cout << "\n[RansomShield] Received signal " << signum
              << ", shutting down...\n";
    g_running.store(false);
}

int main() {
    std::cout << "╔══════════════════════════════════════════════╗\n"
              << "║       RansomShield EDR Agent  v0.1.0        ║\n"
              << "║    Canary · Entropy · Kill · Restore         ║\n"
              << "╚══════════════════════════════════════════════╝\n\n";

    // Register signal handlers for graceful shutdown.
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ── Initialize all subsystems ────────────────────────────────────────
    ransomshield::CanaryManager     canary_mgr;
    ransomshield::EntropyAnalyzer   entropy_analyzer;  // 4KB blocks, threshold 7.2
    ransomshield::MitigationEngine  mitigation_engine;
    ransomshield::RollbackCache     rollback_cache;

    std::cout << "[Main] Subsystems initialized.\n"
              << "  Entropy block size:  " << entropy_analyzer.block_size() << " bytes\n"
              << "  Entropy threshold:   " << entropy_analyzer.threshold() << " bits\n"
              << "  Rollback capacity:   1024 snapshots\n\n";

    // ── Deploy canaries ──────────────────────────────────────────────────
    std::size_t deployed = canary_mgr.deploy_canaries();
    std::cout << "\n[Main] Total canaries deployed: " << deployed << "\n";

    // ── Snapshot all canaries into the rollback cache ────────────────────
    // This must happen IMMEDIATELY after deployment, before any attacker
    // can modify the files.
    {
        auto manifest = canary_mgr.get_manifest();
        std::size_t cached = 0;
        for (const auto& record : manifest) {
            if (rollback_cache.snapshot(record.filepath)) {
                ++cached;
            }
        }
        std::cout << "[Main] Rollback cache: " << cached << " snapshots ("
                  << rollback_cache.total_bytes() << " bytes total).\n\n";
    }

    // ── Register the detection → response pipeline callback ─────────────
    // This callback is the beating heart of RansomShield:
    //   1. Canary event fires (file was modified)
    //   2. Read the modified data
    //   3. Run entropy analysis on the first 4KB block
    //   4. If encrypted → KILL the process → RESTORE the file
    canary_mgr.register_event_callback(
        [&entropy_analyzer, &mitigation_engine, &rollback_cache]
        (const ransomshield::CanaryEvent& event) {

            std::cout << "\n╔══════════════════════════════════════════════╗\n"
                      << "║  ⚠ CANARY TRIPWIRE ACTIVATED                ║\n"
                      << "╚══════════════════════════════════════════════╝\n"
                      << "  File:    " << event.filepath << "\n"
                      << "  PID:     " << event.pid << "\n"
                      << "  Process: " << event.process_name << "\n\n";

            // ── Step 1: Quick entropy check on the modified file ─────────
            std::cout << "[Pipeline] Step 1: Entropy analysis (first "
                      << entropy_analyzer.block_size() << " bytes)...\n";

            bool encrypted = entropy_analyzer.is_encrypted(event.filepath);

            if (!encrypted) {
                std::cout << "[Pipeline] Entropy below threshold. "
                          << "Benign modification — standing down.\n";
                return;
            }

            // ── Step 2: Full entropy analysis for telemetry ──────────────
            std::cout << "[Pipeline] ⚡ HIGH ENTROPY DETECTED! Running full analysis...\n";

            auto full_result = entropy_analyzer.analyze_file(event.filepath);
            if (full_result) {
                std::cout << "[Pipeline] Full analysis results:\n"
                          << "  Max block entropy: " << full_result->max_block_entropy << " bits\n"
                          << "  Mean entropy:      " << full_result->mean_entropy << " bits\n"
                          << "  Blocks above " << full_result->threshold_used << ": "
                          << full_result->blocks_above << "/"
                          << full_result->blocks_analyzed << "\n";
            }

            // ── Step 3: KILL the offending process ───────────────────────
            std::cout << "[Pipeline] Step 3: Process decapitation...\n";

            auto kill_report = mitigation_engine.kill_process_tree(event.pid);

            if (kill_report.result == ransomshield::KillResult::SUCCESS) {
                std::cout << "[Pipeline] ✓ Ransomware process eliminated in "
                          << kill_report.latency_us << "μs.\n";
            } else {
                std::cerr << "[Pipeline] ✗ Kill failed: "
                          << kill_report.error_message << "\n";
            }

            // ── Step 4: RESTORE the canary file from cache ───────────────
            std::cout << "[Pipeline] Step 4: File restoration...\n";

            auto restore_report = rollback_cache.restore(event.filepath);

            if (restore_report.result == ransomshield::RestoreResult::SUCCESS) {
                std::cout << "[Pipeline] ✓ Canary restored ("
                          << restore_report.bytes_restored << " bytes, "
                          << restore_report.latency_us << "μs). Re-armed.\n";
            } else {
                std::cerr << "[Pipeline] ✗ Restore failed: "
                          << restore_report.error_message << "\n";
            }

            // ── Step 5: Telemetry (placeholder) ──────────────────────────
            std::cout << "[Pipeline] Step 5: Sending telemetry to SOC backend...\n"
                      << "[Pipeline] TODO: WebSocket JSON → FastAPI → PostgreSQL\n\n";
        }
    );

    // ── Start monitoring ─────────────────────────────────────────────────
    if (canary_mgr.start_monitoring()) {
        std::cout << "\n[Main] Detection pipeline active. Press Ctrl+C to stop.\n\n";
    } else {
        std::cerr << "[Main] WARNING: Monitoring could not be started.\n";
    }

    // ── Print manifest summary ───────────────────────────────────────────
    auto manifest = canary_mgr.get_manifest();
    std::cout << "[Main] Canary Manifest (" << manifest.size() << " entries):\n";
    for (const auto& record : manifest) {
        std::cout << "  [" << record.naming_tier << "] "
                  << record.filepath << " (" << record.file_size << " bytes)\n";
    }

    // ── Main loop ────────────────────────────────────────────────────────
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // ── Graceful shutdown ────────────────────────────────────────────────
    std::cout << "\n[Main] Shutting down...\n";
    canary_mgr.stop_monitoring();

    std::size_t cleaned = canary_mgr.cleanup_canaries();
    std::cout << "[Main] Cleaned up " << cleaned << " canary files.\n";

    rollback_cache.clear();
    std::cout << "[Main] Rollback cache cleared.\n";
    std::cout << "[Main] RansomShield agent stopped.\n";

    return 0;
}
