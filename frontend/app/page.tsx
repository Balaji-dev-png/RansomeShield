"use client";

import React, { useState } from "react";
import { useSocWebSocket } from "@/hooks/useSocWebSocket";
import { SocHeader } from "@/components/SocHeader";
import { ThreatMetricsGrid } from "@/components/ThreatMetricsGrid";
import { KillLatencyGauge } from "@/components/KillLatencyGauge";
import { EntropyDistributionCard } from "@/components/EntropyDistributionCard";
import { RecentThreatsTable } from "@/components/RecentThreatsTable";
import { ThreatEvent } from "@/types/threat";

export default function SocDashboard() {
  const {
    events,
    latestThreat,
    status,
    activeClients,
    stats,
    isSimulating,
    toggleSimulation,
    clearEvents,
    reconnect,
  } = useSocWebSocket();

  const [activeTab, setActiveTab] = useState<"all" | "critical" | "mitigated">("all");

  const filteredThreats = events.filter((e) => {
    if (activeTab === "critical") return e.severity === "CRITICAL";
    if (activeTab === "mitigated") return e.action_taken === "KILLED_AND_ROLLED_BACK";
    return true;
  });

  return (
    <div className="min-h-screen flex flex-col bg-cyber-bg text-cyber-text">
      {/* Top SOC Navbar */}
      <SocHeader
        status={status}
        activeClients={activeClients}
        isSimulating={isSimulating}
        onToggleSimulation={toggleSimulation}
        onClearEvents={clearEvents}
        onReconnect={reconnect}
      />

      {/* Main Command Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Active Alert Banner (Flashes when a threat is intercepted) */}
        {latestThreat && (
          <div className="relative overflow-hidden rounded-xl bg-rose-950/20 border border-rose-500/50 p-4 shadow-[0_0_20px_rgba(239,68,68,0.25)] flex flex-wrap items-center justify-between gap-4 animate-fade-in">
            <div className="flex items-center space-x-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-400">
                <svg className="w-5 h-5 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider">
                    CRITICAL TRIPWIRE VIOLATION DECAPITATED
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-500/30 text-rose-200">
                    PID {latestThreat.malicious_pid}
                  </span>
                </div>
                <p className="text-xs text-cyber-muted mt-0.5">
                  Process <span className="text-cyber-text font-mono font-semibold">{latestThreat.process_name || "unknown"}</span> attempted high-entropy write ($H={latestThreat.entropy_score.toFixed(3)}$ bits) on canary <span className="text-cyber-text font-mono">{latestThreat.target_canary_path.split("/").pop()}</span>. Decapitated in <span className="text-emerald-400 font-mono font-bold">{latestThreat.mitigation_latency_ms.toFixed(3)} ms</span>.
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                <span>CANARY RESTORED</span>
              </span>
            </div>
          </div>
        )}

        {/* 1. Global Metric Cards Grid */}
        <ThreatMetricsGrid stats={stats} latestThreat={latestThreat} />

        {/* 2. Analytical Diagnostic Row (Kill-Latency Gauge & Entropy Spectrum & Canary Architecture) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Visual Gauge: Process Decapitation Latency */}
          <div className="lg:col-span-1 flex">
            <div className="w-full">
              <KillLatencyGauge
                latestThreat={latestThreat}
                avgLatencyMs={stats.avgMitigationLatencyMs}
              />
            </div>
          </div>

          {/* Entropy Distribution & 4KB Block Inspector */}
          <div className="lg:col-span-1 flex">
            <div className="w-full">
              <EntropyDistributionCard latestThreat={latestThreat} />
            </div>
          </div>

          {/* Canary Multi-Tier Status Card */}
          <div className="lg:col-span-1 rounded-xl bg-cyber-card border border-cyber-border p-6 shadow-2xl flex flex-col justify-between">
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">
                  Honeypot Decoy Architecture
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-bg text-cyber-muted border border-cyber-border">
                270 Decoys Deployed
              </span>
            </div>

            <div className="space-y-3 my-3 text-xs">
              <div className="rounded-lg bg-cyber-bg border border-cyber-border/80 p-2.5">
                <div className="flex justify-between font-mono text-[11px] mb-1">
                  <span className="text-cyber-muted">Tier 1: Alpha-First Traversal</span>
                  <span className="text-cyber-neon font-semibold">_00_, !_, AAA_</span>
                </div>
                <p className="text-[10px] text-cyber-muted/80">
                  Intercepts ascending alphabetical scans (LockBit, Conti, BlackCat standard traversal).
                </p>
              </div>

              <div className="rounded-lg bg-cyber-bg border border-cyber-border/80 p-2.5">
                <div className="flex justify-between font-mono text-[11px] mb-1">
                  <span className="text-cyber-muted">Tier 2: Alpha-Last Traversal</span>
                  <span className="text-cyber-neon font-semibold">ZZ_, zzz_, ~~~</span>
                </div>
                <p className="text-[10px] text-cyber-muted/80">
                  Traps descending or end-first recursive directory encrypters.
                </p>
              </div>

              <div className="rounded-lg bg-cyber-bg border border-cyber-border/80 p-2.5">
                <div className="flex justify-between font-mono text-[11px] mb-1">
                  <span className="text-cyber-muted">Tier 3: Numeric &amp; Zero-Indexed</span>
                  <span className="text-cyber-neon font-semibold">000_, 999_</span>
                </div>
                <p className="text-[10px] text-cyber-muted/80">
                  Traps length-sorted or numeric-indexed ransomware payloads.
                </p>
              </div>
            </div>

            <div className="pt-2 border-t border-cyber-border/70 flex items-center justify-between text-[10px] font-mono text-cyber-muted">
              <span>Lures: .docx, .xlsx, .pdf, .key, .sql</span>
              <span className="text-emerald-400">All Pristine in Memory</span>
            </div>
          </div>
        </div>

        {/* 3. Live Streaming Threat Table */}
        <div className="space-y-3">
          {/* Filter Tabs */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab("all")}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeTab === "all"
                  ? "bg-cyber-card border border-cyber-neon text-cyber-neon"
                  : "bg-cyber-bg text-cyber-muted hover:text-cyber-text border border-cyber-border"
              }`}
            >
              All Interceptions ({events.length})
            </button>
            <button
              onClick={() => setActiveTab("critical")}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeTab === "critical"
                  ? "bg-cyber-card border border-rose-500 text-rose-400"
                  : "bg-cyber-bg text-cyber-muted hover:text-cyber-text border border-cyber-border"
              }`}
            >
              Critical Only ({events.filter((e) => e.severity === "CRITICAL").length})
            </button>
            <button
              onClick={() => setActiveTab("mitigated")}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeTab === "mitigated"
                  ? "bg-cyber-card border border-emerald-500 text-emerald-400"
                  : "bg-cyber-bg text-cyber-muted hover:text-cyber-text border border-cyber-border"
              }`}
            >
              Mitigated &amp; Restored ({events.filter((e) => e.action_taken === "KILLED_AND_ROLLED_BACK").length})
            </button>
          </div>

          <RecentThreatsTable threats={filteredThreats} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-border/80 bg-cyber-bg py-4 px-6 text-center text-xs font-mono text-cyber-muted">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
          <span>RansomShield EDR &middot; Cross-Platform Ransomware Decapitation &amp; Zero-Loss Restoration</span>
          <span className="text-[11px]">eBPF / ETW Kernel Hooks &middot; C++17 &middot; FastAPI &middot; Next.js</span>
        </div>
      </footer>
    </div>
  );
}

