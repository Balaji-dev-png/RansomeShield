"use client";

import React from "react";
import { SocSystemStats, ThreatEvent } from "@/types/threat";

interface ThreatMetricsGridProps {
  stats: SocSystemStats;
  latestThreat: ThreatEvent | null;
}

export function ThreatMetricsGrid({ stats, latestThreat }: ThreatMetricsGridProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Metric 1: Total Interceptions */}
      <div className="rounded-xl bg-cyber-card border border-cyber-border p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between text-cyber-muted">
          <span className="text-xs font-semibold uppercase tracking-wider">Total Decapitations</span>
          <span className="p-1.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </span>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-3xl font-mono font-extrabold text-cyber-text">
            {stats.totalInterceptions}
          </span>
          <span className="text-xs text-rose-400 font-mono">SIGKILL issued</span>
        </div>
        <div className="mt-2 flex items-center text-[11px] text-cyber-muted font-mono">
          <span>Active Endpoints Protected: {stats.activeAgents}</span>
        </div>
      </div>

      {/* Metric 2: Kill Latency */}
      <div className="rounded-xl bg-cyber-card border border-cyber-border p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between text-cyber-muted">
          <span className="text-xs font-semibold uppercase tracking-wider">Avg Response Time</span>
          <span className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </span>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-3xl font-mono font-extrabold text-emerald-400">
            {stats.avgMitigationLatencyMs > 0 ? stats.avgMitigationLatencyMs.toFixed(3) : "0.000"}
          </span>
          <span className="text-xs text-cyber-muted font-mono">ms</span>
        </div>
        <div className="mt-2 flex items-center justify-between text-[11px] text-cyber-muted font-mono">
          <span>Min: {stats.minMitigationLatencyMs.toFixed(3)} ms</span>
          <span>Max: {stats.maxMitigationLatencyMs.toFixed(3)} ms</span>
        </div>
      </div>

      {/* Metric 3: Highest Shannon Entropy */}
      <div className="rounded-xl bg-cyber-card border border-cyber-border p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between text-cyber-muted">
          <span className="text-xs font-semibold uppercase tracking-wider">Peak Entropy H(X)</span>
          <span className="p-1.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </span>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-3xl font-mono font-extrabold text-cyber-text">
            {stats.highestEntropy > 0 ? stats.highestEntropy.toFixed(3) : "7.200"}
          </span>
          <span className="text-xs text-cyber-muted font-mono">/ 8.0 bits</span>
        </div>
        <div className="mt-2 flex items-center text-[11px] text-cyber-muted font-mono">
          <span className="text-rose-400 font-semibold">Threshold: &ge; 7.2 bits</span>
          <span className="mx-1.5">·</span>
          <span>4KB Discrete Blocks</span>
        </div>
      </div>

      {/* Metric 4: Restoration Success Rate */}
      <div className="rounded-xl bg-cyber-card border border-cyber-border p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between text-cyber-muted">
          <span className="text-xs font-semibold uppercase tracking-wider">Micro-Restore Rate</span>
          <span className="p-1.5 rounded-md bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </span>
        </div>
        <div className="mt-2 flex items-baseline space-x-2">
          <span className="text-3xl font-mono font-extrabold text-cyber-neon">
            {stats.restorationSuccessRate.toFixed(1)}%
          </span>
          <span className="text-xs text-cyber-muted font-mono">CoW in-memory</span>
        </div>
        <div className="mt-2 flex items-center text-[11px] text-cyber-muted font-mono">
          <span>0 Bytes User Ransom Paid</span>
        </div>
      </div>
    </div>
  );
}

