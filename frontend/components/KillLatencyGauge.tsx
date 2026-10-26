"use client";

import React from "react";
import { ThreatEvent } from "@/types/threat";

interface KillLatencyGaugeProps {
  latestThreat: ThreatEvent | null;
  avgLatencyMs: number;
}

export function KillLatencyGauge({
  latestThreat,
  avgLatencyMs,
}: KillLatencyGaugeProps) {
  const latencyMs = latestThreat?.mitigation_latency_ms ?? avgLatencyMs ?? 0.0;
  const killUs = latestThreat?.kill_latency_us ?? (latencyMs * 400); // approx estimate if null
  const restoreUs = latestThreat?.restore_latency_us ?? (latencyMs * 600);

  // Normalization for the 0 to 5ms gauge scale
  // RansomShield aims for sub-millisecond execution (< 1.0ms)
  const maxScale = 5.0; // 5ms top of dial
  const percentage = Math.min(Math.max((latencyMs / maxScale) * 100, 4), 100);

  // SVG Gauge calculations (Semi-circle arc)
  // Radius = 80, Circumference of half circle = PI * R ≈ 251.3
  const radius = 78;
  const strokeWidth = 12;
  const arcLength = Math.PI * radius; // half circle perimeter
  const strokeDashoffset = arcLength - (arcLength * percentage) / 100;

  // Determine threat latency state
  let statusColor = "#10B981"; // Emerald (< 1ms)
  let statusBadge = "SUB-MILLISECOND (OPTIMAL)";
  let statusBg = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";

  if (latencyMs > 3.0) {
    statusColor = "#EF4444"; // Red (> 3ms)
    statusBadge = "ELEVATED DECAPITATION TIME";
    statusBg = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  } else if (latencyMs > 1.0) {
    statusColor = "#F59E0B"; // Amber (1 - 3ms)
    statusBadge = "NOMINAL (MODERATE LOAD)";
    statusBg = "bg-amber-500/10 text-amber-400 border-amber-500/30";
  }

  return (
    <div className="relative overflow-hidden rounded-xl bg-cyber-card border border-cyber-border p-6 shadow-2xl flex flex-col justify-between">
      {/* Background glow effect based on latency status */}
      <div
        className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full blur-3xl opacity-15 transition-all duration-700"
        style={{ backgroundColor: statusColor }}
      />

      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
        <div className="flex items-center space-x-2.5">
          <span className="flex h-2.5 w-2.5 relative">
            <span
              className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
              style={{ backgroundColor: statusColor }}
            />
            <span
              className="relative inline-flex rounded-full h-2.5 w-2.5"
              style={{ backgroundColor: statusColor }}
            />
          </span>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">
            Response Metric · Process Decapitation Latency
          </h3>
        </div>
        <span
          className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${statusBg}`}
        >
          {statusBadge}
        </span>
      </div>

      {/* Main Visual Radial Gauge */}
      <div className="my-4 flex flex-col items-center justify-center">
        <div className="relative w-56 h-32 flex items-center justify-center overflow-visible">
          <svg className="w-56 h-36 overflow-visible" viewBox="0 0 200 120">
            <defs>
              <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#10B981" />
                <stop offset="60%" stopColor="#06B6D4" />
                <stop offset="85%" stopColor="#F59E0B" />
                <stop offset="100%" stopColor="#EF4444" />
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Background Track (Muted dark slate arc) */}
            <path
              d="M 22 105 A 78 78 0 0 1 178 105"
              fill="none"
              stroke="#1C283F"
              strokeWidth={strokeWidth}
              strokeLinecap="round"
            />

            {/* Scale Tick Markers */}
            <circle cx="22" cy="105" r="2" fill="#475569" />
            <circle cx="100" cy="27" r="2" fill="#475569" />
            <circle cx="178" cy="105" r="2" fill="#475569" />

            {/* Active Colored Arc */}
            <path
              d="M 22 105 A 78 78 0 0 1 178 105"
              fill="none"
              stroke="url(#gaugeGradient)"
              strokeWidth={strokeWidth}
              strokeDasharray={arcLength}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              filter="url(#glow)"
              className="transition-all duration-700 ease-out"
            />
          </svg>

          {/* Centered Readout */}
          <div className="absolute bottom-1 text-center flex flex-col items-center">
            <div className="flex items-baseline space-x-1">
              <span className="font-mono text-4xl font-extrabold tracking-tight text-cyber-text">
                {latencyMs > 0 ? latencyMs.toFixed(3) : "0.000"}
              </span>
              <span className="font-mono text-sm text-cyber-muted font-medium">ms</span>
            </div>
            <span className="text-[11px] font-mono text-cyber-muted uppercase tracking-wider">
              {latestThreat ? "Last Interception" : "Agent Baseline"}
            </span>
          </div>
        </div>

        {/* Gauge Scale Labels */}
        <div className="w-56 flex justify-between text-[10px] font-mono text-cyber-muted px-2 -mt-1">
          <span>0.0 ms</span>
          <span>1.0 ms</span>
          <span>2.5 ms</span>
          <span>5.0 ms</span>
        </div>
      </div>

      {/* Latency Breakdown Details (Sub-microsecond breakdown) */}
      <div className="grid grid-cols-2 gap-3 pt-3 border-t border-cyber-border/70">
        <div className="rounded-lg bg-cyber-bg/80 border border-cyber-border/80 p-2.5">
          <div className="flex items-center justify-between text-[11px] text-cyber-muted">
            <span className="flex items-center space-x-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
              <span>SIGKILL Decapitation</span>
            </span>
            <span className="font-mono text-xs font-semibold text-rose-400">
              {killUs ? `${Number(killUs).toFixed(1)} µs` : "—"}
            </span>
          </div>
          <div className="mt-1 h-1 w-full bg-cyber-card rounded-full overflow-hidden">
            <div
              className="h-full bg-rose-500 transition-all duration-500"
              style={{
                width: `${Math.min(((Number(killUs) || 0) / 500) * 100, 100)}%`,
              }}
            />
          </div>
        </div>

        <div className="rounded-lg bg-cyber-bg/80 border border-cyber-border/80 p-2.5">
          <div className="flex items-center justify-between text-[11px] text-cyber-muted">
            <span className="flex items-center space-x-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              <span>CoW Micro-Restore</span>
            </span>
            <span className="font-mono text-xs font-semibold text-emerald-400">
              {restoreUs ? `${Number(restoreUs).toFixed(1)} µs` : "—"}
            </span>
          </div>
          <div className="mt-1 h-1 w-full bg-cyber-card rounded-full overflow-hidden">
            <div
              className="h-full bg-emerald-500 transition-all duration-500"
              style={{
                width: `${Math.min(((Number(restoreUs) || 0) / 1000) * 100, 100)}%`,
              }}
            />
          </div>
        </div>
      </div>

      {/* Micro Footer Notice */}
      <div className="mt-3 flex items-center justify-between text-[10px] text-cyber-muted font-mono">
        <span>Target SLA: &lt; 1000 µs (1.0 ms)</span>
        <span>Avg: {avgLatencyMs.toFixed(3)} ms</span>
      </div>
    </div>
  );
}

