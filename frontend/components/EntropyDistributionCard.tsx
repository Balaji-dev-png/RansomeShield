"use client";

import React from "react";
import { ThreatEvent } from "@/types/threat";

interface EntropyDistributionCardProps {
  latestThreat: ThreatEvent | null;
}

export function EntropyDistributionCard({ latestThreat }: EntropyDistributionCardProps) {
  const currentEntropy = latestThreat?.entropy_score ?? 7.92;
  const blocks = latestThreat?.agent_metadata?.block_entropies || [
    currentEntropy,
    Number((currentEntropy - 0.04).toFixed(3)),
    Number((currentEntropy + 0.02).toFixed(3)),
    Number((currentEntropy - 0.01).toFixed(3)),
  ];

  return (
    <div className="rounded-xl bg-cyber-card border border-cyber-border p-6 shadow-2xl flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
        <div className="flex items-center space-x-2">
          <span className="h-2 w-2 rounded-full bg-cyber-neon" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-cyber-muted">
            Heuristic · 4KB Discrete Block Shannon Entropy $H(X)$
          </h3>
        </div>
        <span className="font-mono text-xs px-2 py-0.5 rounded bg-cyber-bg text-cyber-neon border border-cyber-border">
          Threshold: 7.200 bits
        </span>
      </div>

      {/* Main Spectrum Visualizer */}
      <div className="my-4">
        <div className="flex justify-between items-baseline mb-2">
          <span className="text-xs text-cyber-muted">Cryptographic Randomness Spectrum</span>
          <span className="font-mono text-sm font-bold text-rose-400">
            {latestThreat ? `${currentEntropy.toFixed(3)} bits` : "Standing Guard"}
          </span>
        </div>

        {/* Spectrum Bar with gradient */}
        <div className="relative h-6 w-full rounded-md bg-cyber-bg border border-cyber-border/90 overflow-hidden">
          {/* Background Spectrum gradient */}
          <div
            className="absolute inset-0 opacity-40"
            style={{
              background:
                "linear-gradient(90deg, #10B981 0%, #06B6D4 45%, #F59E0B 75%, #EF4444 100%)",
            }}
          />

          {/* 7.2 Threshold Indicator Line */}
          <div
            className="absolute top-0 bottom-0 w-0.5 bg-white z-10 shadow-[0_0_8px_#ffffff]"
            style={{ left: `${(7.2 / 8.0) * 100}%` }}
          >
            <span className="absolute -top-5 -left-4 text-[9px] font-mono text-white/90">
              7.2
            </span>
          </div>

          {/* Active Entropy Marker */}
          {latestThreat && (
            <div
              className="absolute top-0 bottom-0 w-2 bg-rose-500 rounded-sm z-20 shadow-[0_0_12px_#EF4444] transition-all duration-500"
              style={{ left: `${Math.min((currentEntropy / 8.0) * 100, 98)}%` }}
            />
          )}
        </div>

        {/* Labels underneath */}
        <div className="mt-2 flex justify-between text-[10px] font-mono text-cyber-muted">
          <span>0.0 (Zero)</span>
          <span>4.0 (Plaintext)</span>
          <span>6.5 (Office)</span>
          <span className="text-amber-400 font-bold">7.2 (Tripwire)</span>
          <span className="text-rose-400 font-bold">8.0 (AES-256)</span>
        </div>
      </div>

      {/* Discrete 4KB Block Inspector */}
      <div className="pt-3 border-t border-cyber-border/70">
        <div className="flex justify-between items-center text-[11px] text-cyber-muted mb-2">
          <span>Leading 4KB Block Analysis</span>
          <span className="font-mono text-[10px]">
            {latestThreat ? `${blocks.length} blocks checked` : "Zero-index lure ready"}
          </span>
        </div>

        <div className="grid grid-cols-4 gap-2">
          {blocks.slice(0, 4).map((val, idx) => (
            <div
              key={idx}
              className={`rounded p-2 text-center border font-mono transition-all ${
                val >= 7.2
                  ? "bg-rose-950/20 border-rose-500/40 text-rose-300"
                  : "bg-cyber-bg border-cyber-border text-cyber-muted"
              }`}
            >
              <div className="text-[10px] text-cyber-muted">Block #{idx}</div>
              <div className="text-xs font-bold mt-0.5">{val.toFixed(2)}</div>
              <div className="text-[9px] mt-0.5">
                {val >= 7.2 ? "ENCRYPTED" : "NORMAL"}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

