"use client";

import React, { useState, useEffect } from "react";
import { ConnectionStatus } from "@/types/threat";

interface SocHeaderProps {
  status: ConnectionStatus;
  activeClients: number;
  isSimulating: boolean;
  onToggleSimulation: () => void;
  onClearEvents: () => void;
  onReconnect: () => void;
}

export function SocHeader({
  status,
  activeClients,
  isSimulating,
  onToggleSimulation,
  onClearEvents,
  onReconnect,
}: SocHeaderProps) {
  const [timeString, setTimeString] = useState<string>("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeString(
        now.toUTCString().replace("GMT", "UTC")
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="border-b border-cyber-border bg-cyber-bg/95 backdrop-blur sticky top-0 z-40 px-6 py-4">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div className="flex items-center space-x-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-rose-600 via-rose-700 to-amber-600 shadow-[0_0_15px_rgba(239,68,68,0.4)]">
            <svg
              className="h-6 w-6 text-white"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2.2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500" />
            </span>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-black tracking-wider text-cyber-text">
                RANSOM<span className="text-rose-500">SHIELD</span>
              </h1>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyber-border text-cyber-neon">
                EDR v0.1.0
              </span>
            </div>
            <p className="text-[11px] font-mono text-cyber-muted">
              Decoy Canary &middot; eBPF/ETW Kernel Hooks &middot; Shannon Decapitation Engine
            </p>
          </div>
        </div>

        {/* Center / Status indicators */}
        <div className="flex items-center space-x-4">
          {/* WebSocket Status */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border font-mono text-xs">
            <span className="text-cyber-muted">SOC Stream:</span>
            {status === "CONNECTED" ? (
              <span className="inline-flex items-center space-x-1.5 text-emerald-400">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>ONLINE</span>
              </span>
            ) : status === "CONNECTING" ? (
              <span className="inline-flex items-center space-x-1.5 text-amber-400">
                <span className="h-2 w-2 rounded-full bg-amber-400 animate-ping" />
                <span>CONNECTING</span>
              </span>
            ) : (
              <button
                onClick={onReconnect}
                className="inline-flex items-center space-x-1 text-rose-400 hover:underline"
              >
                <span className="h-2 w-2 rounded-full bg-rose-500" />
                <span>OFFLINE (RETRY)</span>
              </button>
            )}
            {activeClients > 0 && (
              <span className="text-cyber-muted/70 pl-1 border-l border-cyber-border">
                {activeClients} {activeClients === 1 ? "Analyst" : "Analysts"}
              </span>
            )}
          </div>

          {/* Clock */}
          <div className="hidden lg:block text-right font-mono text-xs text-cyber-muted">
            <div className="text-cyber-text font-semibold">{timeString || "SYNCHRONIZING..."}</div>
            <div className="text-[10px] text-cyber-muted/80">GLOBAL SOC TIME</div>
          </div>
        </div>

        {/* Actions / Capstone Demo Controls */}
        <div className="flex items-center space-x-2">
          {/* Simulation Toggle */}
          <button
            onClick={onToggleSimulation}
            className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold flex items-center space-x-2 border transition shadow-sm ${
              isSimulating
                ? "bg-rose-500/20 text-rose-300 border-rose-500/60 shadow-[0_0_12px_rgba(239,68,68,0.4)]"
                : "bg-cyber-card hover:bg-cyber-cardHover text-cyber-text border-cyber-border"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isSimulating ? "bg-rose-500 animate-pulse" : "bg-cyber-muted"
              }`}
            />
            <span>{isSimulating ? "Stop Simulation" : "Simulate Ransomware Attack"}</span>
          </button>

          {/* Clear Log */}
          <button
            onClick={onClearEvents}
            title="Clear event buffer"
            className="p-1.5 rounded-lg bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border text-cyber-muted hover:text-cyber-text transition"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
}

