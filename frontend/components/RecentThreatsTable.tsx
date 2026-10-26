"use client";

import React, { useState } from "react";
import { ThreatEvent, SeverityType, ActionTakenType } from "@/types/threat";

interface RecentThreatsTableProps {
  threats: ThreatEvent[];
  onSelectThreat?: (threat: ThreatEvent) => void;
}

export function RecentThreatsTable({ threats, onSelectThreat }: RecentThreatsTableProps) {
  const [selectedEvent, setSelectedEvent] = useState<ThreatEvent | null>(null);

  const getSeverityBadge = (severity: SeverityType) => {
    switch (severity) {
      case "CRITICAL":
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/40">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
            <span>CRITICAL</span>
          </span>
        );
      case "HIGH":
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/40">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            <span>HIGH</span>
          </span>
        );
      case "MEDIUM":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            {severity}
          </span>
        );
    }
  };

  const getActionBadge = (action: ActionTakenType) => {
    switch (action) {
      case "KILLED_AND_ROLLED_BACK":
        return (
          <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <svg className="w-3 h-3 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
            </svg>
            <span>KILLED & RESTORED</span>
          </span>
        );
      case "KILLED_ONLY":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
            KILLED ONLY
          </span>
        );
      case "KILL_FAILED":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-rose-500/20 text-rose-300 border border-rose-500/50">
            KILL FAILED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800 text-slate-300">
            {action}
          </span>
        );
    }
  };

  const formatTimestamp = (isoString: string | null) => {
    if (!isoString) return "—";
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        fractionalSecondDigits: 3,
      });
    } catch {
      return isoString;
    }
  };

  return (
    <>
      <div className="overflow-hidden rounded-xl bg-cyber-card border border-cyber-border shadow-2xl flex flex-col">
        {/* Table Toolbar */}
        <div className="px-6 py-4 border-b border-cyber-border/80 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyber-bg border border-cyber-border">
              <svg className="h-4 w-4 text-cyber-neon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-bold tracking-wide text-cyber-text flex items-center gap-2">
                LIVE INTERCEPTIONS &amp; THREAT TELEMETRY
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyber-bg text-cyber-muted border border-cyber-border">
                  {threats.length} Recorded
                </span>
              </h2>
              <p className="text-xs text-cyber-muted">
                Real-time kernel hook events captured by eBPF (Linux) and ETW (Windows)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono bg-cyber-bg border border-cyber-border text-cyber-muted">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping-slow" />
              <span>Streaming WebSocket Active</span>
            </span>
          </div>
        </div>

        {/* The Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border/70 bg-cyber-bg/70 text-cyber-muted font-mono uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Time (UTC)</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Offending Process</th>
                <th className="py-3 px-4">Canary Trap Tripped</th>
                <th className="py-3 px-4">Entropy H(X)</th>
                <th className="py-3 px-4">Kill Latency</th>
                <th className="py-3 px-4">EDR Action</th>
                <th className="py-3 px-4 text-right">Forensics</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/50 font-mono">
              {threats.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-cyber-muted">
                    <div className="flex flex-col items-center justify-center space-y-3">
                      <div className="relative h-12 w-12 rounded-full border border-dashed border-cyber-border flex items-center justify-center">
                        <span className="h-3 w-3 rounded-full bg-cyber-neon/40 animate-ping" />
                      </div>
                      <p className="text-sm font-sans text-cyber-muted">
                        No active canary tripwires triggered. System standing guard.
                      </p>
                      <p className="text-[11px] text-cyber-muted/70">
                        Canary files are armed across Documents, Desktop, and Downloads.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                threats.map((threat, index) => {
                  const isHighEntropy = threat.entropy_score >= 7.2;
                  const isNewest = index === 0;

                  return (
                    <tr
                      key={threat.id || `${threat.malicious_pid}-${index}`}
                      className={`group hover:bg-cyber-cardHover/70 transition-colors ${
                        isNewest ? "bg-rose-950/10 border-l-2 border-l-rose-500" : ""
                      }`}
                    >
                      {/* Timestamp */}
                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        <span className="text-cyber-text font-semibold">
                          {formatTimestamp(threat.timestamp)}
                        </span>
                        <div className="text-[10px] text-cyber-muted/80">
                          {threat.host_identifier}
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        {getSeverityBadge(threat.severity)}
                      </td>

                      {/* Malicious Process */}
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="px-1.5 py-0.5 rounded bg-cyber-bg text-cyber-muted text-[10px] border border-cyber-border">
                            PID {threat.malicious_pid}
                          </span>
                          <span className="text-cyber-text font-medium text-[12px] truncate max-w-[140px]" title={threat.process_name || ""}>
                            {threat.process_name || "unknown"}
                          </span>
                        </div>
                        {threat.process_user && (
                          <div className="text-[10px] text-cyber-muted/80 mt-0.5 truncate max-w-[140px]">
                            user: {threat.process_user}
                          </div>
                        )}
                      </td>

                      {/* Canary Path */}
                      <td className="py-3 px-4 max-w-[200px]">
                        <div className="truncate text-cyber-text font-medium text-[11px]" title={threat.target_canary_path}>
                          {threat.target_canary_path.split("/").pop() ||
                            threat.target_canary_path.split("\\").pop()}
                        </div>
                        <div className="flex items-center space-x-1.5 text-[10px] text-cyber-muted mt-0.5">
                          <span className="px-1 py-0.2 rounded bg-cyber-bg/80 border border-cyber-border text-cyber-muted">
                            {threat.canary_naming_tier || "honeypot"}
                          </span>
                          <span className="truncate" title={threat.target_canary_path}>
                            {threat.target_canary_path}
                          </span>
                        </div>
                      </td>

                      {/* Shannon Entropy */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`font-bold ${
                              isHighEntropy ? "text-rose-400" : "text-amber-400"
                            }`}
                          >
                            {threat.entropy_score.toFixed(3)}
                          </span>
                          <span className="text-[10px] text-cyber-muted">/ 8.0</span>
                        </div>
                        <div className="mt-1 h-1.5 w-24 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border/70">
                          <div
                            className={`h-full ${
                              isHighEntropy
                                ? "bg-rose-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"
                                : "bg-amber-400"
                            }`}
                            style={{
                              width: `${(threat.entropy_score / 8.0) * 100}%`,
                            }}
                          />
                        </div>
                      </td>

                      {/* Kill Latency */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="font-semibold text-emerald-400">
                          {threat.mitigation_latency_ms.toFixed(3)} ms
                        </span>
                        {threat.kill_latency_us && (
                          <div className="text-[10px] text-cyber-muted">
                            kill: {Number(threat.kill_latency_us).toFixed(1)} µs
                          </div>
                        )}
                      </td>

                      {/* EDR Action */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        {getActionBadge(threat.action_taken)}
                      </td>

                      {/* Inspect Button */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => {
                            setSelectedEvent(threat);
                            if (onSelectThreat) onSelectThreat(threat);
                          }}
                          className="px-2.5 py-1 text-[11px] rounded bg-cyber-bg hover:bg-cyber-border text-cyber-muted hover:text-cyber-text border border-cyber-border transition"
                        >
                          Forensics
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-2xl rounded-xl bg-cyber-card border border-cyber-border shadow-2xl p-6 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-2">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500 animate-pulse" />
                <h3 className="text-sm font-bold text-cyber-text uppercase tracking-wider">
                  Threat Event Forensic Dump · Incident #{selectedEvent.id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-cyber-muted hover:text-cyber-text p-1 text-base leading-none"
              >
                ✕
              </button>
            </div>

            <div className="my-4 grid grid-cols-2 gap-4 text-cyber-text">
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">Host Endpoint</span>
                <span className="font-bold">{selectedEvent.host_identifier}</span> ({selectedEvent.host_os})
              </div>
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">Offending PID</span>
                <span className="font-bold text-rose-400">{selectedEvent.malicious_pid}</span> ({selectedEvent.process_name || "unknown"})
              </div>
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">Target Canary Path</span>
                <span className="break-all text-[11px]">{selectedEvent.target_canary_path}</span>
              </div>
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">Calculated Shannon Entropy</span>
                <span className="font-bold text-rose-400">{selectedEvent.entropy_score} bits</span> (Threshold: 7.2)
              </div>
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">Decapitation &amp; Restore Latency</span>
                <span className="font-bold text-emerald-400">{selectedEvent.mitigation_latency_ms} ms</span>
              </div>
              <div>
                <span className="text-cyber-muted block text-[10px] uppercase">EDR Mitigation Outcome</span>
                <span className="font-bold text-emerald-400">{selectedEvent.action_taken}</span>
              </div>
            </div>

            {selectedEvent.process_cmdline && (
              <div className="mb-4">
                <span className="text-cyber-muted block text-[10px] uppercase mb-1">Process Command Line</span>
                <pre className="p-2 rounded bg-cyber-bg border border-cyber-border text-[11px] overflow-x-auto text-amber-300">
                  {selectedEvent.process_cmdline}
                </pre>
              </div>
            )}

            <div>
              <span className="text-cyber-muted block text-[10px] uppercase mb-1">Raw JSON Telemetry Payload</span>
              <pre className="p-3 rounded bg-cyber-bg border border-cyber-border text-[10px] text-cyber-muted overflow-x-auto max-h-48">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded bg-cyber-border hover:bg-slate-700 text-cyber-text text-xs transition"
              >
                Close Forensics
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

