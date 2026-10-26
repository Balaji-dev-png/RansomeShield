"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { ThreatEvent, ConnectionStatus, SocSystemStats } from "@/types/threat";

const DEFAULT_WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/soc";

const MAX_EVENT_BUFFER = 100;

export function useSocWebSocket(url: string = DEFAULT_WS_URL) {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [latestThreat, setLatestThreat] = useState<ThreatEvent | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("CONNECTING");
  const [activeClients, setActiveClients] = useState<number>(0);
  const [lastHeartbeat, setLastHeartbeat] = useState<Date | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptRef = useRef<number>(0);
  const simulationIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Compute live aggregates
  const stats: SocSystemStats = {
    totalInterceptions: events.length,
    activeAgents: Math.max(1, new Set(events.map((e) => e.host_identifier)).size),
    avgMitigationLatencyMs:
      events.length > 0
        ? Number(
            (
              events.reduce((sum, e) => sum + e.mitigation_latency_ms, 0) /
              events.length
            ).toFixed(3)
          )
        : 0.0,
    minMitigationLatencyMs:
      events.length > 0
        ? Math.min(...events.map((e) => e.mitigation_latency_ms))
        : 0.0,
    maxMitigationLatencyMs:
      events.length > 0
        ? Math.max(...events.map((e) => e.mitigation_latency_ms))
        : 0.0,
    highestEntropy:
      events.length > 0
        ? Math.max(...events.map((e) => e.entropy_score))
        : 0.0,
    restorationSuccessRate:
      events.length > 0
        ? Number(
            (
              (events.filter(
                (e) =>
                  e.action_taken === "KILLED_AND_ROLLED_BACK" ||
                  e.action_taken === "ROLLBACK_ONLY"
              ).length /
                events.length) *
              100
            ).toFixed(1)
          )
        : 100,
  };

  const handleIncomingThreat = useCallback((threat: ThreatEvent) => {
    setLatestThreat(threat);
    setEvents((prev) => {
      // Deduplicate if needed by id
      const exists = prev.some((e) => e.id === threat.id);
      if (exists) return prev;
      return [threat, ...prev].slice(0, MAX_EVENT_BUFFER);
    });
  }, []);

  const connect = useCallback(() => {
    if (socketRef.current && (socketRef.current.readyState === WebSocket.OPEN || socketRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setStatus("CONNECTING");

    try {
      const ws = new WebSocket(url);
      socketRef.current = ws;

      ws.onopen = () => {
        setStatus("CONNECTED");
        reconnectAttemptRef.current = 0;
        setLastHeartbeat(new Date());

        // Setup 15s keepalive ping
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Handle system handshake / metadata
          if (data.type === "connection_established") {
            setActiveClients(data.active_soc_clients || 1);
            setLastHeartbeat(new Date());
            return;
          }

          if (data.type === "pong") {
            setActiveClients(data.active_soc_clients || 1);
            setLastHeartbeat(new Date());
            return;
          }

          // Handle threat telemetry payload
          if (data.entropy_score !== undefined || data.target_canary_path) {
            handleIncomingThreat(data as ThreatEvent);
          }
        } catch (err) {
          console.error("[useSocWebSocket] Failed to parse message:", err, event.data);
        }
      };

      ws.onerror = () => {
        setStatus("ERROR");
      };

      ws.onclose = () => {
        setStatus("DISCONNECTED");
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);

        // Schedule auto-reconnect with exponential backoff
        const timeout = Math.min(1000 * Math.pow(1.5, reconnectAttemptRef.current), 10000);
        reconnectAttemptRef.current += 1;
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, timeout);
      };
    } catch (err) {
      console.error("[useSocWebSocket] Connection init error:", err);
      setStatus("ERROR");
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    }
  }, [url, handleIncomingThreat]);

  // Clean shutdown
  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (simulationIntervalRef.current) clearInterval(simulationIntervalRef.current);
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [connect]);

  // Capstone Demo Attack Simulator (Toggleable from the dashboard)
  const toggleSimulation = useCallback(() => {
    setIsSimulating((prev) => {
      const nextState = !prev;
      if (nextState) {
        // Start emitting realistic ransomware detections every 3-5 seconds
        const runMockStep = () => {
          const sampleHosts = [
            { host: "ws-finance-042", os: "Linux 6.8.0-generic", user: "j.smith" },
            { host: "exec-laptop-09", os: "Windows 11 Pro 23H2", user: "c.miller" },
            { host: "db-backup-srv3", os: "Linux 6.1.0-21-amd64", user: "svc_backup" },
            { host: "dev-workstation-12", os: "Linux 6.8.0-generic", user: "b.developer" },
          ];
          const sampleProcesses = [
            { name: "svchost_updater.bin", path: "/tmp/.cache/svchost_updater.bin", cmd: "./svchost_updater.bin --no-banner" },
            { name: "winword_macro.exe", path: "C:\\Users\\AppData\\Local\\Temp\\winword_macro.exe", cmd: "winword_macro.exe -silent" },
            { name: "crypt_daemon", path: "/usr/local/bin/.crypt_daemon", cmd: "crypt_daemon --encrypt /home/user" },
            { name: "lockbit3_sim.exe", path: "C:\\Temp\\lockbit3_sim.exe", cmd: "lockbit3_sim.exe -pass test" },
          ];
          const sampleCanaries = [
            { path: "/home/user/Documents/_00_confidential.docx", tier: "alpha_first" },
            { path: "C:\\Users\\Desktop\\!_URGENT.xlsx", tier: "alpha_first" },
            { path: "/home/user/Downloads/ZZ_passwords.txt", tier: "alpha_last" },
            { path: "C:\\Users\\Documents\\000_records.sql", tier: "numeric" },
            { path: "/home/user/Desktop/~~~archive.key", tier: "alpha_last" },
          ];

          const hostObj = sampleHosts[Math.floor(Math.random() * sampleHosts.length)];
          const procObj = sampleProcesses[Math.floor(Math.random() * sampleProcesses.length)];
          const canaryObj = sampleCanaries[Math.floor(Math.random() * sampleCanaries.length)];

          // Real ransomware entropy is high (7.82 - 7.99)
          const entropy = Number((7.45 + Math.random() * 0.54).toFixed(4));
          const killUs = Number((45 + Math.random() * 85).toFixed(1));
          const restoreUs = Number((120 + Math.random() * 180).toFixed(1));
          const totalMs = Number(((killUs + restoreUs) / 1000 + 0.12).toFixed(3));
          const pid = Math.floor(10000 + Math.random() * 80000);

          const mockEvent: ThreatEvent = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            agent_timestamp: new Date().toISOString(),
            host_identifier: hostObj.host,
            host_os: hostObj.os,
            agent_version: "0.1.0",
            malicious_pid: pid,
            process_name: procObj.name,
            process_path: procObj.path,
            process_user: hostObj.user,
            process_cmdline: procObj.cmd,
            target_canary_path: canaryObj.path,
            canary_naming_tier: canaryObj.tier,
            entropy_score: entropy,
            mean_entropy: Number((entropy - 0.08).toFixed(4)),
            blocks_analyzed: 4,
            blocks_above_threshold: 4,
            severity: entropy >= 7.8 ? "CRITICAL" : "HIGH",
            action_taken: "KILLED_AND_ROLLED_BACK",
            mitigation_latency_ms: totalMs,
            kill_latency_us: killUs,
            restore_latency_us: restoreUs,
            children_killed: Math.random() > 0.6 ? Math.floor(Math.random() * 3) + 1 : 0,
            agent_metadata: {
              block_entropies: [entropy, entropy - 0.02, entropy + 0.01, entropy - 0.04],
              heuristic: "eBPF_VFS_WRITE_TRIPWIRE",
            },
          };

          handleIncomingThreat(mockEvent);
        };

        // Run one immediately then interval
        runMockStep();
        simulationIntervalRef.current = setInterval(runMockStep, 4000);
      } else {
        if (simulationIntervalRef.current) {
          clearInterval(simulationIntervalRef.current);
          simulationIntervalRef.current = null;
        }
      }
      return nextState;
    });
  }, [handleIncomingThreat]);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setLatestThreat(null);
  }, []);

  return {
    events,
    latestThreat,
    status,
    activeClients,
    lastHeartbeat,
    stats,
    isSimulating,
    toggleSimulation,
    clearEvents,
    reconnect: connect,
  };
}

