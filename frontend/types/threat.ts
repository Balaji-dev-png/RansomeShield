/**
 * RansomShield SOC Dashboard — Telemetry Types & Contract
 *
 * Direct client-side counterpart to the C++ EDR agent and FastAPI backend models.
 */

export type ActionTakenType =
  | "KILLED_AND_ROLLED_BACK"
  | "KILLED_ONLY"
  | "ROLLBACK_ONLY"
  | "DETECTED_ONLY"
  | "KILL_FAILED"
  | "FULL_FAILURE";

export type SeverityType = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ThreatEvent {
  id: number;
  timestamp: string | null;           // ISO 8601 string from backend
  agent_timestamp?: string | null;
  host_identifier: string;            // e.g. "endpoint-alpha-01"
  host_os: string;                    // e.g. "Linux 6.8.0-generic" or "Windows 11 23H2"
  agent_version?: string | null;
  malicious_pid: number;
  process_name?: string | null;       // e.g. "wannacry_payload.bin"
  process_path?: string | null;
  process_user?: string | null;
  process_cmdline?: string | null;
  target_canary_path: string;         // e.g. "/home/user/Documents/_00_confidential.docx"
  canary_naming_tier?: string | null; // "alpha_first" | "alpha_last" | "numeric"
  entropy_score: number;              // Shannon entropy [0.0 - 8.0]
  mean_entropy?: number | null;
  blocks_analyzed?: number | null;
  blocks_above_threshold?: number | null;
  severity: SeverityType;
  action_taken: ActionTakenType;
  mitigation_latency_ms: number;      // e.g. 0.42 ms
  kill_latency_us?: number | null;    // e.g. 78.4 us
  restore_latency_us?: number | null; // e.g. 195.2 us
  children_killed?: number | null;
  agent_metadata?: {
    block_entropies?: number[];
    cpu_load?: number;
    [key: string]: any;
  } | null;
}

export type ConnectionStatus = "CONNECTING" | "CONNECTED" | "DISCONNECTED" | "ERROR";

export interface SocSystemStats {
  totalInterceptions: number;
  activeAgents: number;
  avgMitigationLatencyMs: number;
  minMitigationLatencyMs: number;
  maxMitigationLatencyMs: number;
  highestEntropy: number;
  restorationSuccessRate: number;
}

