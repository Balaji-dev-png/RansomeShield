"""
RansomShield Backend — SQLAlchemy ORM Models

Defines the PostgreSQL schema for storing EDR telemetry events. Each row
in the threat_events table represents a single detection-and-response
lifecycle: a canary was tripped, entropy was analyzed, a process was killed,
and a file was restored.

Schema Design Rationale:
────────────────────────
- Timestamp is server-side (server_default) to avoid clock skew between
  agents and the backend. The agent_timestamp column preserves the agent's
  local time for forensic correlation.

- Indexed columns: host_identifier, severity, action_taken — these are
  the primary SOC dashboard filter axes (show me all CRITICAL events on
  host X that were KILLED_AND_ROLLED_BACK).

- entropy_score uses Float (double precision) because Shannon entropy is
  a continuous value in [0.0, 8.0] and we need sub-decimal precision for
  threshold tuning analysis.

- The agent_metadata JSONB column stores arbitrary agent-reported data
  (OS version, agent version, CPU load at detection time, etc.) without
  requiring schema migrations for every new field.
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────


class ActionTaken(str, enum.Enum):
    """
    Possible response actions the agent can take when a canary is tripped.

    These map directly to the C++ MitigationEngine outcomes:
      - KILLED_AND_ROLLED_BACK: Process killed + canary restored (ideal case).
      - KILLED_ONLY:            Process killed but restore failed.
      - ROLLBACK_ONLY:          Process already dead, canary restored.
      - DETECTED_ONLY:          Entropy was below threshold; logged only.
      - KILL_FAILED:            Process termination failed (permissions).
      - FULL_FAILURE:           Both kill and restore failed.
    """

    KILLED_AND_ROLLED_BACK = "KILLED_AND_ROLLED_BACK"
    KILLED_ONLY = "KILLED_ONLY"
    ROLLBACK_ONLY = "ROLLBACK_ONLY"
    DETECTED_ONLY = "DETECTED_ONLY"
    KILL_FAILED = "KILL_FAILED"
    FULL_FAILURE = "FULL_FAILURE"


class Severity(str, enum.Enum):
    """
    Threat severity classification based on entropy score and response outcome.

    Classification rules (applied by the agent):
      - CRITICAL: Entropy >= 7.8 (strong encryption detected, likely AES/ChaCha).
      - HIGH:     Entropy >= 7.2 (encryption threshold crossed).
      - MEDIUM:   Entropy >= 6.5 (suspicious but may be compression).
      - LOW:      Entropy <  6.5 (likely benign modification).
      - INFO:     Informational event (agent heartbeat, config change).
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# ThreatEvent Model
# ─────────────────────────────────────────────────────────────────────────────


class ThreatEvent(Base):
    """
    Represents a single threat detection-and-response event from the EDR agent.

    One row = one complete lifecycle:
        Canary tripped → Entropy analyzed → Process killed → File restored

    This table is the primary data source for the SOC dashboard. The frontend
    queries it for real-time event feeds, historical analysis, and host-level
    threat timelines.
    """

    __tablename__ = "threat_events"

    # ── Primary Key ───────────────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Auto-incrementing primary key.",
    )

    # ── Timestamps ────────────────────────────────────────────────────────

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        comment="Server-side UTC timestamp when the event was received.",
    )

    agent_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Agent-side timestamp (may differ from server due to clock skew).",
    )

    # ── Host Identification ───────────────────────────────────────────────

    host_identifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Unique host identifier (hostname or machine UUID).",
    )

    host_os: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment='Operating system of the reporting agent (e.g., "Linux 6.1", "Windows 11").',
    )

    agent_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment='Version of the RansomShield agent (e.g., "0.1.0").',
    )

    # ── Threat Details ────────────────────────────────────────────────────

    malicious_pid: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="PID of the process that triggered the canary.",
    )

    process_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Name of the offending process (from /proc/<pid>/comm or ToolHelp32).",
    )

    process_path: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Full executable path of the offending process.",
    )

    process_user: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="User context the offending process was running under.",
    )

    process_cmdline: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Full command line of the offending process (forensics).",
    )

    target_canary_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Absolute path of the canary file that was tripped.",
    )

    canary_naming_tier: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        comment='Which naming tier triggered: "alpha_first", "alpha_last", "numeric".',
    )

    # ── Entropy Analysis ──────────────────────────────────────────────────

    entropy_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Maximum Shannon entropy across all analyzed 4KB blocks [0.0, 8.0].",
    )

    mean_entropy: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Mean Shannon entropy across all analyzed blocks.",
    )

    blocks_analyzed: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Number of 4KB blocks analyzed.",
    )

    blocks_above_threshold: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Number of blocks with entropy above the detection threshold.",
    )

    entropy_threshold: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Entropy threshold used for this detection (default: 7.2).",
    )

    # ── Response Outcome ──────────────────────────────────────────────────

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_enum", create_constraint=True),
        nullable=False,
        index=True,
        default=Severity.HIGH,
        comment="Threat severity classification based on entropy and outcome.",
    )

    action_taken: Mapped[ActionTaken] = mapped_column(
        Enum(ActionTaken, name="action_taken_enum", create_constraint=True),
        nullable=False,
        index=True,
        comment="Response action taken by the agent.",
    )

    # ── Performance Metrics ───────────────────────────────────────────────

    mitigation_latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Total time from canary event to process kill, in milliseconds.",
    )

    kill_latency_us: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Time for the kill syscall alone, in microseconds.",
    )

    restore_latency_us: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Time for the file restoration, in microseconds.",
    )

    children_killed: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        default=0,
        comment="Number of child processes also terminated (tree kill).",
    )

    # ── Flexible Metadata ─────────────────────────────────────────────────

    agent_metadata: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Arbitrary JSON metadata from the agent (per-block entropies, etc.).",
    )

    # ── Table-Level Indexes ───────────────────────────────────────────────
    # Composite indexes for common SOC dashboard query patterns.

    __table_args__ = (
        # "Show me all CRITICAL events on host X in the last 24h"
        Index(
            "ix_threat_host_severity_time",
            "host_identifier",
            "severity",
            "timestamp",
        ),
        # "Show me all events where kill failed"
        Index("ix_threat_action_time", "action_taken", "timestamp"),
        {"comment": "EDR threat detection and response events from RansomShield agents."},
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatEvent(id={self.id}, host={self.host_identifier!r}, "
            f"pid={self.malicious_pid}, entropy={self.entropy_score:.4f}, "
            f"action={self.action_taken.value}, severity={self.severity.value})>"
        )

    def to_broadcast_dict(self) -> dict:
        """
        Serialize this event to a dict suitable for WebSocket broadcast
        to the SOC dashboard. Excludes internal fields and formats
        timestamps as ISO 8601 strings.

        This is called after the DB insert so self.id and self.timestamp
        are populated by the database.
        """
        return {
            "id": self.id,
            "timestamp": (
                self.timestamp.isoformat() if self.timestamp else None
            ),
            "agent_timestamp": (
                self.agent_timestamp.isoformat()
                if self.agent_timestamp
                else None
            ),
            "host_identifier": self.host_identifier,
            "host_os": self.host_os,
            "agent_version": self.agent_version,
            "malicious_pid": self.malicious_pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "process_user": self.process_user,
            "target_canary_path": self.target_canary_path,
            "canary_naming_tier": self.canary_naming_tier,
            "entropy_score": self.entropy_score,
            "mean_entropy": self.mean_entropy,
            "blocks_analyzed": self.blocks_analyzed,
            "blocks_above_threshold": self.blocks_above_threshold,
            "severity": self.severity.value,
            "action_taken": self.action_taken.value,
            "mitigation_latency_ms": self.mitigation_latency_ms,
            "kill_latency_us": self.kill_latency_us,
            "restore_latency_us": self.restore_latency_us,
            "children_killed": self.children_killed,
            "agent_metadata": self.agent_metadata,
        }

