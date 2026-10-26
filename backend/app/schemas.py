"""
RansomShield Backend — Pydantic Schemas for Validation & Serialization

These schemas serve as the contract between the C++ agent and the FastAPI
backend. The agent sends JSON payloads over WebSocket; these schemas validate
the payload structure and coerce types before database insertion.

Separation from SQLAlchemy models is intentional:
  - Models define the database schema (storage concern).
  - Schemas define the API contract (validation concern).
  - This allows the agent payload format to evolve independently of the
    database schema (e.g., adding computed fields on ingest).
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ThreatEventIngest(BaseModel):
    """
    Schema for incoming telemetry from the C++ EDR agent.

    The agent sends this JSON payload over the /ws/agent WebSocket when
    a canary event is detected and processed. All fields match the C++
    agent's telemetry struct.

    Example payload from the agent:
    {
        "host_identifier": "workstation-042",
        "host_os": "Linux 6.1",
        "agent_version": "0.1.0",
        "malicious_pid": 12345,
        "process_name": "evil_ransomware",
        "process_path": "/tmp/evil_ransomware",
        "process_user": "victim_user",
        "process_cmdline": "/tmp/evil_ransomware --encrypt-all",
        "target_canary_path": "/home/user/Documents/_00_confidential.docx",
        "canary_naming_tier": "alpha_first",
        "entropy_score": 7.95,
        "mean_entropy": 7.89,
        "blocks_analyzed": 1,
        "blocks_above_threshold": 1,
        "entropy_threshold": 7.2,
        "severity": "CRITICAL",
        "action_taken": "KILLED_AND_ROLLED_BACK",
        "mitigation_latency_ms": 0.42,
        "kill_latency_us": 85.3,
        "restore_latency_us": 210.7,
        "children_killed": 2,
        "agent_timestamp": "2026-10-26T12:00:00Z",
        "agent_metadata": {
            "block_entropies": [7.95],
            "cpu_load": 0.23
        }
    }
    """

    # ── Required fields ───────────────────────────────────────────────────

    host_identifier: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Unique host identifier (hostname or machine UUID).",
    )

    host_os: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Operating system of the reporting agent.",
    )

    malicious_pid: int = Field(
        ...,
        ge=0,
        description="PID of the process that triggered the canary.",
    )

    target_canary_path: str = Field(
        ...,
        min_length=1,
        description="Absolute path of the canary file that was tripped.",
    )

    entropy_score: float = Field(
        ...,
        ge=0.0,
        le=8.0,
        description="Maximum Shannon entropy across analyzed blocks [0.0, 8.0].",
    )

    mitigation_latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total detection-to-response latency in milliseconds.",
    )

    action_taken: str = Field(
        ...,
        description="Response action taken by the agent.",
    )

    # ── Optional fields ───────────────────────────────────────────────────

    agent_version: Optional[str] = Field(
        None, max_length=32, description="Agent version string."
    )
    severity: str = Field(
        "HIGH", description="Threat severity classification."
    )
    process_name: Optional[str] = Field(
        None, max_length=255, description="Offending process name."
    )
    process_path: Optional[str] = Field(
        None, description="Full executable path."
    )
    process_user: Optional[str] = Field(
        None, max_length=128, description="Process owner."
    )
    process_cmdline: Optional[str] = Field(
        None, description="Full command line."
    )
    canary_naming_tier: Optional[str] = Field(
        None, max_length=32, description="Naming tier that triggered."
    )
    mean_entropy: Optional[float] = Field(
        None, ge=0.0, le=8.0, description="Mean entropy across blocks."
    )
    blocks_analyzed: Optional[int] = Field(
        None, ge=0, description="Number of blocks analyzed."
    )
    blocks_above_threshold: Optional[int] = Field(
        None, ge=0, description="Blocks above entropy threshold."
    )
    entropy_threshold: Optional[float] = Field(
        None, ge=0.0, le=8.0, description="Threshold used."
    )
    kill_latency_us: Optional[float] = Field(
        None, ge=0.0, description="Kill syscall latency in microseconds."
    )
    restore_latency_us: Optional[float] = Field(
        None, ge=0.0, description="File restore latency in microseconds."
    )
    children_killed: Optional[int] = Field(
        None, ge=0, description="Number of child processes killed."
    )
    agent_timestamp: Optional[datetime] = Field(
        None, description="Agent-local timestamp (ISO 8601)."
    )
    agent_metadata: Optional[dict[str, Any]] = Field(
        None, description="Arbitrary agent metadata (JSONB)."
    )

    @field_validator("action_taken")
    @classmethod
    def validate_action(cls, v: str) -> str:
        """Validate action_taken against known values."""
        valid = {
            "KILLED_AND_ROLLED_BACK",
            "KILLED_ONLY",
            "ROLLBACK_ONLY",
            "DETECTED_ONLY",
            "KILL_FAILED",
            "FULL_FAILURE",
        }
        if v not in valid:
            raise ValueError(
                f"Invalid action_taken '{v}'. Must be one of: {valid}"
            )
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity against known levels."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if v not in valid:
            raise ValueError(
                f"Invalid severity '{v}'. Must be one of: {valid}"
            )
        return v


class ThreatEventResponse(BaseModel):
    """
    Schema for outbound event data (REST API responses and SOC broadcasts).
    Mirrors the database record with all fields serialized.
    """

    id: int
    timestamp: Optional[datetime] = None
    agent_timestamp: Optional[datetime] = None
    host_identifier: str
    host_os: str
    agent_version: Optional[str] = None
    malicious_pid: int
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_user: Optional[str] = None
    target_canary_path: str
    canary_naming_tier: Optional[str] = None
    entropy_score: float
    mean_entropy: Optional[float] = None
    blocks_analyzed: Optional[int] = None
    blocks_above_threshold: Optional[int] = None
    severity: str
    action_taken: str
    mitigation_latency_ms: float
    kill_latency_us: Optional[float] = None
    restore_latency_us: Optional[float] = None
    children_killed: Optional[int] = None
    agent_metadata: Optional[dict[str, Any]] = None

    model_config = {"from_attributes": True}

