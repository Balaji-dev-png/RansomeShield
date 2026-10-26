"""
RansomShield Backend — FastAPI Application Entry Point

This is the core of the RansomShield backend. It provides:

  1. WebSocket /ws/agent  — Ingestion endpoint for C++ EDR agents.
     Agents connect here and stream JSON telemetry events. Each event
     is validated, persisted to PostgreSQL, and broadcast to SOC clients.

  2. WebSocket /ws/soc    — Broadcast endpoint for the Next.js SOC dashboard.
     Dashboard clients connect here and receive real-time event streams.
     Multiple concurrent SOC analyst sessions are supported.

  3. REST endpoints       — Standard CRUD for historical event queries,
     dashboard aggregations, and health checks.

Architecture:
─────────────
                    ┌──────────────┐
                    │  C++ Agent   │
                    │  (Linux/Win) │
                    └──────┬───────┘
                           │ WebSocket JSON
                           ▼
                    ┌──────────────┐
                    │  /ws/agent   │ ← Validates, persists, broadcasts
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │PostgreSQL│ │ /ws/soc  │ │ /ws/soc  │
        │   (DB)   │ │ Client 1 │ │ Client 2 │
        └──────────┘ └──────────┘ └──────────┘
                      SOC Dashboard Clients

Concurrency Model:
──────────────────
- The SOC broadcast uses asyncio-native primitives (no locks, no threads).
- A ConnectionManager class tracks connected SOC WebSockets in a set.
- Broadcasting iterates the set and sends concurrently via asyncio.gather.
- Disconnected clients are automatically pruned on send failure.
- Agent WebSocket handling is fully async — multiple agents can stream
  events simultaneously without blocking each other.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from .database import engine, Base, AsyncSessionLocal, get_db
from .models import ThreatEvent, ActionTaken, Severity
from .schemas import ThreatEventIngest, ThreatEventResponse


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ransomshield.api")


# ─────────────────────────────────────────────────────────────────────────────
# SOC WebSocket Connection Manager
# ─────────────────────────────────────────────────────────────────────────────


class ConnectionManager:
    """
    Manages concurrent WebSocket connections from SOC dashboard clients.

    Design goals:
      - O(1) connect/disconnect via set-based tracking.
      - Concurrent broadcast to all clients using asyncio.gather.
      - Automatic pruning of dead connections on send failure.
      - No locks required — all operations run on the asyncio event loop
        (single-threaded cooperative multitasking).

    Thread safety:
      - This class is NOT thread-safe by design. It relies on asyncio's
        single-threaded event loop model. All calls must be from async
        coroutines running on the same event loop.
    """

    def __init__(self) -> None:
        # Active SOC dashboard WebSocket connections.
        # Using a set for O(1) add/remove.
        self._active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new SOC WebSocket connection and add it to the pool."""
        await websocket.accept()
        self._active_connections.add(websocket)
        logger.info(
            "SOC client connected. Active SOC connections: %d",
            len(self._active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a SOC WebSocket connection from the pool."""
        self._active_connections.discard(websocket)
        logger.info(
            "SOC client disconnected. Active SOC connections: %d",
            len(self._active_connections),
        )

    async def broadcast(self, message: dict) -> None:
        """
        Broadcast a JSON message to ALL connected SOC dashboard clients.

        Sends to all clients concurrently using asyncio.gather. If a send
        fails (client disconnected), that client is automatically pruned
        from the pool.

        This is the hot path for real-time SOC updates:
          Agent event → DB insert → broadcast(event_dict) → all SOC clients
        """
        if not self._active_connections:
            return  # No SOC clients connected; nothing to broadcast.

        payload = json.dumps(message)
        dead_connections: list[WebSocket] = []

        # Create send tasks for all clients.
        async def _safe_send(ws: WebSocket) -> None:
            try:
                await ws.send_text(payload)
            except Exception:
                # Client disconnected or network error — mark for removal.
                dead_connections.append(ws)

        # Send to all clients concurrently.
        await asyncio.gather(
            *[_safe_send(ws) for ws in self._active_connections]
        )

        # Prune dead connections outside the iteration.
        for ws in dead_connections:
            self._active_connections.discard(ws)
            logger.warning("Pruned dead SOC connection during broadcast.")

    @property
    def active_count(self) -> int:
        """Number of currently connected SOC clients."""
        return len(self._active_connections)


# Singleton connection manager instance.
soc_manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────────────────────
# Application Lifespan (Startup / Shutdown)
# ─────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    On startup:
      - Creates all database tables if they don't exist.
      - Logs the startup banner.

    On shutdown:
      - Disposes the database engine (closes all pool connections).
    """
    # ── Startup ───────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("RansomShield Backend starting...")
    logger.info("=" * 60)

    # Create tables (idempotent — won't drop existing data).
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified/created.")

    yield  # Application is running.

    # ── Shutdown ──────────────────────────────────────────────────────────
    logger.info("RansomShield Backend shutting down...")
    await engine.dispose()
    logger.info("Database connections closed.")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="RansomShield SOC API",
    description=(
        "Backend API for the RansomShield EDR system. "
        "Receives real-time threat telemetry from C++ agents via WebSocket, "
        "persists events in PostgreSQL, and streams them to the SOC dashboard."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Next.js SOC dashboard (typically on port 3000) to connect.
# In production, restrict origins to the actual dashboard domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",     # Next.js dev server
        "http://localhost:3001",     # Alternate dev port
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket: Agent Telemetry Ingestion (/ws/agent)
# ─────────────────────────────────────────────────────────────────────────────


@app.websocket("/ws/agent")
async def ws_agent_ingest(websocket: WebSocket):
    """
    WebSocket endpoint for C++ EDR agent telemetry ingestion.

    Protocol:
    ─────────
    1. Agent connects to ws://<backend>/ws/agent
    2. Agent sends JSON messages (one per canary event).
    3. Backend validates, persists to PostgreSQL, and broadcasts to SOC clients.
    4. Backend sends an ACK back to the agent with the event ID.
    5. Connection stays open for the agent's lifetime (persistent connection).

    Message format (agent → backend):
        See ThreatEventIngest schema for the full JSON specification.

    ACK format (backend → agent):
        {"status": "ok", "event_id": 42}

    Error format (backend → agent):
        {"status": "error", "detail": "validation error message"}

    The agent should reconnect with exponential backoff if the connection drops.
    """
    await websocket.accept()
    agent_id = websocket.client.host if websocket.client else "unknown"
    logger.info("Agent connected from %s", agent_id)

    try:
        while True:
            # ── Receive JSON payload from agent ──────────────────────────
            raw_data = await websocket.receive_text()

            try:
                payload = json.loads(raw_data)
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON from agent %s: %s", agent_id, e)
                await websocket.send_json(
                    {"status": "error", "detail": f"Invalid JSON: {e}"}
                )
                continue

            # ── Validate payload against schema ──────────────────────────
            try:
                event_data = ThreatEventIngest(**payload)
            except ValidationError as e:
                logger.warning(
                    "Validation error from agent %s: %s", agent_id, e
                )
                await websocket.send_json(
                    {"status": "error", "detail": str(e)}
                )
                continue

            # ── Persist to PostgreSQL ────────────────────────────────────
            async with AsyncSessionLocal() as session:
                try:
                    db_event = ThreatEvent(
                        host_identifier=event_data.host_identifier,
                        host_os=event_data.host_os,
                        agent_version=event_data.agent_version,
                        malicious_pid=event_data.malicious_pid,
                        process_name=event_data.process_name,
                        process_path=event_data.process_path,
                        process_user=event_data.process_user,
                        process_cmdline=event_data.process_cmdline,
                        target_canary_path=event_data.target_canary_path,
                        canary_naming_tier=event_data.canary_naming_tier,
                        entropy_score=event_data.entropy_score,
                        mean_entropy=event_data.mean_entropy,
                        blocks_analyzed=event_data.blocks_analyzed,
                        blocks_above_threshold=event_data.blocks_above_threshold,
                        entropy_threshold=event_data.entropy_threshold,
                        severity=Severity(event_data.severity),
                        action_taken=ActionTaken(event_data.action_taken),
                        mitigation_latency_ms=event_data.mitigation_latency_ms,
                        kill_latency_us=event_data.kill_latency_us,
                        restore_latency_us=event_data.restore_latency_us,
                        children_killed=event_data.children_killed,
                        agent_timestamp=event_data.agent_timestamp,
                        agent_metadata=event_data.agent_metadata,
                    )

                    session.add(db_event)
                    await session.commit()

                    # Refresh to get DB-generated fields (id, timestamp).
                    await session.refresh(db_event)

                    event_id = db_event.id
                    broadcast_data = db_event.to_broadcast_dict()

                    logger.info(
                        "Event #%d persisted: host=%s pid=%d entropy=%.4f action=%s",
                        event_id,
                        event_data.host_identifier,
                        event_data.malicious_pid,
                        event_data.entropy_score,
                        event_data.action_taken,
                    )

                except Exception as e:
                    await session.rollback()
                    logger.error("DB insert failed: %s", e)
                    await websocket.send_json(
                        {"status": "error", "detail": f"Database error: {e}"}
                    )
                    continue

            # ── Broadcast to SOC dashboard clients ───────────────────────
            # This runs AFTER the DB commit so SOC clients see consistent data
            # (the event has an ID and a server-side timestamp).
            await soc_manager.broadcast(broadcast_data)

            # ── Send ACK back to agent ───────────────────────────────────
            await websocket.send_json(
                {"status": "ok", "event_id": event_id}
            )

    except WebSocketDisconnect:
        logger.info("Agent %s disconnected.", agent_id)
    except Exception as e:
        logger.error("Agent WebSocket error (%s): %s", agent_id, e)


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket: SOC Dashboard Stream (/ws/soc)
# ─────────────────────────────────────────────────────────────────────────────


@app.websocket("/ws/soc")
async def ws_soc_stream(websocket: WebSocket):
    """
    WebSocket endpoint for the Next.js SOC dashboard.

    SOC analysts connect here to receive real-time threat event streams.
    Multiple concurrent connections are supported — all receive the same
    broadcast feed.

    Protocol:
    ─────────
    1. Dashboard client connects to ws://<backend>/ws/soc
    2. Client receives a welcome message with connection metadata.
    3. Client receives JSON event objects as they arrive from agents.
    4. Client can optionally send ping/keepalive messages.
    5. Connection persists until the client disconnects or navigates away.

    The client does NOT need to send any messages — this is a receive-only
    stream. However, we do listen for messages to support:
      - Ping/pong keepalive (prevents proxy timeouts).
      - Future: filter subscriptions (e.g., "only show CRITICAL events").
    """
    await soc_manager.connect(websocket)

    # Send welcome message with connection metadata.
    await websocket.send_json(
        {
            "type": "connection_established",
            "message": "Connected to RansomShield SOC event stream.",
            "active_soc_clients": soc_manager.active_count,
            "server_time": datetime.now(timezone.utc).isoformat(),
        }
    )

    try:
        while True:
            # Listen for client messages (keepalive, filters, etc.).
            # This also detects disconnections via WebSocketDisconnect.
            data = await websocket.receive_text()

            # Handle ping/keepalive.
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json(
                        {
                            "type": "pong",
                            "server_time": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "active_soc_clients": soc_manager.active_count,
                        }
                    )
            except json.JSONDecodeError:
                pass  # Ignore malformed client messages.

    except WebSocketDisconnect:
        soc_manager.disconnect(websocket)
    except Exception as e:
        logger.error("SOC WebSocket error: %s", e)
        soc_manager.disconnect(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/health")
async def health_check():
    """
    Health check endpoint for load balancers and monitoring.

    Returns the backend status, database connectivity, and connected
    client counts.
    """
    db_ok = False
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(select(func.count()).select_from(ThreatEvent))
            db_ok = True
    except Exception:
        pass

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "soc_clients_connected": soc_manager.active_count,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.0",
    }


@app.get("/api/events", response_model=list[ThreatEventResponse])
async def list_events(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    host: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
):
    """
    List threat events with optional filtering.

    Used by the SOC dashboard for paginated historical event tables.
    Results are ordered by timestamp (newest first).

    Query parameters:
      - limit:    Max events to return (default 50, max 500).
      - offset:   Pagination offset.
      - severity: Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
      - host:     Filter by host_identifier (exact match).
      - action:   Filter by action_taken.
    """
    query = select(ThreatEvent).order_by(desc(ThreatEvent.timestamp))

    if severity:
        query = query.where(ThreatEvent.severity == Severity(severity))
    if host:
        query = query.where(ThreatEvent.host_identifier == host)
    if action:
        query = query.where(ThreatEvent.action_taken == ActionTaken(action))

    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    return events


@app.get("/api/events/{event_id}", response_model=ThreatEventResponse)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    """Retrieve a single threat event by ID."""
    result = await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if event is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Event not found.")

    return event


@app.get("/api/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    """
    Aggregate statistics for the SOC dashboard header widgets.

    Returns:
      - Total events count.
      - Counts by severity.
      - Counts by action_taken.
      - Average mitigation latency.
      - Unique hosts reporting.
    """
    # Total events
    total_result = await db.execute(
        select(func.count()).select_from(ThreatEvent)
    )
    total_events = total_result.scalar() or 0

    # Count by severity
    severity_result = await db.execute(
        select(ThreatEvent.severity, func.count())
        .group_by(ThreatEvent.severity)
    )
    severity_counts = {
        row[0].value: row[1] for row in severity_result.all()
    }

    # Count by action
    action_result = await db.execute(
        select(ThreatEvent.action_taken, func.count())
        .group_by(ThreatEvent.action_taken)
    )
    action_counts = {row[0].value: row[1] for row in action_result.all()}

    # Average latency
    latency_result = await db.execute(
        select(func.avg(ThreatEvent.mitigation_latency_ms))
    )
    avg_latency = latency_result.scalar()

    # Unique hosts
    hosts_result = await db.execute(
        select(func.count(func.distinct(ThreatEvent.host_identifier)))
    )
    unique_hosts = hosts_result.scalar() or 0

    return {
        "total_events": total_events,
        "severity_breakdown": severity_counts,
        "action_breakdown": action_counts,
        "avg_mitigation_latency_ms": (
            round(avg_latency, 3) if avg_latency else 0.0
        ),
        "unique_hosts": unique_hosts,
        "soc_clients_connected": soc_manager.active_count,
    }

