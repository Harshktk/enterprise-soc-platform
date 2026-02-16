"""
FastAPI — SOC Platform REST API
Serves alert data to the React dashboard via HTTP + WebSocket.
"""
from __future__ import annotations
import json
import asyncio
from typing import List, Optional, Set
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import structlog

from storage.db import Database
from pipeline.kafka.consumer import KafkaConsumer

logger = structlog.get_logger()

# ─── App Setup ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Enterprise SOC Platform API",
    description="Phase 1 — Alert ingestion, normalization, real-time dashboard",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Injected at startup
db: Optional[Database] = None
ws_clients: Set[WebSocket] = set()


# ─── Lifecycle ───────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global db
    import yaml, os
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)
    dsn = cfg["database"]["url"]
    db = Database(dsn)
    await db.init()
    logger.info("api_started")
    # Start background WebSocket broadcast task
    asyncio.create_task(broadcast_from_kafka(cfg))


async def broadcast_from_kafka(cfg: dict):
    """
    Consume from normalized.alerts Kafka topic and broadcast
    each new alert to all connected WebSocket clients in real-time.
    """
    consumer = KafkaConsumer(
        bootstrap_servers=cfg["kafka"]["bootstrap_servers"],
        group_id="soc-api-ws-group",
        topics=[cfg["kafka"]["topics"]["normalized"]],
    )
    consumer.connect()

    def on_message(topic: str, msg: dict):
        asyncio.run_coroutine_threadsafe(
            broadcast(msg), asyncio.get_event_loop()
        )

    import threading
    t = threading.Thread(target=consumer.consume, args=(on_message,), daemon=True)
    t.start()


async def broadcast(message: dict):
    """Send a message to all connected WebSocket clients."""
    dead = set()
    for ws in ws_clients:
        try:
            await ws.send_text(json.dumps(message, default=str))
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


# ─── REST Endpoints ───────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    uid: str
    source_siem: str
    timestamp: datetime
    ingested_at: datetime
    severity: int
    severity_label: Optional[str]
    title: str
    description: Optional[str]
    status: str
    risk_score: Optional[float]
    tags: Optional[list]
    src_endpoint: Optional[dict]
    dst_endpoint: Optional[dict]
    attack_techniques: Optional[list]

    class Config:
        from_attributes = True


@app.get("/api/alerts", response_model=List[AlertOut], tags=["Alerts"])
async def list_alerts(
    limit: int        = Query(default=100, le=1000),
    severity_min: int = Query(default=0, ge=0, le=6),
    source_siem: Optional[str] = Query(default=None),
    status: Optional[str]      = Query(default=None),
):
    """Fetch recent alerts with optional filters."""
    if not db:
        raise HTTPException(503, "Database not initialized")
    records = await db.get_recent_alerts(
        limit=limit,
        severity_min=severity_min,
        source_siem=source_siem,
        status=status,
    )
    return records


@app.get("/api/alerts/{uid}", response_model=AlertOut, tags=["Alerts"])
async def get_alert(uid: str):
    """Fetch a single alert by UID."""
    from sqlalchemy import select
    async with db.session_factory() as session:
        from storage.db import AlertRecord
        result = await session.execute(
            select(AlertRecord).where(AlertRecord.uid == uid)
        )
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(404, f"Alert {uid} not found")
        return record


@app.patch("/api/alerts/{uid}/status", tags=["Alerts"])
async def update_alert_status(uid: str, status: str):
    """Update alert status (new → in_progress → resolved)."""
    valid = {"new", "in_progress", "resolved", "suppressed", "escalated"}
    if status not in valid:
        raise HTTPException(400, f"status must be one of: {valid}")
    from sqlalchemy import update
    async with db.session_factory() as session:
        from storage.db import AlertRecord
        await session.execute(
            update(AlertRecord)
            .where(AlertRecord.uid == uid)
            .values(status=status)
        )
        await session.commit()
    return {"uid": uid, "status": status}


@app.get("/api/stats", tags=["Dashboard"])
async def get_stats():
    """Aggregated alert statistics for the dashboard."""
    if not db:
        raise HTTPException(503, "Database not initialized")
    return await db.get_alert_stats()


@app.get("/api/health", tags=["System"])
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
        "ws_clients": len(ws_clients),
    }


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    Real-time alert stream.
    Connect: ws://localhost:8000/ws/alerts
    Receives: NormalizedAlert JSON objects as they arrive from Kafka.
    """
    await websocket.accept()
    ws_clients.add(websocket)
    logger.info("ws_client_connected", total=len(ws_clients))
    try:
        while True:
            # Keep-alive ping every 30s
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        ws_clients.discard(websocket)
        logger.info("ws_client_disconnected", total=len(ws_clients))
