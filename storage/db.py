"""
Storage Layer — TimescaleDB models and queries.
TimescaleDB is PostgreSQL with time-series superpowers.
Alerts table is a hypertable partitioned by ingested_at for high-speed time queries.
"""
from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    Column, String, Integer, Float, DateTime,
    JSON, Text, Index, text
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession, async_sessionmaker
)
from schemas.ocsf import NormalizedAlert
import structlog

logger = structlog.get_logger()


# ─── ORM Base ────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ─── Alert Model ─────────────────────────────────────────────────────────────

class AlertRecord(Base):
    """
    Persisted version of NormalizedAlert.
    TimescaleDB hypertable on ingested_at — enables fast time-range queries.
    """
    __tablename__ = "alerts"

    uid             = Column(String(36),  primary_key=True)
    source_uid      = Column(String(256), nullable=False)
    source_siem     = Column(String(64),  nullable=False, index=True)
    timestamp       = Column(DateTime,    nullable=False)
    ingested_at     = Column(DateTime,    nullable=False, default=datetime.utcnow)
    category        = Column(String(128), nullable=True)
    type_name       = Column(String(256), nullable=True)
    severity        = Column(Integer,     nullable=False, default=0, index=True)
    severity_label  = Column(String(32),  nullable=True)
    title           = Column(String(512), nullable=False)
    description     = Column(Text,        nullable=True)
    status          = Column(String(32),  nullable=False, default="new", index=True)
    assigned_to     = Column(String(128), nullable=True)
    risk_score      = Column(Float,       nullable=True)
    risk_level      = Column(String(32),  nullable=True)
    false_positive_score = Column(Float,  nullable=True)

    # JSON fields — stored as JSONB in Postgres for indexing
    raw_event       = Column(JSON, nullable=True)
    actor           = Column(JSON, nullable=True)
    src_endpoint    = Column(JSON, nullable=True)
    dst_endpoint    = Column(JSON, nullable=True)
    attack_techniques = Column(JSON, nullable=True)
    observables     = Column(JSON, nullable=True)
    tags            = Column(JSON, nullable=True)
    enrichments     = Column(JSON, nullable=True)


# ─── Database Engine ─────────────────────────────────────────────────────────

class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.engine = create_async_engine(
            dsn,
            pool_size=10,
            max_overflow=20,
            echo=False,
        )
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self.log = structlog.get_logger().bind(component="database")

    async def init(self):
        """Create tables and convert alerts to TimescaleDB hypertable."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # Convert to hypertable for time-series performance
            await conn.execute(text(
                "SELECT create_hypertable('alerts', 'ingested_at', "
                "if_not_exists => TRUE, migrate_data => TRUE);"
            ))
            self.log.info("database_initialized")

    async def insert_alert(self, alert: NormalizedAlert) -> AlertRecord:
        """Persist a NormalizedAlert to the database."""
        record = AlertRecord(
            uid=alert.uid,
            source_uid=alert.source_uid,
            source_siem=alert.source_siem,
            timestamp=alert.timestamp,
            ingested_at=alert.ingested_at,
            category=alert.category,
            type_name=alert.type_name,
            severity=int(alert.severity),
            severity_label=alert.severity_label,
            title=alert.title,
            description=alert.description,
            status=alert.status,
            assigned_to=alert.assigned_to,
            risk_score=alert.risk_score,
            risk_level=alert.risk_level,
            false_positive_score=alert.false_positive_score,
            raw_event=alert.raw_event,
            actor=alert.actor.model_dump() if alert.actor else None,
            src_endpoint=alert.src_endpoint.model_dump() if alert.src_endpoint else None,
            dst_endpoint=alert.dst_endpoint.model_dump() if alert.dst_endpoint else None,
            attack_techniques=[t.model_dump() for t in alert.attack_techniques],
            observables=[o.model_dump() for o in alert.observables],
            tags=alert.tags,
            enrichments=alert.enrichments,
        )
        async with self.session_factory() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
        return record

    async def get_recent_alerts(
        self,
        limit: int = 100,
        severity_min: Optional[int] = None,
        source_siem: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[AlertRecord]:
        """Query recent alerts with optional filters."""
        from sqlalchemy import select
        stmt = select(AlertRecord).order_by(AlertRecord.ingested_at.desc()).limit(limit)
        if severity_min is not None:
            stmt = stmt.where(AlertRecord.severity >= severity_min)
        if source_siem:
            stmt = stmt.where(AlertRecord.source_siem == source_siem)
        if status:
            stmt = stmt.where(AlertRecord.status == status)

        async with self.session_factory() as session:
            result = await session.execute(stmt)
            return result.scalars().all()

    async def get_alert_stats(self) -> Dict[str, Any]:
        """Aggregated stats for the dashboard."""
        async with self.session_factory() as session:
            total = (await session.execute(
                text("SELECT COUNT(*) FROM alerts WHERE ingested_at > NOW() - INTERVAL '24 hours'")
            )).scalar()
            by_severity = (await session.execute(
                text("""
                    SELECT severity_label, COUNT(*) as count
                    FROM alerts
                    WHERE ingested_at > NOW() - INTERVAL '24 hours'
                    GROUP BY severity_label
                    ORDER BY count DESC
                """)
            )).fetchall()
            by_siem = (await session.execute(
                text("""
                    SELECT source_siem, COUNT(*) as count
                    FROM alerts
                    WHERE ingested_at > NOW() - INTERVAL '24 hours'
                    GROUP BY source_siem
                    ORDER BY count DESC
                """)
            )).fetchall()
            return {
                "total_24h": total,
                "by_severity": [{"label": r[0], "count": r[1]} for r in by_severity],
                "by_siem":     [{"siem": r[0],  "count": r[1]} for r in by_siem],
            }
