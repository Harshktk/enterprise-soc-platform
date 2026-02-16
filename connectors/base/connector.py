"""
Base Connector — Abstract class every SIEM connector must implement.

To add a new SIEM:
1. Create a new folder under connectors/
2. Subclass BaseConnector
3. Implement: connect(), fetch_raw_events(), normalize()
4. Register in connectors/__init__.py
"""

from __future__ import annotations
import asyncio
import structlog
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, Any, List
from datetime import datetime

from schemas.ocsf import NormalizedAlert
from pipeline.kafka.producer import KafkaProducer

logger = structlog.get_logger()


class ConnectorConfig(BaseModel if False else object):
    """Base config — subclasses extend this."""
    pass


class BaseConnector(ABC):
    """
    Abstract base for all SIEM connectors.
    Each connector runs as an independent async loop.
    """

    def __init__(self, config: Dict[str, Any], kafka_producer: KafkaProducer):
        self.config = config
        self.producer = kafka_producer
        self.source_name = self._source_name()
        self.raw_topic = f"raw.{self.source_name}.alerts"
        self._running = False
        self.log = structlog.get_logger().bind(connector=self.source_name)

    # ── Must implement ──────────────────────────────────────────────────────

    @abstractmethod
    def _source_name(self) -> str:
        """Return SIEM identifier: splunk | qradar | wazuh"""
        ...

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection/session to the SIEM. Return True if successful."""
        ...

    @abstractmethod
    async def fetch_raw_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Yield raw events from the SIEM one by one.
        Each event is the original dict as returned by the SIEM API.
        """
        ...

    @abstractmethod
    def normalize(self, raw_event: Dict[str, Any]) -> NormalizedAlert:
        """
        Transform a raw SIEM event into a NormalizedAlert (OCSF schema).
        This is the core mapping logic specific to each SIEM.
        """
        ...

    # ── Provided by base ────────────────────────────────────────────────────

    async def run(self):
        """Main connector loop — connect, poll, produce to Kafka."""
        self._running = True
        poll_interval = self.config.get("poll_interval_seconds", 30)

        self.log.info("connector_starting")

        connected = await self.connect()
        if not connected:
            self.log.error("connector_failed_to_connect")
            return

        self.log.info("connector_connected")

        while self._running:
            try:
                count = 0
                async for raw_event in self.fetch_raw_events():
                    # Push raw event to Kafka raw topic
                    await self.producer.send(
                        topic=self.raw_topic,
                        value=raw_event,
                        key=str(raw_event.get("id", ""))
                    )
                    count += 1

                self.log.info("poll_complete", events_fetched=count)

            except Exception as e:
                self.log.error("poll_error", error=str(e))

            await asyncio.sleep(poll_interval)

    def stop(self):
        self._running = False
        self.log.info("connector_stopping")

    def _utcnow(self) -> datetime:
        return datetime.utcnow()
