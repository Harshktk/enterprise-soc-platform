"""
OCSF Normalizer Worker
Consumes raw.*.alerts topics → transforms to OCSF → publishes to normalized.alerts
This is the core of the data pipeline.
"""
from __future__ import annotations
import json
import structlog
from typing import Any, Dict
from datetime import datetime

from pipeline.kafka.producer import KafkaProducer
from pipeline.kafka.consumer import KafkaConsumer
from schemas.ocsf import NormalizedAlert

logger = structlog.get_logger()


class NormalizerWorker:
    """
    Reads from all raw SIEM topics, applies the correct connector normalizer,
    then publishes the unified NormalizedAlert to the normalized.alerts topic.
    """

    def __init__(self, kafka_bootstrap: str, topics_config: Dict[str, str]):
        self.bootstrap = kafka_bootstrap
        self.raw_topics = [
            topics_config["splunk_raw"],
            topics_config["qradar_raw"],
            topics_config["wazuh_raw"],
        ]
        self.normalized_topic = topics_config["normalized"]
        self.dead_letter_topic = topics_config["dead_letter"]
        self.log = structlog.get_logger().bind(component="normalizer")

        self.consumer = KafkaConsumer(
            bootstrap_servers=kafka_bootstrap,
            group_id="soc-normalizer-group",
            topics=self.raw_topics,
        )
        self.producer = KafkaProducer(bootstrap_servers=kafka_bootstrap)

        # Lazy import connectors to avoid circular deps
        self._normalizers: Dict[str, Any] = {}

    def _load_normalizers(self):
        """Load connector instances for normalize() calls only (no polling)."""
        from connectors.splunk.connector import SplunkConnector
        from connectors.qradar.connector import QRadarConnector
        from connectors.wazuh.connector import WazuhConnector

        # We only need the normalize() method — pass empty config
        self._normalizers = {
            "raw.splunk.alerts": SplunkConnector(config={}, kafka_producer=self.producer),
            "raw.qradar.alerts": QRadarConnector(config={}, kafka_producer=self.producer),
            "raw.wazuh.alerts": WazuhConnector(config={}, kafka_producer=self.producer),
        }

    def start(self):
        self.producer.connect()
        self.consumer.connect()
        self._load_normalizers()
        self.log.info("normalizer_started", topics=self.raw_topics)
        self.consumer.consume(handler=self._handle_message)

    def _handle_message(self, topic: str, raw_event: Dict[str, Any]):
        """Transform one raw event and publish normalized version."""
        try:
            normalizer = self._normalizers.get(topic)
            if not normalizer:
                self.log.warning("no_normalizer_for_topic", topic=topic)
                return

            normalized: NormalizedAlert = normalizer.normalize(raw_event)
            payload = normalized.to_kafka_dict()

            # Publish to normalized topic synchronously (via internal async shim)
            import asyncio
            loop = asyncio.new_event_loop()
            loop.run_until_complete(
                self.producer.send(
                    topic=self.normalized_topic,
                    value=payload,
                    key=normalized.uid,
                )
            )
            loop.close()

            self.log.info(
                "event_normalized",
                source=normalized.source_siem,
                uid=normalized.uid,
                severity=normalized.severity_label,
                title=normalized.title[:60],
            )

        except Exception as e:
            self.log.error("normalization_failed", topic=topic, error=str(e))
            self._send_to_dead_letter(topic, raw_event, str(e))

    def _send_to_dead_letter(self, topic: str, raw_event: Dict[str, Any], reason: str):
        """Failed events go to dead.letter for manual review."""
        import asyncio
        payload = {
            "original_topic": topic,
            "raw_event": raw_event,
            "failure_reason": reason,
            "failed_at": datetime.utcnow().isoformat(),
        }
        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            self.producer.send(topic=self.dead_letter_topic, value=payload)
        )
        loop.close()
