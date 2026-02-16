"""
Kafka Producer - wraps confluent-kafka for async use.
All SIEM connectors use this to push raw events to their topic.
"""
from __future__ import annotations
import json
import structlog
from typing import Any, Dict, Optional
from confluent_kafka import Producer as ConfluentProducer
from confluent_kafka.admin import AdminClient, NewTopic


class KafkaProducer:
    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self._producer: Optional[ConfluentProducer] = None
        self.log = structlog.get_logger().bind(component="kafka_producer")

    def connect(self):
        self._producer = ConfluentProducer({
            "bootstrap.servers": self.bootstrap_servers,
            "acks": "all",
            "retries": 5,
            "retry.backoff.ms": 300,
            "compression.type": "lz4",
            "linger.ms": 5,
            "batch.size": 65536,
        })
        self.log.info("kafka_producer_connected", servers=self.bootstrap_servers)

    def ensure_topics(self, topics: list, num_partitions: int = 3, replication_factor: int = 1):
        """Create topics if they don't already exist."""
        admin = AdminClient({"bootstrap.servers": self.bootstrap_servers})
        existing = set(admin.list_topics(timeout=10).topics.keys())
        to_create = [
            NewTopic(t, num_partitions=num_partitions, replication_factor=replication_factor)
            for t in topics if t not in existing
        ]
        if to_create:
            futures = admin.create_topics(to_create)
            for topic, future in futures.items():
                try:
                    future.result()
                    self.log.info("kafka_topic_created", topic=topic)
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        self.log.error("kafka_topic_create_failed", topic=topic, error=str(e))

    async def send(self, topic: str, value: Dict[str, Any], key: str = "") -> bool:
        """Serialize and produce a message to Kafka."""
        if not self._producer:
            self.log.error("producer_not_connected")
            return False
        try:
            self._producer.produce(
                topic=topic,
                key=key.encode("utf-8") if key else None,
                value=json.dumps(value, default=str).encode("utf-8"),
                on_delivery=self._delivery_callback,
            )
            self._producer.poll(0)
            return True
        except BufferError:
            self._producer.flush(timeout=5)
            return await self.send(topic, value, key)
        except Exception as e:
            self.log.error("kafka_produce_failed", topic=topic, error=str(e))
            return False

    def flush(self, timeout: float = 10.0):
        if self._producer:
            remaining = self._producer.flush(timeout=timeout)
            if remaining > 0:
                self.log.warning("kafka_flush_incomplete", remaining=remaining)

    def _delivery_callback(self, err, msg):
        if err:
            self.log.error("kafka_delivery_failed", topic=msg.topic(), error=str(err))
        else:
            self.log.debug("kafka_delivery_success",
                           topic=msg.topic(), partition=msg.partition(), offset=msg.offset())
