"""
Kafka Consumer - base consumer used by the normalizer and future AI agents.
Each consumer group reads from a topic independently.
"""
from __future__ import annotations
import json
import structlog
from typing import Any, Callable, Dict, Optional
from confluent_kafka import Consumer as ConfluentConsumer, KafkaError, KafkaException


class KafkaConsumer:
    def __init__(self, bootstrap_servers: str, group_id: str, topics: list):
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.topics = topics
        self._consumer: Optional[ConfluentConsumer] = None
        self._running = False
        self.log = structlog.get_logger().bind(component="kafka_consumer", group=group_id)

    def connect(self):
        self._consumer = ConfluentConsumer({
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,        # Manual commit for reliability
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 30000,
        })
        self._consumer.subscribe(self.topics)
        self.log.info("kafka_consumer_subscribed", topics=self.topics)

    def consume(self, handler: Callable[[str, Dict[str, Any]], None], batch_size: int = 50):
        """
        Poll Kafka and call handler(topic, message_dict) for each message.
        Commits offset only after successful handler execution.
        """
        self._running = True
        while self._running:
            msgs = self._consumer.consume(num_messages=batch_size, timeout=1.0)
            for msg in msgs:
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    self.log.error("kafka_consumer_error", error=str(msg.error()))
                    continue
                try:
                    value = json.loads(msg.value().decode("utf-8"))
                    handler(msg.topic(), value)
                    self._consumer.commit(msg)
                except json.JSONDecodeError as e:
                    self.log.error("kafka_message_decode_error", error=str(e))
                except Exception as e:
                    self.log.error("kafka_handler_error", topic=msg.topic(), error=str(e))
                    # Send to dead letter topic in a real impl

    def stop(self):
        self._running = False
        if self._consumer:
            self._consumer.close()
        self.log.info("kafka_consumer_stopped")
