"""
Connector runner — starts all enabled connectors from config.yaml
Run with: python -m connectors.runner
"""
from __future__ import annotations
import asyncio
import yaml
import os
import structlog
from typing import List
from connectors import CONNECTOR_REGISTRY
from pipeline.kafka.producer import KafkaProducer

logger = structlog.get_logger()


async def run_connectors():
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    kafka_bootstrap = cfg["kafka"]["bootstrap_servers"]
    producer = KafkaProducer(bootstrap_servers=kafka_bootstrap)
    producer.connect()

    # Create required Kafka topics
    topics = list(cfg["kafka"]["topics"].values())
    producer.ensure_topics(topics)

    # Start each enabled connector
    tasks: List[asyncio.Task] = []
    for siem, connector_cfg in cfg["connectors"].items():
        if not connector_cfg.get("enabled", False):
            continue
        ConnectorClass = CONNECTOR_REGISTRY.get(siem)
        if not ConnectorClass:
            logger.warning("unknown_connector", siem=siem)
            continue

        # Substitute env vars in config
        resolved_cfg = _resolve_env_vars(connector_cfg)
        connector = ConnectorClass(config=resolved_cfg, kafka_producer=producer)
        logger.info("starting_connector", siem=siem)
        tasks.append(asyncio.create_task(connector.run()))

    if not tasks:
        logger.error("no_connectors_enabled")
        return

    logger.info("all_connectors_started", count=len(tasks))
    await asyncio.gather(*tasks, return_exceptions=True)


def _resolve_env_vars(cfg: dict) -> dict:
    """Replace ${VAR} placeholders with actual environment variable values."""
    resolved = {}
    for k, v in cfg.items():
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            env_key = v[2:-1]
            resolved[k] = os.environ.get(env_key, v)
        else:
            resolved[k] = v
    return resolved


if __name__ == "__main__":
    asyncio.run(run_connectors())
