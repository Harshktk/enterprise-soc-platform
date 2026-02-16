# Enterprise Agentic SOC Platform

> On-Premise · Air-Gap Ready · Multi-SIEM · LLM-Powered

## Phase 1 — Data Pipeline Foundation

This phase establishes the core data ingestion and normalization backbone.

### What's built here

- **SIEM Connectors** — Splunk, QRadar, Wazuh (pluggable SDK)
- **Kafka Pipeline** — raw event streaming, per-SIEM topics
- **OCSF Normalizer** — unified schema for all events
- **TimescaleDB Storage** — time-series alert persistence
- **FastAPI** — REST API for the dashboard
- **React Dashboard** — live alert queue (Phase 1 UI)

### Project Structure

```
enterprise-soc-platform/
├── connectors/
│   ├── base/           # Abstract base connector class
│   ├── splunk/         # Splunk connector
│   ├── qradar/         # IBM QRadar connector
│   └── wazuh/          # Wazuh connector
├── pipeline/
│   ├── kafka/          # Kafka producer/consumer wrappers
│   └── normalizer/     # OCSF normalization engine
├── schemas/            # OCSF schema definitions (Pydantic)
├── storage/            # TimescaleDB models & queries
├── api/                # FastAPI routes
├── dashboard/          # React frontend
├── infra/              # Docker Compose, Kafka setup
├── tests/              # Unit + integration tests
├── config.yaml         # Main config file
└── docker-compose.yml  # Full stack local dev
```

### Quick Start

```bash
# 1. Start infrastructure (Kafka, Zookeeper, TimescaleDB)
docker-compose up -d

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run a connector (example: Wazuh)
python -m connectors.wazuh.connector

# 4. Run the normalizer worker
python -m pipeline.normalizer.worker

# 5. Start the API
uvicorn api.main:app --reload
```

### Kafka Topics

| Topic | Description |
|---|---|
| `raw.splunk.alerts` | Raw Splunk events |
| `raw.qradar.alerts` | Raw QRadar offenses |
| `raw.wazuh.alerts` | Raw Wazuh alerts |
| `normalized.alerts` | OCSF-normalized unified stream |
| `dead.letter` | Failed/unparseable events |

### Environment Variables

Copy `.env.example` to `.env` and fill in your values.
