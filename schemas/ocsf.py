"""
OCSF (Open Cybersecurity Schema Framework) — Normalized Alert Schema
Every event from every SIEM gets transformed into this unified model.
"""

from __future__ import annotations
from datetime import datetime
from enum import IntEnum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid


# ─── Severity Mapping (OCSF standard) ───────────────────────────────────────

class Severity(IntEnum):
    UNKNOWN   = 0
    INFORMATIONAL = 1
    LOW       = 2
    MEDIUM    = 3
    HIGH      = 4
    CRITICAL  = 5
    FATAL     = 6


# ─── OCSF Sub-objects ────────────────────────────────────────────────────────

class Actor(BaseModel):
    user: Optional[str] = None
    process: Optional[str] = None
    session_uid: Optional[str] = None


class NetworkEndpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    domain: Optional[str] = None


class Malware(BaseModel):
    name: Optional[str] = None
    classification: Optional[str] = None
    family: Optional[str] = None


class AttackTechnique(BaseModel):
    """MITRE ATT&CK reference"""
    tactic_id: Optional[str] = None     # e.g. TA0001
    tactic_name: Optional[str] = None   # e.g. Initial Access
    technique_id: Optional[str] = None  # e.g. T1059
    technique_name: Optional[str] = None


class Observable(BaseModel):
    type: str                           # ip, domain, hash, url, user
    value: str
    reputation: Optional[str] = None   # clean, suspicious, malicious


# ─── Core Normalized Alert (OCSF Security Finding) ───────────────────────────

class NormalizedAlert(BaseModel):
    """
    OCSF-compliant Security Finding object.
    This is the single unified schema that all SIEM connectors produce.
    """

    # Identity
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_uid: str                     # Original ID in the source SIEM
    source_siem: str                    # splunk | qradar | wazuh | sentinel | ...

    # Timestamps
    timestamp: datetime                 # Event occurrence time (UTC)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    # Classification
    category: str                       # e.g. "Security Finding"
    type_name: str                      # e.g. "Malware Activity", "Network Activity"
    severity: Severity = Severity.UNKNOWN
    severity_label: str = "Unknown"

    # Content
    title: str                          # Short human-readable title
    description: Optional[str] = None
    raw_event: Dict[str, Any] = Field(default_factory=dict)  # Original payload

    # Actors & Targets
    actor: Optional[Actor] = None
    src_endpoint: Optional[NetworkEndpoint] = None
    dst_endpoint: Optional[NetworkEndpoint] = None

    # Threat Context
    attack_techniques: List[AttackTechnique] = Field(default_factory=list)
    observables: List[Observable] = Field(default_factory=list)
    malware: Optional[Malware] = None

    # Risk (will be enriched by AI agents later)
    risk_score: Optional[float] = None     # 0.0 – 100.0
    risk_level: Optional[str] = None       # low | medium | high | critical
    false_positive_score: Optional[float] = None

    # Status
    status: str = "new"                    # new | in_progress | resolved | suppressed
    assigned_to: Optional[str] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    enrichments: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True

    def to_kafka_dict(self) -> Dict[str, Any]:
        """Serialize for Kafka message payload."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        data["ingested_at"] = self.ingested_at.isoformat()
        return data

    @classmethod
    def from_kafka_dict(cls, data: Dict[str, Any]) -> "NormalizedAlert":
        """Deserialize from Kafka message payload."""
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["ingested_at"] = datetime.fromisoformat(data["ingested_at"])
        return cls(**data)
