"""
Tests — Phase 1 Pipeline
Tests normalization logic for each connector without needing live SIEM connections.
"""
from __future__ import annotations
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from schemas.ocsf import Severity, NormalizedAlert


# ─── Splunk Normalizer Tests ──────────────────────────────────────────────────

class TestSplunkNormalizer:

    def _make_connector(self):
        from connectors.splunk.connector import SplunkConnector
        connector = SplunkConnector.__new__(SplunkConnector)
        connector.config = {}
        connector.producer = MagicMock()
        connector.source_name = "splunk"
        connector.raw_topic = "raw.splunk.alerts"
        connector.log = MagicMock()
        return connector

    def test_normalize_high_severity(self):
        conn = self._make_connector()
        raw = {
            "event_id": "splunk-001",
            "urgency": "high",
            "_time": "2024-01-15T10:30:00",
            "rule_name": "Brute Force Detected",
            "rule_description": "Multiple failed login attempts",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "user": "jdoe",
            "mitre_technique_id": "T1110",
            "mitre_technique": "Brute Force",
            "mitre_tactic_id": "TA0006",
            "mitre_tactic": "Credential Access",
        }
        alert = conn.normalize(raw)
        assert isinstance(alert, NormalizedAlert)
        assert alert.severity == Severity.HIGH
        assert alert.source_siem == "splunk"
        assert alert.title == "Brute Force Detected"
        assert alert.src_endpoint.ip == "192.168.1.100"
        assert alert.actor.user == "jdoe"
        assert len(alert.attack_techniques) == 1
        assert alert.attack_techniques[0].technique_id == "T1110"

    def test_normalize_critical_severity(self):
        conn = self._make_connector()
        raw = {"event_id": "splunk-002", "urgency": "critical", "_time": "1705312200.0",
               "rule_name": "Ransomware Activity", "src_ip": "10.0.0.99"}
        alert = conn.normalize(raw)
        assert alert.severity == Severity.CRITICAL

    def test_normalize_unknown_severity_defaults(self):
        conn = self._make_connector()
        raw = {"event_id": "splunk-003", "_time": "2024-01-15T10:00:00",
               "search_name": "Generic Alert"}
        alert = conn.normalize(raw)
        assert alert.severity == Severity.UNKNOWN
        assert alert.source_siem == "splunk"

    def test_normalize_missing_ips(self):
        conn = self._make_connector()
        raw = {"event_id": "splunk-004", "urgency": "medium",
               "_time": "2024-01-15T10:00:00", "rule_name": "Test"}
        alert = conn.normalize(raw)
        assert alert.src_endpoint is None
        assert alert.dst_endpoint is None


# ─── QRadar Normalizer Tests ─────────────────────────────────────────────────

class TestQRadarNormalizer:

    def _make_connector(self):
        from connectors.qradar.connector import QRadarConnector
        connector = QRadarConnector.__new__(QRadarConnector)
        connector.config = {"host": "https://qradar.test", "api_token": "test"}
        connector.producer = MagicMock()
        connector.source_name = "qradar"
        connector.raw_topic = "raw.qradar.alerts"
        connector.log = MagicMock()
        return connector

    def test_normalize_offense(self):
        conn = self._make_connector()
        raw = {
            "id": 12345,
            "offense_name": "DDoS Attack Suspected",
            "description": "High volume traffic from single source",
            "magnitude": 8,
            "start_time": 1705312200000,
            "last_updated_time": 1705312500000,
            "offense_type": "Network Event",
            "categories": ["DDoS", "Exploit"],
            "offense_source": "192.168.50.10",
            "_resolved_src_ips": ["192.168.50.10"],
            "relevance": 9,
            "credibility": 8,
            "event_count": 5000,
            "flow_count": 200,
        }
        alert = conn.normalize(raw)
        assert alert.severity == Severity.HIGH
        assert alert.source_siem == "qradar"
        assert alert.source_uid == "12345"
        assert alert.title == "DDoS Attack Suspected"
        assert alert.src_endpoint.ip == "192.168.50.10"
        assert alert.enrichments["magnitude"] == 8
        assert alert.enrichments["event_count"] == 5000
        assert len(alert.attack_techniques) == 2  # DDoS + Exploit categories

    def test_magnitude_to_severity_mapping(self):
        from connectors.qradar.connector import _magnitude_to_severity
        assert _magnitude_to_severity(1)  == Severity.INFORMATIONAL
        assert _magnitude_to_severity(3)  == Severity.LOW
        assert _magnitude_to_severity(5)  == Severity.MEDIUM
        assert _magnitude_to_severity(7)  == Severity.HIGH
        assert _magnitude_to_severity(10) == Severity.CRITICAL


# ─── Wazuh Normalizer Tests ───────────────────────────────────────────────────

class TestWazuhNormalizer:

    def _make_connector(self):
        from connectors.wazuh.connector import WazuhConnector
        connector = WazuhConnector.__new__(WazuhConnector)
        connector.config = {}
        connector.producer = MagicMock()
        connector.source_name = "wazuh"
        connector.raw_topic = "raw.wazuh.alerts"
        connector.log = MagicMock()
        return connector

    def test_normalize_basic_alert(self):
        conn = self._make_connector()
        raw = {
            "id": "wazuh-001",
            "timestamp": "2024-01-15T10:30:00Z",
            "rule": {
                "id": "100001",
                "level": 10,
                "description": "Possible rootkit detected",
                "groups": ["rootkit", "pci_dss_10"],
                "mitre": {
                    "id": ["T1014"],
                    "technique": ["Rootkit"],
                    "tactic": ["Defense Evasion"],
                }
            },
            "agent": {"id": "001", "name": "web-server-01"},
            "data": {"srcip": "203.0.113.50", "dstip": "10.0.0.10"},
            "full_log": "Rootkit detected in /usr/lib",
        }
        alert = conn.normalize(raw)
        assert alert.severity == Severity.HIGH
        assert alert.source_siem == "wazuh"
        assert alert.title == "Possible rootkit detected"
        assert alert.src_endpoint.ip == "203.0.113.50"
        assert alert.enrichments["agent_name"] == "web-server-01"
        assert any(t.technique_id == "T1014" for t in alert.attack_techniques)

    def test_normalize_low_level_alert(self):
        conn = self._make_connector()
        raw = {
            "id": "wazuh-002",
            "timestamp": "2024-01-15T10:00:00Z",
            "rule": {"id": "5001", "level": 2, "description": "User logged in",
                     "groups": ["authentication_success"]},
            "agent": {"id": "001", "name": "server-01"},
            "data": {},
        }
        alert = conn.normalize(raw)
        assert alert.severity == Severity.INFORMATIONAL

    def test_level_to_severity_mapping(self):
        from connectors.wazuh.connector import _level_to_severity
        assert _level_to_severity(2)  == Severity.INFORMATIONAL
        assert _level_to_severity(5)  == Severity.LOW
        assert _level_to_severity(8)  == Severity.MEDIUM
        assert _level_to_severity(11) == Severity.HIGH
        assert _level_to_severity(14) == Severity.CRITICAL


# ─── OCSF Schema Tests ────────────────────────────────────────────────────────

class TestOCSFSchema:

    def test_normalized_alert_serialization(self):
        from schemas.ocsf import NormalizedAlert, Severity, NetworkEndpoint, Actor
        alert = NormalizedAlert(
            source_uid="test-001",
            source_siem="splunk",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            category="Security Finding",
            type_name="Brute Force",
            severity=Severity.HIGH,
            severity_label="High",
            title="Test Alert",
        )
        d = alert.to_kafka_dict()
        assert d["severity"] == 4
        assert "timestamp" in d
        assert isinstance(d["timestamp"], str)

    def test_kafka_roundtrip(self):
        from schemas.ocsf import NormalizedAlert, Severity
        alert = NormalizedAlert(
            source_uid="test-002",
            source_siem="wazuh",
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            category="Security Finding",
            type_name="Malware",
            severity=Severity.CRITICAL,
            severity_label="Critical",
            title="Malware Detected",
        )
        d = alert.to_kafka_dict()
        recovered = NormalizedAlert.from_kafka_dict(d)
        assert recovered.uid == alert.uid
        assert recovered.severity == alert.severity
        assert recovered.title == alert.title
