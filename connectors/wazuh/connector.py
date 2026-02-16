"""
Wazuh Connector
Polls Wazuh Manager REST API for new security alerts.
Wazuh is the primary open-source SIEM target for air-gapped environments.
API: Wazuh 4.x — https://documentation.wazuh.com/current/user-manual/api/
"""
from __future__ import annotations
import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Dict, Any, Optional

from connectors.base.connector import BaseConnector
from schemas.ocsf import (
    NormalizedAlert, Severity, Actor,
    NetworkEndpoint, AttackTechnique, Observable
)

logger = structlog.get_logger()

# Wazuh rule levels (0-15) → OCSF Severity
def _level_to_severity(level: int) -> Severity:
    if level <= 3:  return Severity.INFORMATIONAL
    if level <= 6:  return Severity.LOW
    if level <= 9:  return Severity.MEDIUM
    if level <= 12: return Severity.HIGH
    return Severity.CRITICAL

SEVERITY_LABEL = {
    Severity.INFORMATIONAL: "Informational",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

# Wazuh rule groups → MITRE tactic hints
RULE_GROUP_TACTIC_MAP = {
    "authentication_failed": ("TA0006", "Credential Access"),
    "authentication_success": ("TA0001", "Initial Access"),
    "pci_dss_10": ("TA0005", "Defense Evasion"),
    "rootkit": ("TA0004", "Privilege Escalation"),
    "sql_injection": ("TA0001", "Initial Access"),
    "web": ("TA0001", "Initial Access"),
    "syslog": (None, None),
}


class WazuhConnector(BaseConnector):

    def _source_name(self) -> str:
        return "wazuh"

    async def connect(self) -> bool:
        """Authenticate to Wazuh API — returns JWT token."""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    f"{self.config['host']}/security/user/authenticate",
                    auth=(
                        self.config.get("username", "wazuh-wui"),
                        self.config.get("password", ""),
                    ),
                    timeout=10,
                )
                resp.raise_for_status()
                self._token = resp.json()["data"]["token"]
                self._token_expiry = datetime.utcnow() + timedelta(seconds=900)
                self._last_polled = (
                    datetime.utcnow() - timedelta(minutes=5)
                ).strftime("%Y-%m-%dT%H:%M:%S")
                self.log.info("wazuh_authenticated")
                return True
        except Exception as e:
            self.log.error("wazuh_auth_failed", error=str(e))
            return False

    async def _refresh_token_if_needed(self):
        """Re-authenticate if token is close to expiry."""
        if datetime.utcnow() >= self._token_expiry - timedelta(seconds=60):
            await self.connect()

    async def fetch_raw_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fetch alerts via Wazuh Indexer API (OpenSearch-based).
        Queries alerts index with a time range filter.
        """
        await self._refresh_token_if_needed()

        current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": self._last_polled,
                        "lte": current_time,
                        "format": "yyyy-MM-dd'T'HH:mm:ss"
                    }
                }
            },
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": self.config.get("max_alerts_per_poll", 1000)
        }

        self._last_polled = current_time

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(verify=False) as client:
            # Wazuh 4.x uses the Wazuh Indexer (OpenSearch) for alert queries
            resp = await client.post(
                f"{self.config['host']}/wazuh-alerts-*/_search",
                headers=headers,
                json=query,
                timeout=30,
            )

            # Fallback: use Wazuh Manager API if indexer not available
            if resp.status_code != 200:
                async for event in self._fetch_via_manager_api(headers, client):
                    yield event
                return

            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            for hit in hits:
                yield hit.get("_source", {})

    async def _fetch_via_manager_api(
        self, headers: Dict, client: httpx.AsyncClient
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fallback: use Wazuh Manager REST API /alerts endpoint."""
        params = {
            "limit": self.config.get("max_alerts_per_poll", 1000),
            "offset": 0,
            "sort": "+timestamp",
            "q": f"timestamp>{self._last_polled}",
        }
        resp = await client.get(
            f"{self.config['host']}/alerts",
            headers=headers,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        for alert in data.get("data", {}).get("affected_items", []):
            yield alert

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Map Wazuh alert fields → OCSF NormalizedAlert."""

        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        data  = raw.get("data", {})
        syscheck = raw.get("syscheck", {})

        # Severity from rule level
        level    = int(rule.get("level", 5))
        severity = _level_to_severity(level)
        sev_lbl  = SEVERITY_LABEL.get(severity, "Unknown")

        # Timestamp
        ts_raw = raw.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            timestamp = datetime.utcnow()

        # ATT&CK mapping from rule groups
        techniques = []
        rule_groups = rule.get("groups", [])
        for group in rule_groups:
            tactic_id, tactic_name = RULE_GROUP_TACTIC_MAP.get(group, (None, None))
            if tactic_id:
                techniques.append(AttackTechnique(
                    tactic_id=tactic_id,
                    tactic_name=tactic_name,
                ))
        # Direct MITRE fields if present
        if rule.get("mitre", {}).get("technique"):
            for i, tid in enumerate(rule["mitre"].get("id", [])):
                name_list = rule["mitre"].get("technique", [])
                tactic_list = rule["mitre"].get("tactic", [])
                techniques.append(AttackTechnique(
                    technique_id=tid,
                    technique_name=name_list[i] if i < len(name_list) else None,
                    tactic_name=tactic_list[i] if i < len(tactic_list) else None,
                ))

        # Observables — extract IPs, hashes from syscheck/data
        observables = []
        src_ip = (
            raw.get("location", None) or
            data.get("srcip", None) or
            raw.get("data", {}).get("win", {}).get("system", {}).get("computer", None)
        )
        if data.get("srcip"):
            observables.append(Observable(type="ip", value=data["srcip"]))
        if syscheck.get("md5_after"):
            observables.append(Observable(type="hash", value=syscheck["md5_after"]))
        if syscheck.get("sha256_after"):
            observables.append(Observable(type="hash", value=syscheck["sha256_after"]))

        src_endpoint = NetworkEndpoint(
            ip=data.get("srcip", None),
            port=int(data["srcport"]) if data.get("srcport") else None,
            hostname=agent.get("name", None),
        )

        dst_endpoint = NetworkEndpoint(
            ip=data.get("dstip", None),
            port=int(data["dstport"]) if data.get("dstport") else None,
        )

        return NormalizedAlert(
            source_uid=raw.get("id", str(rule.get("id", ""))),
            source_siem="wazuh",
            timestamp=timestamp,
            category="Security Finding",
            type_name=", ".join(rule_groups[:2]) if rule_groups else "Wazuh Alert",
            severity=severity,
            severity_label=sev_lbl,
            title=rule.get("description", "Wazuh Security Alert"),
            description=raw.get("full_log", rule.get("description", "")),
            raw_event=raw,
            actor=Actor(
                user=data.get("dstuser", data.get("srcuser", None)),
                process=raw.get("program_name", None),
            ),
            src_endpoint=src_endpoint if (src_endpoint.ip or src_endpoint.hostname) else None,
            dst_endpoint=dst_endpoint if dst_endpoint.ip else None,
            attack_techniques=techniques,
            observables=observables,
            tags=["wazuh"] + rule_groups,
            enrichments={
                "rule_id":     rule.get("id"),
                "rule_level":  level,
                "rule_groups": rule_groups,
                "agent_id":    agent.get("id"),
                "agent_name":  agent.get("name"),
                "manager":     raw.get("manager", {}).get("name"),
                "decoder":     raw.get("decoder", {}).get("name"),
                "location":    raw.get("location"),
            },
        )
