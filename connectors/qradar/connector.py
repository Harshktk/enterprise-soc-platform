"""
IBM QRadar Connector
Polls QRadar REST API for new offenses (QRadar's term for correlated incidents).
Supports: QRadar SIEM 7.4+
API Docs: https://ibmsecuritydocs.github.io/qradar_api_overview/
"""
from __future__ import annotations
import httpx
import structlog
from datetime import datetime, timedelta
from typing import AsyncGenerator, Dict, Any

from connectors.base.connector import BaseConnector
from schemas.ocsf import (
    NormalizedAlert, Severity, Actor,
    NetworkEndpoint, AttackTechnique
)

logger = structlog.get_logger()

# QRadar magnitude (1-10) → OCSF Severity
def _magnitude_to_severity(magnitude: int) -> Severity:
    if magnitude <= 2:  return Severity.INFORMATIONAL
    if magnitude <= 4:  return Severity.LOW
    if magnitude <= 6:  return Severity.MEDIUM
    if magnitude <= 8:  return Severity.HIGH
    return Severity.CRITICAL

SEVERITY_LABEL_MAP = {
    Severity.INFORMATIONAL: "Informational",
    Severity.LOW:    "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH:   "High",
    Severity.CRITICAL: "Critical",
}


class QRadarConnector(BaseConnector):

    def _source_name(self) -> str:
        return "qradar"

    async def connect(self) -> bool:
        """Validate QRadar API token by hitting the system info endpoint."""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(
                    f"{self.config['host']}/api/system/about",
                    headers=self._headers(),
                    timeout=10,
                )
                resp.raise_for_status()
                info = resp.json()
                self.log.info(
                    "qradar_connected",
                    version=info.get("external_version", "unknown"),
                )
                self._last_polled_ms = int(
                    (datetime.utcnow() - timedelta(minutes=5)).timestamp() * 1000
                )
                return True
        except Exception as e:
            self.log.error("qradar_connect_failed", error=str(e))
            return False

    async def fetch_raw_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fetch new/updated offenses since last poll.
        QRadar offenses are fetched via GET /api/siem/offenses with a filter.
        """
        # Filter: offenses updated since last poll, not yet closed
        filter_str = (
            f"last_updated_time > {self._last_polled_ms} "
            f"and status != CLOSED"
        )
        self._last_polled_ms = int(datetime.utcnow().timestamp() * 1000)

        params = {
            "filter": filter_str,
            "fields": (
                "id,description,offense_name,offense_type,offense_source,"
                "categories,magnitude,severity,relevance,credibility,"
                "source_address_ids,local_destination_address_ids,"
                "start_time,last_updated_time,status,username_count,"
                "source_network,destination_networks,assigned_to,"
                "event_count,flow_count,log_sources"
            ),
            "sort": "+last_updated_time",
            "Range": f"items=0-{self.config.get('max_offenses_per_poll', 200) - 1}",
        }

        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{self.config['host']}/api/siem/offenses",
                headers=self._headers(),
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            offenses = resp.json()

            # Enrich each offense with source IPs (separate API call)
            for offense in offenses:
                src_ips = await self._resolve_addresses(
                    client, offense.get("source_address_ids", [])[:5]
                )
                offense["_resolved_src_ips"] = src_ips
                yield offense

    async def _resolve_addresses(
        self, client: httpx.AsyncClient, address_ids: list
    ) -> list:
        """Resolve QRadar address IDs to actual IP strings."""
        if not address_ids:
            return []
        id_filter = " or ".join(f"id={i}" for i in address_ids)
        try:
            resp = await client.get(
                f"{self.config['host']}/api/siem/source_addresses",
                headers=self._headers(),
                params={"filter": id_filter, "fields": "id,source_ip"},
                timeout=10,
            )
            resp.raise_for_status()
            return [a["source_ip"] for a in resp.json()]
        except Exception:
            return []

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Map QRadar offense fields → OCSF NormalizedAlert."""

        magnitude  = raw.get("magnitude", 5)
        severity   = _magnitude_to_severity(magnitude)
        sev_label  = SEVERITY_LABEL_MAP.get(severity, "Unknown")

        # QRadar timestamps are epoch milliseconds
        ts_ms      = raw.get("start_time", raw.get("last_updated_time", 0))
        timestamp  = datetime.utcfromtimestamp(ts_ms / 1000) if ts_ms else datetime.utcnow()

        # Source IPs (resolved)
        src_ips = raw.get("_resolved_src_ips", [])
        src_endpoint = NetworkEndpoint(ip=src_ips[0]) if src_ips else None

        # ATT&CK techniques — QRadar categories can map loosely
        techniques = []
        for cat in raw.get("categories", []):
            techniques.append(AttackTechnique(technique_name=cat))

        return NormalizedAlert(
            source_uid=str(raw.get("id", "")),
            source_siem="qradar",
            timestamp=timestamp,
            category="Security Finding",
            type_name=raw.get("offense_type", "QRadar Offense"),
            severity=severity,
            severity_label=sev_label,
            title=raw.get("offense_name", raw.get("description", "QRadar Offense")),
            description=raw.get("description", ""),
            raw_event=raw,
            actor=Actor(user=raw.get("offense_source", None)),
            src_endpoint=src_endpoint,
            attack_techniques=techniques,
            tags=["qradar"] + raw.get("categories", []),
            enrichments={
                "magnitude":   magnitude,
                "relevance":   raw.get("relevance", 0),
                "credibility": raw.get("credibility", 0),
                "event_count": raw.get("event_count", 0),
                "flow_count":  raw.get("flow_count", 0),
            },
        )

    def _headers(self) -> Dict[str, str]:
        return {
            "SEC": self.config.get("api_token", ""),
            "Accept": "application/json",
            "Version": "16.0",
        }
