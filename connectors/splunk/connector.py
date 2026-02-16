"""
Splunk Connector
Polls Splunk REST API for new alerts/notable events.
Supports: Splunk Enterprise, Splunk Cloud
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

# Splunk severity string → OCSF Severity mapping
SPLUNK_SEVERITY_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low":           Severity.LOW,
    "medium":        Severity.MEDIUM,
    "high":          Severity.HIGH,
    "critical":      Severity.CRITICAL,
}


class SplunkConnector(BaseConnector):

    def _source_name(self) -> str:
        return "splunk"

    async def connect(self) -> bool:
        """Authenticate to Splunk and obtain session key."""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(
                    f"{self.config['host']}/services/auth/login",
                    data={
                        "username": self.config["username"],
                        "password": self.config["password"],
                        "output_mode": "json"
                    },
                    timeout=10
                )
                resp.raise_for_status()
                self._session_key = resp.json()["sessionKey"]
                self._last_polled = datetime.utcnow() - timedelta(minutes=5)
                return True
        except Exception as e:
            self.log.error("splunk_auth_failed", error=str(e))
            return False

    async def fetch_raw_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Fetch notable events from Splunk ES (Enterprise Security).
        Uses the /services/search/jobs endpoint with SPL query.
        """
        earliest = self._last_polled.strftime("%m/%d/%Y:%H:%M:%S")
        self._last_polled = datetime.utcnow()

        spl = (
            f"search index={self.config.get('index','main')} "
            f"earliest=\"{earliest}\" "
            f"| head {self.config.get('max_events_per_poll', 500)}"
        )

        headers = {
            "Authorization": f"Splunk {self._session_key}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        async with httpx.AsyncClient(verify=False) as client:
            # Create search job
            resp = await client.post(
                f"{self.config['host']}/services/search/jobs",
                headers=headers,
                data={"search": spl, "output_mode": "json"},
                timeout=30
            )
            resp.raise_for_status()
            sid = resp.json()["sid"]

            # Poll until job is done
            while True:
                status_resp = await client.get(
                    f"{self.config['host']}/services/search/jobs/{sid}",
                    headers=headers,
                    params={"output_mode": "json"},
                    timeout=10
                )
                state = status_resp.json()["entry"][0]["content"]["dispatchState"]
                if state == "DONE":
                    break
                import asyncio; await asyncio.sleep(1)

            # Fetch results
            results_resp = await client.get(
                f"{self.config['host']}/services/search/jobs/{sid}/results",
                headers=headers,
                params={"output_mode": "json", "count": 500},
                timeout=30
            )
            results_resp.raise_for_status()
            events = results_resp.json().get("results", [])

            for event in events:
                yield event

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Map Splunk notable event fields → OCSF NormalizedAlert."""

        severity_str = raw.get("urgency", raw.get("severity", "unknown")).lower()
        severity = SPLUNK_SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

        # Parse timestamp — Splunk uses epoch or _time field
        ts_raw = raw.get("_time", raw.get("time", ""))
        try:
            if ts_raw and "." in str(ts_raw):
                timestamp = datetime.fromtimestamp(float(ts_raw))
            else:
                timestamp = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            timestamp = datetime.utcnow()

        # Build src/dst endpoints
        src = NetworkEndpoint(
            ip=raw.get("src_ip", raw.get("src", None)),
            port=int(raw["src_port"]) if raw.get("src_port") else None,
            hostname=raw.get("src_host", None),
        )
        dst = NetworkEndpoint(
            ip=raw.get("dest_ip", raw.get("dest", None)),
            port=int(raw["dest_port"]) if raw.get("dest_port") else None,
            hostname=raw.get("dest_host", None),
        )

        # Build ATT&CK references from Splunk ES fields
        techniques = []
        if raw.get("mitre_technique_id"):
            techniques.append(AttackTechnique(
                technique_id=raw.get("mitre_technique_id"),
                technique_name=raw.get("mitre_technique"),
                tactic_id=raw.get("mitre_tactic_id"),
                tactic_name=raw.get("mitre_tactic"),
            ))

        return NormalizedAlert(
            source_uid=raw.get("event_id", raw.get("_cd", str(id(raw)))),
            source_siem="splunk",
            timestamp=timestamp,
            category="Security Finding",
            type_name=raw.get("type", raw.get("search_name", "Splunk Alert")),
            severity=severity,
            severity_label=severity_str.capitalize(),
            title=raw.get("rule_name", raw.get("search_name", "Splunk Notable Event")),
            description=raw.get("rule_description", raw.get("description", "")),
            raw_event=raw,
            actor=Actor(user=raw.get("user", raw.get("src_user", None))),
            src_endpoint=src if src.ip else None,
            dst_endpoint=dst if dst.ip else None,
            attack_techniques=techniques,
            tags=["splunk", severity_str],
        )
