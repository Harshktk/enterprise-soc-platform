"""
Connectors package — register all SIEM connectors here.
Import from this module to get the full connector registry.
"""
from connectors.splunk.connector import SplunkConnector
from connectors.qradar.connector import QRadarConnector
from connectors.wazuh.connector import WazuhConnector

# Registry: config key → connector class
CONNECTOR_REGISTRY = {
    "splunk": SplunkConnector,
    "qradar": QRadarConnector,
    "wazuh":  WazuhConnector,
}

__all__ = ["CONNECTOR_REGISTRY", "SplunkConnector", "QRadarConnector", "WazuhConnector"]
