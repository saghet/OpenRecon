"""
Dynamic Connector Registry for OpenRecon 3.0.
Allows registering and discovering intelligence connectors without modifying core modules.
"""

from typing import Dict, List, Optional
from app.services.connectors.base import BaseConnector


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: Dict[str, BaseConnector] = {}

    def register(self, connector: BaseConnector) -> None:
        cid = connector.config.connector_id
        self._connectors[cid] = connector

    def unregister(self, connector_id: str) -> None:
        self._connectors.pop(connector_id, None)

    def get(self, connector_id: str) -> Optional[BaseConnector]:
        return self._connectors.get(connector_id)

    def list_all(self) -> List[Dict]:
        return [c.metadata() for c in self._connectors.values()]

    async def health_summary(self) -> List[Dict]:
        return [await c.health_check() for c in self._connectors.values()]


global_connector_registry = ConnectorRegistry()
