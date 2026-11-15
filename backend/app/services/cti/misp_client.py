"""
MISP (Malware Information Sharing Platform) Client for OpenRecon
Provides decoupled synchronization of Threat Intelligence Events,
Attributes, Indicators of Compromise (IoCs), and Warninglists.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import httpx

from app.core.config import settings
from app.core.tls_config import get_httpx_verify

logger = logging.getLogger(__name__)


class MISPClient:
    """
    Decoupled client for MISP REST API.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_key: Optional[str] = None,
        timeout: float = 8.0,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
    ):
        if not verify_ssl:
            raise ValueError("TLS verification cannot be disabled in MISPClient. Use ca_bundle for private CAs.")
        resolved_url = base_url or settings.MISP_URL or "https://misp.local"
        self.base_url = resolved_url.rstrip("/")
        self.auth_key = auth_key or settings.MISP_KEY or ""
        self.timeout = timeout
        self.ca_bundle = ca_bundle
        self.verify_ssl = get_httpx_verify(ca_bundle=ca_bundle)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "OpenRecon-MISP-Connector/1.0"
        }
        if self.auth_key:
            headers["Authorization"] = self.auth_key
        return headers

    async def check_health(self) -> Dict[str, Any]:
        """
        Check MISP instance connectivity and version.
        """
        url = f"{self.base_url}/servers/getVersion.json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "unknown")
                    return {
                        "status": "ONLINE",
                        "version": version,
                        "url": self.base_url,
                        "timestamp": datetime.utcnow().isoformat()
                    }
        except Exception as e:
            logger.warning(f"MISP connection check failed: {e}")

        return {
            "status": "OFFLINE",
            "message": "MISP service unreachable. Local CTI fallback active.",
            "url": self.base_url,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def fetch_recent_iocs(
        self,
        days: int = 7,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch published attributes/IoCs (IPs, domains, hashes) from MISP events.
        """
        url = f"{self.base_url}/attributes/restSearch"
        payload = {
            "returnFormat": "json",
            "limit": limit,
            "last": f"{days}d",
            "type": ["ip-dst", "ip-src", "domain", "hostname", "url", "sha256", "md5"],
            "enforceWarninglist": True
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(url, json=payload, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("response", {}).get("Attribute", [])
                    results = []
                    for a in attrs:
                        results.append({
                            "id": a.get("id"),
                            "event_id": a.get("event_id"),
                            "type": a.get("type"),
                            "value": a.get("value"),
                            "category": a.get("category"),
                            "comment": a.get("comment"),
                            "timestamp": datetime.fromtimestamp(int(a.get("timestamp", 0))).isoformat()
                        })
                    return results
        except Exception as e:
            logger.warning(f"Error fetching MISP attributes: {e}")

        return []

    async def create_event(
        self,
        info: str,
        threat_level_id: int = 2,
        analysis: int = 1,
        distribution: int = 0
    ) -> Dict[str, Any]:
        """
        Creates a new Threat Intelligence Event in MISP.
        threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined
        analysis: 0=Initial, 1=Ongoing, 2=Completed
        distribution: 0=Your organization only, 1=This community only, 2=Connected communities, 3=All
        """
        url = f"{self.base_url}/events/add"
        payload = {
            "Event": {
                "info": info,
                "threat_level_id": threat_level_id,
                "analysis": analysis,
                "distribution": distribution
            }
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(url, json=payload, headers=self._get_headers())
                if resp.status_code in (200, 201):
                    return resp.json().get("Event", {})
        except Exception as e:
            logger.warning(f"Error creating MISP event: {e}")

        return {"error": "Failed to create MISP event or service offline"}

    async def add_attribute(
        self,
        event_id: str,
        attr_type: str,
        value: str,
        category: str = "External analysis",
        comment: str = "Discovered by OpenRecon Dark Intelligence"
    ) -> Dict[str, Any]:
        """
        Adds an IOC attribute to an existing MISP event.
        """
        url = f"{self.base_url}/attributes/add/{event_id}"
        payload = {
            "type": attr_type,
            "value": value,
            "category": category,
            "comment": comment,
            "to_ids": True
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(url, json=payload, headers=self._get_headers())
                if resp.status_code in (200, 201):
                    return resp.json().get("Attribute", {})
        except Exception as e:
            logger.warning(f"Error adding attribute to MISP event {event_id}: {e}")

        return {"error": f"Failed to add attribute to MISP event {event_id}"}

