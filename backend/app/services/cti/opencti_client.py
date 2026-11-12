"""
OpenCTI Client & STIX 2.1 Engine for OpenRecon
Provides decoupled, resilient integration with OpenCTI Platform.
If OpenCTI instance is offline or unreachable, OpenRecon gracefully
degrades to local threat intelligence without blocking operations.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class OpenCTIClient:
    """
    Decoupled client for OpenCTI GraphQL API and STIX 2.1 bundle processing.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_token: Optional[str] = None,
        timeout: float = 8.0,
        verify_ssl: bool = False
    ):
        self.base_url = base_url.rstrip("/")
        self.graphql_url = f"{self.base_url}/graphql"
        self.api_token = api_token or ""
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.is_connected = False
        self._last_health_check: Optional[datetime] = None

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OpenRecon-OpenCTI-Connector/1.0"
        }
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    async def check_health(self) -> Dict[str, Any]:
        """
        Verify OpenCTI API availability.
        """
        query = """
        query HealthCheck {
            about {
                version
            }
        }
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(
                    self.graphql_url,
                    json={"query": query},
                    headers=self._get_headers()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("data", {}).get("about", {}).get("version", "unknown")
                    self.is_connected = True
                    self._last_health_check = datetime.utcnow()
                    return {
                        "status": "ONLINE",
                        "version": version,
                        "url": self.base_url,
                        "timestamp": self._last_health_check.isoformat()
                    }
        except Exception as e:
            logger.warning(f"OpenCTI connection check failed: {e}")
            self.is_connected = False

        return {
            "status": "OFFLINE",
            "message": "OpenCTI service unreachable. Falling back to local OpenRecon intelligence.",
            "url": self.base_url,
            "timestamp": datetime.utcnow().isoformat()
        }

    async def query_indicators(
        self,
        indicator_type: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Retrieve STIX 2.1 Indicators from OpenCTI.
        Gracefully returns empty list if OpenCTI is offline.
        """
        query = """
        query GetIndicators($first: Int, $filters: [IndicatorsFiltering]) {
            indicators(first: $first, filters: $filters) {
                edges {
                    node {
                        id
                        standard_id
                        name
                        pattern
                        pattern_type
                        valid_from
                        confidence
                        x_opencti_score
                        created
                        revoked
                        indicator_types
                    }
                }
            }
        }
        """
        filters = []
        if indicator_type:
            filters.append({"key": "pattern_type", "values": [indicator_type]})

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(
                    self.graphql_url,
                    json={"query": query, "variables": {"first": limit, "filters": filters}},
                    headers=self._get_headers()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    edges = data.get("data", {}).get("indicators", {}).get("edges", [])
                    return [edge["node"] for edge in edges if "node" in edge]
        except Exception as e:
            logger.warning(f"Error querying OpenCTI indicators: {e}")

        return []

    async def query_threat_actors(self, limit: int = 25) -> List[Dict[str, Any]]:
        """
        Retrieve Threat Actors (Intrusion Sets) from OpenCTI.
        """
        query = """
        query GetThreatActors($first: Int) {
            threatActors(first: $first) {
                edges {
                    node {
                        id
                        name
                        aliases
                        description
                        sophistication
                        resource_level
                        primary_motivation
                        goals
                        confidence
                    }
                }
            }
        }
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(
                    self.graphql_url,
                    json={"query": query, "variables": {"first": limit}},
                    headers=self._get_headers()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    edges = data.get("data", {}).get("threatActors", {}).get("edges", [])
                    return [edge["node"] for edge in edges if "node" in edge]
        except Exception as e:
            logger.warning(f"Error querying OpenCTI threat actors: {e}")

        return []

    async def correlate_ioc(self, value: str, ioc_type: str = "ipv4-addr") -> Dict[str, Any]:
        """
        Check if an IP, domain or hash matches an active Indicator in OpenCTI.
        """
        pattern = f"[{ioc_type}:value = '{value}']"
        query = """
        query CorrelateIoc($pattern: String!) {
            indicators(filters: [{key: "pattern", values: [$pattern]}]) {
                edges {
                    node {
                        id
                        name
                        confidence
                        x_opencti_score
                        valid_from
                        description
                    }
                }
            }
        }
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.post(
                    self.graphql_url,
                    json={"query": query, "variables": {"pattern": pattern}},
                    headers=self._get_headers()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    edges = data.get("data", {}).get("indicators", {}).get("edges", [])
                    if edges:
                        return {
                            "matched": True,
                            "source": "OpenCTI",
                            "indicator": edges[0]["node"],
                            "confidence": edges[0]["node"].get("confidence", 75),
                            "score": edges[0]["node"].get("x_opencti_score", 80)
                        }
        except Exception as e:
            logger.debug(f"OpenCTI IoC correlation fallback for {value}: {e}")

        return {"matched": False, "source": "OpenCTI", "value": value}

    async def import_stix21_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends a STIX 2.1 JSON bundle to OpenCTI for automated ingestion.
        """
        mutation = """
        mutation ImportStixBundle($file: Upload!) {
            stixBundleImport(file: $file) {
                id
                name
                status
            }
        }
        """
        try:
            bundle_json = json.dumps(bundle)
            files = {
                "file": ("stix_bundle.json", bundle_json, "application/json")
            }
            operations = {
                "query": mutation,
                "variables": {"file": None}
            }
            data = {
                "operations": json.dumps(operations),
                "map": json.dumps({"0": ["variables.file"]})
            }
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                headers = self._get_headers()
                # Remove Content-Type so httpx sets multipart boundary
                headers.pop("Content-Type", None)
                resp = await client.post(
                    self.graphql_url,
                    data=data,
                    files={"0": ("stix_bundle.json", bundle_json.encode("utf-8"), "application/json")},
                    headers=headers
                )
                if resp.status_code == 200:
                    return {"status": "SUCCESS", "response": resp.json()}
                return {"status": "ERROR", "code": resp.status_code, "body": resp.text}
        except Exception as e:
            logger.warning(f"Error importing STIX bundle to OpenCTI: {e}")
            return {"status": "OFFLINE_FALLBACK", "message": str(e)}

    def convert_to_stix21_bundle(
        self,
        assets: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Convert OpenRecon assets and vulnerabilities to standard STIX 2.1 JSON bundle.
        Enables export to OpenCTI, MISP, or external TAXII servers.
        """
        bundle_id = f"bundle--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        objects = []

        # 1. Identity representing OpenRecon Platform
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--d89e4719-f9c1-4b13-8d65-openreconplatform",
            "name": "OpenRecon Platform",
            "identity_class": "system",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z"
        }
        objects.append(identity)

        # 2. Convert Assets to STIX Observed Data / Indicators
        for asset in assets:
            subdomain = asset.get("subdomain") or asset.get("value", "")
            ip = asset.get("ip_address")
            if ip:
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--ip-{abs(hash(ip))}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": f"Asset IP: {ip}",
                    "description": f"Discovered by OpenRecon for domain {subdomain}",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                    "confidence": 90,
                    "created_by_ref": identity["id"]
                }
                objects.append(indicator)

            if subdomain:
                domain_ind = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--domain-{abs(hash(subdomain))}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": f"Asset Domain: {subdomain}",
                    "description": "Perimeter asset identified in OpenRecon attack surface",
                    "pattern": f"[domain-name:value = '{subdomain}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                    "confidence": 95,
                    "created_by_ref": identity["id"]
                }
                objects.append(domain_ind)

        # 3. Convert Vulnerabilities to STIX Vulnerability SDOs
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            title = vuln.get("title", "Perimeter Exposure")
            v_id = f"vulnerability--{abs(hash(title + str(cve_id)))}"
            vuln_obj = {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": v_id,
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": title,
                "description": vuln.get("description", ""),
                "created_by_ref": identity["id"]
            }
            if cve_id:
                vuln_obj["external_references"] = [
                    {"source_name": "cve", "external_id": cve_id}
                ]
            objects.append(vuln_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
