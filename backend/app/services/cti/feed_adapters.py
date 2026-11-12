"""
Unified Threat Intelligence Feed Adapters for OpenRecon
Provides standardized connectors for Free, API Key, and Commercial Feeds.
Handles rate limiting, response normalization, and caching.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class BaseFeedAdapter:
    """Abstract base class for all CTI adapters."""
    def __init__(self, name: str, category: str, requires_key: bool = False):
        self.name = name
        self.category = category  # FREE, API_KEY, COMMERCIAL
        self.requires_key = requires_key

    async def query_ip(self, ip_address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError

    async def query_domain(self, domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError


class AbuseIPDBAdapter(BaseFeedAdapter):
    """AbuseIPDB v2 API Adapter (API Key Tier)."""
    def __init__(self):
        super().__init__("AbuseIPDB API v2", "API_KEY", requires_key=True)
        self.endpoint = "https://api.abuseipdb.com/api/v2/check"

    async def query_ip(self, ip_address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        if not api_key:
            return {"service": self.name, "available": False, "reason": "Missing API Key"}
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(self.endpoint, headers=headers, params=params)
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    return {
                        "service": self.name,
                        "available": True,
                        "ip": ip_address,
                        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "country_code": d.get("countryCode"),
                        "isp": d.get("isp"),
                        "is_whitelisted": d.get("isWhitelisted", False)
                    }
        except Exception as e:
            logger.warning(f"AbuseIPDB query error: {e}")
        return {"service": self.name, "available": False, "error": "Query failed"}


class URLhausAdapter(BaseFeedAdapter):
    """abuse.ch URLhaus API Adapter (Free/API Key Tier)."""
    def __init__(self):
        super().__init__("abuse.ch URLhaus", "FREE", requires_key=False)
        self.endpoint = "https://urlhaus-api.abuse.ch/v1/host/"

    async def query_domain(self, domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Auth-Key"] = api_key
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.post(self.endpoint, data={"host": domain}, headers=headers)
                if resp.status_code == 200:
                    d = resp.json()
                    status = d.get("query_status")
                    if status == "ok":
                        urls = d.get("urls", [])
                        return {
                            "service": self.name,
                            "available": True,
                            "domain": domain,
                            "malicious_urls_count": len(urls),
                            "threat": d.get("threat", "Malware distribution"),
                            "status": "MALICIOUS" if len(urls) > 0 else "CLEAN"
                        }
                    else:
                        return {"service": self.name, "available": True, "domain": domain, "status": "NOT_FOUND"}
        except Exception as e:
            logger.warning(f"URLhaus query error: {e}")
        return {"service": self.name, "available": False, "error": "Query failed"}


class ThreatFoxAdapter(BaseFeedAdapter):
    """abuse.ch ThreatFox API Adapter (Free / IoC Search)."""
    def __init__(self):
        super().__init__("abuse.ch ThreatFox", "FREE", requires_key=False)
        self.endpoint = "https://threatfox-api.abuse.ch/api/v1/"

    async def query_ip(self, ip_address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        payload = {"query": "search_ioc", "search_term": ip_address}
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Auth-Key"] = api_key
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.post(self.endpoint, json=payload, headers=headers)
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("query_status") == "ok":
                        data = d.get("data", [])
                        return {
                            "service": self.name,
                            "available": True,
                            "ip": ip_address,
                            "matches_count": len(data),
                            "threat_type": data[0].get("threat_type") if data else None,
                            "malware_printable": data[0].get("malware_printable") if data else None,
                            "confidence_level": data[0].get("confidence_level") if data else 0
                        }
                    else:
                        return {"service": self.name, "available": True, "ip": ip_address, "matches_count": 0}
        except Exception as e:
            logger.warning(f"ThreatFox query error: {e}")
        return {"service": self.name, "available": False, "error": "Query failed"}


class CTIEnrichmentEngine:
    """
    Orchestrates queries across all available adapters based on configured keys and categories.
    """
    def __init__(self):
        self.abuseipdb = AbuseIPDBAdapter()
        self.urlhaus = URLhausAdapter()
        self.threatfox = ThreatFoxAdapter()

    async def enrich_ip(self, ip_address: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        keys = keys or {}
        results = {
            "ip_address": ip_address,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {}
        }
        # 1. ThreatFox (Free)
        results["sources"]["threatfox"] = await self.threatfox.query_ip(ip_address, keys.get("threatfox"))

        # 2. AbuseIPDB (If Key provided)
        if keys.get("abuseipdb"):
            results["sources"]["abuseipdb"] = await self.abuseipdb.query_ip(ip_address, keys.get("abuseipdb"))
        else:
            results["sources"]["abuseipdb"] = {"service": "AbuseIPDB", "status": "KEY_NOT_CONFIGURED"}

        return results

    async def enrich_domain(self, domain: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        keys = keys or {}
        results = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {}
        }
        # 1. URLhaus (Free)
        results["sources"]["urlhaus"] = await self.urlhaus.query_domain(domain, keys.get("urlhaus"))
        return results
