from fastapi import APIRouter, Query, Body, HTTPException
from typing import Optional, List, Dict, Any
from app.services.cti.feed_adapters import CTIEnrichmentEngine
from app.services.cti.misp_client import MISPClient

router = APIRouter()
enrichment_engine = CTIEnrichmentEngine()
misp_client = MISPClient()


@router.get("/enrich/ip/{ip_address}", summary="Multi-source IP Reputation & Threat Enrichment")
async def enrich_ip(
    ip_address: str,
    abuseipdb_key: Optional[str] = Query(None, description="Optional AbuseIPDB API Key"),
    threatfox_key: Optional[str] = Query(None, description="Optional ThreatFox Key")
):
    """
    Enriches IP with AbuseIPDB, ThreatFox, and reputational scoring.
    """
    keys = {}
    if abuseipdb_key:
        keys["abuseipdb"] = abuseipdb_key
    if threatfox_key:
        keys["threatfox"] = threatfox_key

    return await enrichment_engine.enrich_ip(ip_address, keys)


@router.get("/enrich/domain/{domain}", summary="Domain Reputation & URLhaus Malware Check")
async def enrich_domain(
    domain: str,
    urlhaus_key: Optional[str] = Query(None, description="Optional URLhaus Key")
):
    """
    Enriches domain with URLhaus malware distribution intelligence.
    """
    keys = {}
    if urlhaus_key:
        keys["urlhaus"] = urlhaus_key

    return await enrichment_engine.enrich_domain(domain, keys)


@router.get("/misp/health", summary="Check MISP connectivity")
async def check_misp_health():
    """
    Returns connection status to MISP REST API.
    """
    return await misp_client.check_health()


@router.get("/misp/iocs", summary="Fetch published IoCs from MISP")
async def get_misp_iocs(days: int = Query(7, ge=1, le=30), limit: int = Query(50, ge=1, le=200)):
    """
    Retrieves recent threat indicators from MISP instance.
    """
    iocs = await misp_client.fetch_recent_iocs(days=days, limit=limit)
    return {
        "count": len(iocs),
        "source": "MISP",
        "iocs": iocs
    }
