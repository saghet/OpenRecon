from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
from app.services.cti.opencti_client import OpenCTIClient

router = APIRouter()
opencti_client = OpenCTIClient()


@router.get("/health", summary="Check OpenCTI service connectivity")
async def check_opencti_health():
    """
    Returns connection status to OpenCTI GraphQL endpoint.
    If offline, OpenRecon gracefully informs the analyst and uses local CTI.
    """
    return await opencti_client.check_health()


@router.get("/indicators", summary="Query STIX 2.1 Indicators from OpenCTI")
async def get_opencti_indicators(
    pattern_type: Optional[str] = Query(None, description="Filter by pattern type, e.g. ipv4-addr or domain-name"),
    limit: int = Query(50, ge=1, le=200)
):
    """
    Retrieve external indicators synchronized from OpenCTI.
    """
    indicators = await opencti_client.query_indicators(indicator_type=pattern_type, limit=limit)
    return {
        "count": len(indicators),
        "source": "OpenCTI",
        "indicators": indicators
    }


@router.get("/threat-actors", summary="Query Threat Actors from OpenCTI")
async def get_opencti_threat_actors(limit: int = Query(25, ge=1, le=100)):
    """
    Retrieve threat actor profiles (Intrusion Sets) from OpenCTI.
    """
    actors = await opencti_client.query_threat_actors(limit=limit)
    return {
        "count": len(actors),
        "source": "OpenCTI",
        "threat_actors": actors
    }


@router.post("/correlate", summary="Correlate IoC with OpenCTI intelligence")
async def correlate_ioc(value: str, ioc_type: str = "ipv4-addr"):
    """
    Check if an observed perimeter asset matches any active OpenCTI indicator.
    """
    return await opencti_client.correlate_ioc(value=value, ioc_type=ioc_type)


@router.post("/export-stix", summary="Export assets and vulnerabilities to STIX 2.1 Bundle")
async def export_to_stix_bundle(payload: Dict[str, Any]):
    """
    Converts perimeter telemetry into standardized STIX 2.1 JSON bundle.
    """
    assets = payload.get("assets", [])
    vulns = payload.get("vulnerabilities", [])
    bundle = opencti_client.convert_to_stix21_bundle(assets, vulns)
    return bundle
