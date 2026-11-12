"""
REST Endpoints for DARK INTELLIGENCE in OpenRecon FastAPI Backend.
Exposes modular APIs for:
- Dark Web Search (Federated, transparent coverage)
- Onion Sources Directory & SOCKS5 Probing
- Controlled Depth-Bounded Onion Crawling
- Ransomware Intelligence & Sync
- Leak Intelligence (k-Anonymity identity masking)
- Threat Actor Intelligence & MITRE ATT&CK
- Evidence Vault Forensic Proofs
- Organization Exposure Investigations
"""

from fastapi import APIRouter, Query, HTTPException, Body, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.services.cti.dark_search_engine import DarkSearchEngine
from app.services.cti.dark_collector_service import DarkCollectorService
from app.schemas.darkintel import DarkSearchRequest, DarkSearchOut, InvestigationCreate

router = APIRouter()
search_engine = DarkSearchEngine()
collector = DarkCollectorService()


@router.post("/search", response_model=DarkSearchOut, summary="Execute Federated Dark Web Search")
async def execute_darkweb_search(payload: DarkSearchRequest):
    """
    Centralized search across dark web sources, leak feeds, and threat intelligence.
    Enforces coverage transparency: reports real coverage without false claims.
    """
    res = await search_engine.search(
        query=payload.query,
        query_type=payload.query_type,
        sources=payload.sources,
        include_surface=payload.include_surface,
        min_confidence=payload.min_confidence,
        date_from=payload.date_from.isoformat() if payload.date_from else None,
        executed_by="analyst"
    )
    return res


@router.get("/sources", summary="List Tracked .onion Services & Portals")
def get_tracked_sources(category: Optional[str] = None):
    """
    Returns directory of monitored threat syndicates, indexes, and leak sites.
    """
    import sqlite3
    from app.services.cti.dark_collector_service import SQLITE_PATH

    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cur = conn.cursor()
        if category:
            cur.execute("SELECT id, source_name, onion_address, category, status, reliability_rating, last_seen_online, response_time_ms FROM darkintel_sources WHERE category = ?", (category,))
        else:
            cur.execute("SELECT id, source_name, onion_address, category, status, reliability_rating, last_seen_online, response_time_ms FROM darkintel_sources")
        rows = cur.fetchall()
        sources = [
            {
                "id": r[0],
                "source_name": r[1],
                "onion_address": r[2],
                "category": r[3],
                "status": r[4],
                "reliability_rating": r[5],
                "last_seen_online": r[6],
                "response_time_ms": r[7]
            }
            for r in rows
        ]
        return {"count": len(sources), "sources": sources}
    finally:
        conn.close()


@router.post("/sources/probe", summary="Probe .onion service availability and latency")
async def probe_source_availability(payload: Dict[str, str] = Body(...)):
    """
    Tests reachability and latency of a target onion service via Tor SOCKS5h.
    """
    onion = payload.get("onion_address", "")
    if not onion:
        raise HTTPException(status_code=400, detail="onion_address is required")
    res = await collector.check_source_availability(onion)
    return res


@router.post("/crawl", summary="Controlled Depth-Bounded Onion Crawl")
async def execute_onion_crawl(payload: Dict[str, Any] = Body(...)):
    """
    Executes depth-bounded (max_depth=2) crawl strictly locked to target onion hostname.
    Extracts crypto wallets, emails, related onions, and saves snapshots in Evidence Vault.
    """
    url = payload.get("url", "")
    max_depth = min(int(payload.get("max_depth", 1)), 2)
    max_pages = min(int(payload.get("max_pages", 5)), 10)

    if not url:
        raise HTTPException(status_code=400, detail="Target URL is required")

    try:
        res = await collector.crawl_onion_site(url, max_depth=max_depth, max_pages=max_pages)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/ransomware", summary="Get Extortion Posts from Ransomware DLS")
def get_ransomware_posts(limit: int = Query(50, ge=1, le=200)):
    """
    Returns latest announced corporate victims with proof summaries and volume data.
    """
    import sqlite3
    from app.services.cti.dark_collector_service import SQLITE_PATH

    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, evidence_id, group_name, victim_name, victim_website, claim_details,
                   ransom_deadline, data_volume_gb, discovered_at_utc, status
            FROM darkintel_ransomware_posts
            ORDER BY discovered_at_utc DESC
            LIMIT ?
            """,
            (limit,)
        )
        posts = [
            {
                "id": r[0],
                "evidence_id": r[1],
                "group_name": r[2],
                "victim_name": r[3],
                "victim_website": r[4],
                "claim_details": r[5],
                "ransom_deadline": r[6],
                "data_volume_gb": r[7],
                "discovered_at_utc": r[8],
                "status": r[9]
            }
            for r in cur.fetchall()
        ]
        return {"count": len(posts), "posts": posts}
    finally:
        conn.close()


@router.post("/ransomware/sync", summary="Sync Latest Ransomware Extortion Feeds")
async def sync_ransomware_feed(limit: int = Query(100, ge=10, le=300)):
    """
    Fetches latest victims from public threat intelligence feeds, deduplicates,
    and updates Evidence Vault.
    """
    res = await collector.ingest_ransomware_feed(limit=limit)
    return res


@router.get("/leaks", summary="Get Compromised Credentials & Leaks (Masked)")
def get_credential_leaks(limit: int = Query(50, ge=1, le=200)):
    """
    Returns exposed corporate identities and breach records.
    All records are strictly masked under k-anonymity (zero cleartext passwords).
    """
    import sqlite3
    from app.services.cti.dark_collector_service import SQLITE_PATH

    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, evidence_id, domain_mentioned, masked_identity, exposure_type,
                   leak_source, discovered_at, corroboration_level
            FROM darkintel_leaks
            ORDER BY discovered_at DESC
            LIMIT ?
            """,
            (limit,)
        )
        leaks = [
            {
                "id": r[0],
                "evidence_id": r[1],
                "domain_mentioned": r[2],
                "masked_identity": r[3],
                "exposure_type": r[4],
                "leak_source": r[5],
                "discovered_at": r[6],
                "corroboration_level": r[7]
            }
            for r in cur.fetchall()
        ]
        return {"count": len(leaks), "leaks": leaks}
    finally:
        conn.close()


@router.post("/investigate", summary="Run Comprehensive Organization Exposure Investigation")
def run_organization_investigation(payload: InvestigationCreate):
    """
    Correlates an organization's domain seeds, brands, and emails against dark web leaks,
    ransomware posts, CISA KEV vulnerabilities, and IoCs to calculate an Exposure Score.
    """
    res = search_engine.analyze_organization_exposure(
        organization_id=payload.organization_id,
        domains=payload.scope_domains,
        brands=payload.scope_brands,
        emails=payload.scope_emails
    )
    return res


@router.get("/evidence/{evidence_id}", summary="Retrieve Inmutable Evidence Record from Vault")
def get_evidence_record(evidence_id: str):
    """
    Returns forensic evidence proof with raw preview, SHA-256 hash, and HMAC custody signature.
    """
    import sqlite3
    from app.services.cti.dark_collector_service import SQLITE_PATH

    conn = sqlite3.connect(SQLITE_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, source_url, source_type, collected_at_utc, published_at_utc,
                   raw_content_preview, content_sha256, custody_signature, validation_status,
                   severity, confidence_score, analyst_notes
            FROM darkintel_evidence_vault
            WHERE id = ?
            """,
            (evidence_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidence record not found in Vault.")

        return {
            "evidence_id": row[0],
            "source_url": row[1],
            "source_type": row[2],
            "collected_at_utc": row[3],
            "published_at_utc": row[4],
            "raw_content_preview": row[5],
            "content_sha256": row[6],
            "custody_signature": row[7],
            "validation_status": row[8],
            "severity": row[9],
            "confidence_score": row[10],
            "analyst_notes": row[11]
        }
    finally:
        conn.close()


@router.get("/stix/export", summary="Export Dark Intelligence to STIX 2.1 Bundle")
def export_stix_bundle(
    include_actors: bool = Query(True),
    include_ransomware: bool = Query(True),
    include_iocs: bool = Query(True),
    include_leaks: bool = Query(True),
    limit: int = Query(50, ge=1, le=200)
):
    """
    Exports correlated dark web discoveries into an enterprise STIX 2.1 JSON Bundle.
    """
    import sqlite3
    import json
    from app.services.cti.dark_collector_service import SQLITE_PATH
    from app.services.cti.stix_exporter import StixExporter

    exporter = StixExporter()
    actors = []
    ransomware = []
    iocs = []
    leaks = []

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        if include_actors:
            cur.execute("SELECT * FROM darkintel_threat_actors LIMIT ?", (limit,))
            actors = [dict(r) for r in cur.fetchall()]

        if include_ransomware:
            cur.execute("SELECT * FROM darkintel_ransomware_posts LIMIT ?", (limit,))
            ransomware = [dict(r) for r in cur.fetchall()]

        if include_iocs:
            cur.execute("SELECT * FROM darkintel_iocs LIMIT ?", (limit,))
            iocs = [dict(r) for r in cur.fetchall()]

        if include_leaks:
            cur.execute("SELECT * FROM darkintel_leaks LIMIT ?", (limit,))
            leaks = [dict(r) for r in cur.fetchall()]

        bundle = exporter.build_stix21_bundle(
            threat_actors=actors,
            ransomware_posts=ransomware,
            iocs=iocs,
            leaks=leaks
        )
        return bundle
    finally:
        conn.close()


@router.get("/integrations/status", summary="Check Status of External CTI Platforms (MISP / OpenCTI)")
async def get_integrations_status():
    """
    Returns connection health and capabilities of MISP and OpenCTI integrations.
    """
    from app.services.cti.opencti_client import OpenCTIClient
    from app.services.cti.misp_client import MISPClient

    opencti = OpenCTIClient()
    misp = MISPClient()

    opencti_status = await opencti.check_health()
    misp_status = await misp.check_health()

    return {
        "opencti": opencti_status,
        "misp": misp_status,
        "stix_version": "2.1",
        "taxii_ready": True
    }


class AIAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=5, description="Raw evidence or document snippet to analyze")
    evidence_id: Optional[str] = Field(None, description="Linked Evidence Vault identifier")
    source_url: Optional[str] = Field(None, description="Origin URL of the evidence")


@router.post("/ai/analyze", summary="Analyze Dark Web Evidence with DeepSeek (Anti-Injection Shielded)")
async def analyze_evidence_with_ai(payload: AIAnalysisRequest):
    """
    Submits dark web text to the DeepSeek CTI Assistant.
    Enforces anti-injection neutralization, XML boundary isolation, MITRE ATT&CK technique extraction,
    and cryptographic citations against the Evidence Vault.
    """
    from app.services.ai.deepseek_engine import DeepSeekCTIEngine
    engine = DeepSeekCTIEngine()
    result = await engine.analyze_darkweb_text(
        raw_text=payload.text,
        evidence_id=payload.evidence_id,
        source_url=payload.source_url
    )
    return result


