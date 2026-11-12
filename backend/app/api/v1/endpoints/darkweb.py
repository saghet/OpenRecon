from fastapi import APIRouter, Query, Body
from typing import Optional, List, Dict, Any
from app.services.cti.darkweb_collector import DarkWebCollector

router = APIRouter()
collector = DarkWebCollector()


@router.get("/leaks", summary="Fetch active Ransomware Extortion Leaks")
async def get_ransomware_leaks(limit: int = Query(50, ge=1, le=200)):
    """
    Retrieves latest announced corporate victims from public extortion sites.
    """
    posts = await collector.fetch_ransomware_posts(limit=limit)
    return {
        "count": len(posts),
        "source": "Defensive Extortion Feed",
        "posts": posts
    }


@router.get("/groups", summary="Fetch catalog of Ransomware Groups")
async def get_ransomware_groups():
    """
    Lists tracked extortion syndicates, active blogs, and operational status.
    """
    groups = await collector.fetch_active_ransomware_groups()
    return {
        "count": len(groups),
        "groups": groups
    }


@router.post("/correlate-seeds", summary="Correlate corporate seeds against Dark Web leaks")
async def correlate_seeds_with_leaks(payload: Dict[str, Any]):
    """
    Compares organization domain seeds against extortion posts.
    Returns cryptographic evidence records.
    """
    seeds = payload.get("seeds", [])
    posts = await collector.fetch_ransomware_posts(limit=150)
    matches = collector.correlate_leaks_with_seeds(posts, seeds)
    return {
        "seeds_checked": len(seeds),
        "matches_count": len(matches),
        "matches": matches
    }


@router.post("/mask-credential", summary="Safely process leaked credential (k-Anonymity)")
async def mask_credential(payload: Dict[str, Any]):
    """
    Processes leaked credential under strict security guidelines:
    Masks user part, hashes with SHA-256, NEVER stores cleartext.
    """
    return collector.evaluate_credential_leak_safety(payload)
