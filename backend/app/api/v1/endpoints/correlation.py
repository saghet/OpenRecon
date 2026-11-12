from fastapi import APIRouter, Body
from typing import Optional, List, Dict, Any
from app.services.correlation.graph_engine import CorrelationGraphEngine

router = APIRouter()


@router.post("/graph", summary="Construct multidimensional attack correlation graph")
async def generate_correlation_graph(payload: Dict[str, Any]):
    """
    Builds the graph linking:
    Organization -> Domain -> Subdomain -> IP -> Port -> Service -> Tech -> CVE -> IoC -> Threat -> Actor.
    """
    engine = CorrelationGraphEngine()
    org_name = payload.get("org_name", "Enterprise Organization")
    seeds = payload.get("seeds", [])
    assets = payload.get("assets", [])
    vulns = payload.get("vulnerabilities", [])
    actors = payload.get("threat_actors", [])

    graph_data = engine.build_organization_attack_graph(
        org_name=org_name,
        seeds=seeds,
        assets=assets,
        vulns=vulns,
        threat_actors=actors
    )

    attack_paths = engine.find_attack_paths_to_critical_assets()

    return {
        "graph": graph_data,
        "attack_paths": attack_paths
    }
