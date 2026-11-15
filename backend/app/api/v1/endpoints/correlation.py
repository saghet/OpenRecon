from fastapi import APIRouter, Body
from typing import Optional, List, Dict, Any
from app.services.correlation.graph_engine import CorrelationGraphEngine
from app.services.cti.misp_galaxy import MISPGalaxyService

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

    actor_names = [a.get("name", "") for a in actors if isinstance(a, dict) and a.get("name")]
    actor_names.extend([str(n) for n in payload.get("actor_names", []) if n])
    galaxy_edges = 0
    if actor_names:
        galaxy = MISPGalaxyService()
        target_node = f"org:{org_name}" if f"org:{org_name}" in engine.nodes else None
        galaxy_edges = galaxy.enrich_correlation_graph(engine, actor_names, target_node_id=target_node)

    attack_paths = engine.find_attack_paths_to_critical_assets()

    return {
        "graph": {
            "nodes": list(engine.nodes.values()),
            "edges": engine.edges,
            "stats": graph_data.get("stats", {}),
        },
        "galaxy_enriched_edges": galaxy_edges,
        "attack_paths": attack_paths
    }
