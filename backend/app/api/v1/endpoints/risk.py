from fastapi import APIRouter, Body
from typing import Optional, List, Dict, Any
from app.services.risk.risk_engine import IntelligentRiskEngine

router = APIRouter()


@router.post("/calculate", summary="Evaluate explainable vulnerability risk score")
async def calculate_vuln_risk(payload: Dict[str, Any]):
    """
    Evaluates individual vulnerability score combining CVSS, EPSS, KEV, exposure, and validation state.
    """
    vuln = payload.get("vulnerability", {})
    asset = payload.get("asset")
    custom_weights = payload.get("weights")

    engine = IntelligentRiskEngine(custom_weights=custom_weights)
    return engine.calculate_vulnerability_risk(vuln, asset)


@router.post("/organization-posture", summary="Calculate organization Exposure Score")
async def calculate_org_posture(payload: Dict[str, Any]):
    """
    Calculates overall Exposure Score (0-100) and posture classification.
    """
    vulns = payload.get("vulnerabilities", [])
    total_assets = payload.get("total_assets", len(vulns))
    ransomware_matched = payload.get("ransomware_matched_count", 0)
    custom_weights = payload.get("weights")

    engine = IntelligentRiskEngine(custom_weights=custom_weights)
    return engine.calculate_organization_posture_score(
        vulnerabilities=vulns,
        total_assets=total_assets,
        ransomware_matched_count=ransomware_matched
    )
