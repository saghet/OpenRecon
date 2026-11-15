import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict, Any
from app.core.auth import require_api_token
from app.core.database import get_db
from app.core.security_guard import SecurityGovernanceGuard
from app.models.asset import Asset
from app.models.exposure import Vulnerability, DigitalRiskFinding, PortService, SeverityLevel
from app.schemas.exposure import VulnerabilityResponse, DigitalRiskFindingResponse
from app.services.evidence.manager import EvidenceManager
from app.services.github_intel.scanner import GitHubIntelConnector

router = APIRouter()


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    organization_id: int,
    severity: Optional[SeverityLevel] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability).join(Asset).filter(Asset.organization_id == organization_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    return query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/drp", response_model=List[DigitalRiskFindingResponse])
def list_drp_findings(
    organization_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    return db.query(DigitalRiskFinding).filter(
        DigitalRiskFinding.organization_id == organization_id
    ).order_by(DigitalRiskFinding.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/stats")
def get_exposure_stats(organization_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    total_assets = db.query(Asset).filter(Asset.organization_id == organization_id).count()
    live_assets = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.is_live == True).count()
    
    # Count open ports
    open_ports_count = db.query(PortService).join(Asset).filter(Asset.organization_id == organization_id).count()

    # Vulnerability counts by severity
    critical_vulns = db.query(Vulnerability).join(Asset).filter(
        Asset.organization_id == organization_id,
        Vulnerability.severity == SeverityLevel.CRITICAL
    ).count()

    high_vulns = db.query(Vulnerability).join(Asset).filter(
        Asset.organization_id == organization_id,
        Vulnerability.severity == SeverityLevel.HIGH
    ).count()

    medium_vulns = db.query(Vulnerability).join(Asset).filter(
        Asset.organization_id == organization_id,
        Vulnerability.severity == SeverityLevel.MEDIUM
    ).count()

    # DRP findings
    drp_threats = db.query(DigitalRiskFinding).filter(
        DigitalRiskFinding.organization_id == organization_id,
        DigitalRiskFinding.is_resolved == False
    ).count()

    # Calculate preliminary Exposure Score (0 - 100, where 100 is excellent posture, 0 is critical risk)
    # Deduct penalty for severe exposures
    penalty = (critical_vulns * 25) + (high_vulns * 10) + (medium_vulns * 3) + (drp_threats * 5)
    exposure_score = max(0, min(100, 100 - penalty))

    return {
        "organization_id": organization_id,
        "exposure_score": exposure_score,
        "posture": "Critical" if exposure_score < 50 else ("Fair" if exposure_score < 75 else "Good"),
        "total_assets": total_assets,
        "live_assets": live_assets,
        "open_services": open_ports_count,
        "vulnerabilities": {
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns
        },
        "drp_active_threats": drp_threats
    }


@router.post("/secrets/scan")
async def scan_secrets_exposure(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    """
    Executes passive secret exposure detection (GitHub REST API or sandboxed Gitleaks CLI).
    Strictly blocks arbitrary server filesystem paths and active credential testing.
    """
    ks = SecurityGovernanceGuard.is_kill_switch_active()
    if ks.get("active"):
        raise HTTPException(status_code=503, detail=f"Emergency Kill-Switch active: {ks.get('reason')}")

    org_id = int(payload.get("organization_id", 1))
    mode = str(payload.get("mode", "github_org")).strip().lower()
    ev_mgr = EvidenceManager(db)

    if mode == "local_sandbox":
        rel_repo = str(payload.get("repo_dir", "")).strip()
        sandbox_base = os.getenv(
            "OPENRECON_REPO_SANDBOX",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "repo_sandbox")),
        )
        os.makedirs(sandbox_base, exist_ok=True)
        candidate_path = os.path.join(sandbox_base, rel_repo)
        try:
            res = GitHubIntelConnector.run_gitleaks_cli(
                candidate_path,
                allowed_base_dir=sandbox_base,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        for item in res.get("findings", []):
            ev_mgr.record_finding(
                organization_id=org_id,
                related_asset=rel_repo or "sandbox",
                source="gitleaks_cli",
                technical_evidence=item.get("redacted_preview") or f"rule={item.get('rule')} sha256={item.get('secret_sha256')}",
                detection_method="gitleaks_secret_scan",
                confidence_level=0.6,
                external_reference=item.get("commit"),
                actor=operator,
            )
        db.commit()
        return {"mode": "local_sandbox", "operator": operator, **res}

    github_org = str(payload.get("target", "")).strip()
    if not github_org:
        raise HTTPException(status_code=400, detail="Missing 'target' GitHub organization/user.")
    connector = GitHubIntelConnector()
    res = await connector.execute(github_org)
    return {
        "mode": "github_org",
        "operator": operator,
        "success": res.success,
        "status": res.status.value,
        "findings": res.records,
        "error": res.error,
    }
