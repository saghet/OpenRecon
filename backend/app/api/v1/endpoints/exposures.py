from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict, Any
from app.core.database import get_db
from app.models.asset import Asset
from app.models.exposure import Vulnerability, DigitalRiskFinding, PortService, SeverityLevel
from app.schemas.exposure import VulnerabilityResponse, DigitalRiskFindingResponse

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
