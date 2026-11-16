"""
FastAPI Endpoints for Selective WebCopilot Integration (/api/v1/web-recon).
Enforces RoE scope, Kill-Switch, API Token auth, and Safe-by-Default org policies.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import require_api_token
from app.core.database import SessionLocal, get_db
from app.core.security_guard import SecurityGovernanceGuard
from app.models.asset import Asset
from app.models.evidence import EvidenceRecord, FindingValidationState
from app.models.exposure import Vulnerability
from app.models.organization import Organization, Seed
from app.models.scan import ScanJob, ScanStatus, ScanType
from app.models.web_recon import DiscoveredEndpoint, WebOrgPolicy, WebScanExecution
from app.services.web_security.webcopilot_adapter import WebCopilotAdapter, WebReconOptions

router = APIRouter()


class WebReconScanRequest(BaseModel):
    organization_id: int
    investigation_id: Optional[str] = Field(default=None, max_length=64)
    asset_ids: Optional[List[int]] = None
    enable_historical_discovery: bool = True
    enable_param_analysis: bool = True
    enable_nuclei_enrichment: bool = True
    enable_xss_validation: bool = True
    enable_open_redirect_validation: bool = True
    allow_intrusive_nuclei: bool = False
    allow_interactsh_oob: bool = False
    allow_controlled_sqlmap: bool = False
    excluded_domains: List[str] = Field(default_factory=list)


class WebOrgPolicyUpdate(BaseModel):
    interactsh_enabled: Optional[bool] = None
    interactsh_server: Optional[str] = Field(default=None, max_length=255)
    interactsh_token: Optional[str] = Field(default=None, max_length=512)
    sqlmap_enabled: Optional[bool] = None
    nuclei_allow_intrusive: Optional[bool] = None
    max_concurrency: Optional[int] = Field(default=None, ge=1, le=20)
    rate_limit_rps: Optional[int] = Field(default=None, ge=1, le=50)


async def _run_selective_web_recon_bg(
    organization_id: int,
    scan_job_id: int,
    asset_ids: Optional[List[int]],
    authorized_scope: List[str],
    investigation_id: Optional[str],
    options: WebReconOptions,
) -> None:
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = ScanStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            db.commit()

        q = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.is_live == True)  # noqa: E712
        if asset_ids:
            q = q.filter(Asset.id.in_(asset_ids))
        assets = q.all()

        adapter = WebCopilotAdapter(db=db)
        res = await adapter.run_for_assets(
            organization_id=organization_id,
            assets=assets,
            authorized_scope=authorized_scope,
            scan_job_id=scan_job_id,
            investigation_id=investigation_id,
            options=options,
        )
        if job:
            job.status = ScanStatus.COMPLETED
            job.finished_at = datetime.now(timezone.utc)
            job.processed_targets = len(assets)
            job.summary = str(res)
            db.commit()
    except Exception as exc:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = ScanStatus.FAILED
            job.error_log = str(exc)
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
def launch_selective_web_recon(
    req: WebReconScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    ks = SecurityGovernanceGuard.is_kill_switch_active()
    if ks.get("active"):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Web Recon rejected: Emergency Kill Switch is ACTIVE ({ks.get('reason')})",
        )

    org = db.query(Organization).filter(Organization.id == req.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    active_seeds = db.query(Seed).filter(Seed.organization_id == org.id, Seed.is_active == 1).all()
    if not active_seeds:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RoE Violation: Organization has no active authorized seeds.",
        )

    authorized_scope = [s.value for s in active_seeds]
    live_q = db.query(Asset).filter(Asset.organization_id == org.id, Asset.is_live == True)  # noqa: E712
    if req.asset_ids:
        live_q = live_q.filter(Asset.id.in_(req.asset_ids))
    live_assets = live_q.all()
    if not live_assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No live assets available for selective web recon.",
        )

    job = ScanJob(
        organization_id=org.id,
        scan_type=ScanType.WEB_RECON,
        status=ScanStatus.PENDING,
        total_targets=len(live_assets),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    opts = WebReconOptions(
        enable_historical_discovery=req.enable_historical_discovery,
        enable_param_analysis=req.enable_param_analysis,
        enable_nuclei_enrichment=req.enable_nuclei_enrichment,
        enable_xss_validation=req.enable_xss_validation,
        enable_open_redirect_validation=req.enable_open_redirect_validation,
        allow_intrusive_nuclei=req.allow_intrusive_nuclei,
        allow_interactsh_oob=req.allow_interactsh_oob,
        allow_controlled_sqlmap=req.allow_controlled_sqlmap,
        excluded_domains=req.excluded_domains,
    )
    background_tasks.add_task(
        _run_selective_web_recon_bg,
        org.id,
        job.id,
        req.asset_ids,
        authorized_scope,
        req.investigation_id,
        opts,
    )
    return {
        "scan_job_id": job.id,
        "organization_id": org.id,
        "scan_type": ScanType.WEB_RECON.value,
        "targets_queued": len(live_assets),
        "status": ScanStatus.PENDING.value,
    }


@router.get("/endpoints/{organization_id}")
def list_discovered_endpoints(
    organization_id: int,
    only_with_params: bool = Query(default=False),
    gf_category: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    q = db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.organization_id == organization_id)
    if only_with_params:
        q = q.filter(DiscoveredEndpoint.has_params == True)  # noqa: E712

    rows = q.order_by(DiscoveredEndpoint.last_seen.desc()).limit(limit).all()
    if gf_category:
        cat_low = gf_category.strip().lower()
        rows = [r for r in rows if cat_low in [c.lower() for c in (r.gf_categories or [])]]

    return {
        "organization_id": organization_id,
        "count": len(rows),
        "endpoints": [
            {
                "id": r.id,
                "asset_id": r.asset_id,
                "url": r.url,
                "host": r.host,
                "path": r.path,
                "query_params": r.query_params,
                "has_params": r.has_params,
                "gf_categories": r.gf_categories,
                "sources": r.sources,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in rows
        ],
    }


@router.get("/summary/{organization_id}")
def get_web_recon_summary(
    organization_id: int,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    endpoints = db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.organization_id == organization_id).all()
    param_endpoints = [e for e in endpoints if e.has_params]
    unique_params = sorted({p for e in param_endpoints for p in (e.query_params or [])})

    gf_breakdown: Dict[str, int] = {}
    for ep in endpoints:
        for cat in (ep.gf_categories or []):
            gf_breakdown[cat] = gf_breakdown.get(cat, 0) + 1

    vulns = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id)
        .all()
    )
    by_detector: Dict[str, int] = {}
    for v in vulns:
        det = v.detector or "unknown"
        by_detector[det] = by_detector.get(det, 0) + 1

    evidences = db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == organization_id).all()
    confirmed_count = sum(1 for e in evidences if e.validation_status == FindingValidationState.CONFIRMADO.value)
    potential_count = sum(
        1 for e in evidences
        if e.validation_status in (
            FindingValidationState.PROBABLE.value,
            FindingValidationState.PENDIENTE_DE_VERIFICACION.value,
            FindingValidationState.NUEVO.value,
        )
    )

    executions = (
        db.query(WebScanExecution)
        .filter(WebScanExecution.organization_id == organization_id)
        .order_by(WebScanExecution.started_at.desc())
        .limit(30)
        .all()
    )

    return {
        "organization_id": organization_id,
        "total_endpoints": len(endpoints),
        "parameterized_endpoints": len(param_endpoints),
        "unique_parameters": unique_params,
        "gf_category_breakdown": gf_breakdown,
        "vulnerabilities_by_detector": by_detector,
        "confirmed_vs_potential": {
            "confirmed": confirmed_count,
            "potential": potential_count,
        },
        "execution_history": [
            {
                "id": ex.id,
                "tool_name": ex.tool_name,
                "status": ex.status,
                "duration_ms": ex.duration_ms,
                "items_processed": ex.items_processed,
                "findings_count": ex.findings_count,
                "started_at": ex.started_at.isoformat() if ex.started_at else None,
            }
            for ex in executions
        ],
    }


@router.get("/policy/{organization_id}")
def get_web_org_policy(
    organization_id: int,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    policy = db.query(WebOrgPolicy).filter(WebOrgPolicy.organization_id == organization_id).first()
    if not policy:
        return {
            "organization_id": organization_id,
            "interactsh_enabled": False,
            "interactsh_server": None,
            "has_interactsh_token": False,
            "sqlmap_enabled": False,
            "nuclei_allow_intrusive": False,
            "max_concurrency": 5,
            "rate_limit_rps": 15,
        }
    return {
        "organization_id": organization_id,
        "interactsh_enabled": policy.interactsh_enabled,
        "interactsh_server": policy.interactsh_server,
        "has_interactsh_token": bool(policy.interactsh_token_encrypted),
        "sqlmap_enabled": policy.sqlmap_enabled,
        "nuclei_allow_intrusive": policy.nuclei_allow_intrusive,
        "max_concurrency": policy.max_concurrency,
        "rate_limit_rps": policy.rate_limit_rps,
    }


@router.put("/policy/{organization_id}")
def update_web_org_policy(
    organization_id: int,
    payload: WebOrgPolicyUpdate,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    policy = db.query(WebOrgPolicy).filter(WebOrgPolicy.organization_id == organization_id).first()
    if not policy:
        policy = WebOrgPolicy(organization_id=organization_id)
        db.add(policy)

    if payload.interactsh_enabled is not None:
        policy.interactsh_enabled = payload.interactsh_enabled
    if payload.interactsh_server is not None:
        policy.interactsh_server = payload.interactsh_server.strip() or None
    if payload.interactsh_token is not None:
        # Store only hashed/protected token reference; never return plaintext
        import hashlib
        policy.interactsh_token_encrypted = hashlib.sha256(payload.interactsh_token.encode("utf-8")).hexdigest()
    if payload.sqlmap_enabled is not None:
        policy.sqlmap_enabled = payload.sqlmap_enabled
    if payload.nuclei_allow_intrusive is not None:
        policy.nuclei_allow_intrusive = payload.nuclei_allow_intrusive
    if payload.max_concurrency is not None:
        policy.max_concurrency = payload.max_concurrency
    if payload.rate_limit_rps is not None:
        policy.rate_limit_rps = payload.rate_limit_rps

    db.commit()
    db.refresh(policy)
    return get_web_org_policy(organization_id, db=db, _operator=_operator)
