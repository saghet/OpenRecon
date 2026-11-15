import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional
from app.core.auth import require_api_token
from app.core.database import get_db, SessionLocal
from app.core.security_guard import SecurityGovernanceGuard
from app.models.organization import Organization, Seed
from app.models.scan import ScanJob, ScanStatus, ScanType
from app.schemas.scan import ScanJobCreate, ScanJobResponse
from app.services.scanner_orchestrator import ScannerOrchestrator

router = APIRouter()

_ACTIVE_SCAN_TASKS: Dict[int, asyncio.Task] = {}
_ACTIVE_SCAN_PROCESSES: Dict[int, List[Any]] = {}


def register_scan_process(scan_job_id: int, proc: Any) -> None:
    _ACTIVE_SCAN_PROCESSES.setdefault(scan_job_id, []).append(proc)


def stop_scan_execution(scan_job_id: int) -> Dict[str, int]:
    """Cancel active asyncio task and terminate any tracked subprocesses for a scan job."""
    cancelled_tasks = 0
    terminated_processes = 0

    task = _ACTIVE_SCAN_TASKS.get(scan_job_id)
    if task is not None and not task.done():
        task.cancel()
        cancelled_tasks += 1

    procs = _ACTIVE_SCAN_PROCESSES.pop(scan_job_id, [])
    for proc in procs:
        try:
            if getattr(proc, "returncode", None) is None:
                proc.terminate()
                terminated_processes += 1
        except Exception:
            try:
                proc.kill()
                terminated_processes += 1
            except Exception:
                pass

    return {
        "cancelled_tasks": cancelled_tasks,
        "terminated_processes": terminated_processes,
    }


def cancel_all_active_scans() -> Dict[str, int]:
    """Cancel all active scan tasks and subprocesses across the platform."""
    scan_ids = list(set(_ACTIVE_SCAN_TASKS.keys()) | set(_ACTIVE_SCAN_PROCESSES.keys()))
    total_tasks = 0
    total_procs = 0
    for sid in scan_ids:
        res = stop_scan_execution(sid)
        total_tasks += res["cancelled_tasks"]
        total_procs += res["terminated_processes"]
    return {
        "stopped_scan_ids": len(scan_ids),
        "cancelled_tasks": total_tasks,
        "terminated_processes": total_procs,
    }


async def run_scan_in_background(scan_job_id: int):
    db = SessionLocal()
    current_task = asyncio.current_task()
    if current_task is not None:
        _ACTIVE_SCAN_TASKS[scan_job_id] = current_task
    try:
        orchestrator = ScannerOrchestrator(db)
        await orchestrator.execute_scan(scan_job_id)
    except asyncio.CancelledError:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job and job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            job.status = ScanStatus.STOPPED
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        _ACTIVE_SCAN_TASKS.pop(scan_job_id, None)
        _ACTIVE_SCAN_PROCESSES.pop(scan_job_id, None)
        db.close()


@router.post("/", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
def launch_scan(
    scan_in: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
):
    ks = SecurityGovernanceGuard.is_kill_switch_active()
    if ks.get("active"):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Scan rejected: Emergency Kill Switch is ACTIVE ({ks.get('reason')})",
        )

    org = db.query(Organization).filter(Organization.id == scan_in.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    active_seeds = db.query(Seed).filter(Seed.organization_id == org.id, Seed.is_active == 1).all()
    if not active_seeds:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RoE Violation: Organization has no active authorized seeds.",
        )

    authorized_scope = [s.value for s in active_seeds]
    for s in active_seeds:
        check = SecurityGovernanceGuard.validate_target_safety(
            s.value,
            authorized_scope=authorized_scope,
            resolve_dns=True,
        )
        if not check.get("safe"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"RoE / Anti-SSRF Violation for seed '{s.value}': {check.get('reason')}",
            )

    job = ScanJob(
        organization_id=scan_in.organization_id,
        scan_type=scan_in.scan_type,
        status=ScanStatus.PENDING
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Dispatch to background task runner
    background_tasks.add_task(run_scan_in_background, job.id)

    return job


@router.get("/active")
def list_active_scans() -> Dict[str, Any]:
    """Return currently active scan job IDs tracked in memory."""
    active_ids = sorted(
        sid for sid, task in _ACTIVE_SCAN_TASKS.items() if not task.done()
    )
    return {
        "active_scan_ids": active_ids,
        "tracked_processes": {str(k): len(v) for k, v in _ACTIVE_SCAN_PROCESSES.items()},
    }


@router.post("/{scan_id}/stop")
def stop_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    """Stop an active scan job, cancelling its asyncio task and tracked subprocesses."""
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    exec_stop = stop_scan_execution(scan_id)
    if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        job.status = ScanStatus.STOPPED
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(job)

    return {
        "scan_id": scan_id,
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        **exec_stop,
    }


@router.get("/{scan_id}", response_model=ScanJobResponse)
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/", response_model=List[ScanJobResponse])
def list_scans(
    organization_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(ScanJob)
    if organization_id:
        query = query.filter(ScanJob.organization_id == organization_id)
    return query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()
