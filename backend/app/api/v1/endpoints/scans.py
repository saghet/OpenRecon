from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db, SessionLocal
from app.models.organization import Organization
from app.models.scan import ScanJob, ScanStatus, ScanType
from app.schemas.scan import ScanJobCreate, ScanJobResponse
from app.services.scanner_orchestrator import ScannerOrchestrator

router = APIRouter()


async def run_scan_in_background(scan_job_id: int):
    db = SessionLocal()
    try:
        orchestrator = ScannerOrchestrator(db)
        await orchestrator.execute_scan(scan_job_id)
    finally:
        db.close()


@router.post("/", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
def launch_scan(
    scan_in: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.id == scan_in.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

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
