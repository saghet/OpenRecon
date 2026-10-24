from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime
from app.models.scan import ScanType, ScanStatus


class ScanJobCreate(BaseModel):
    organization_id: int
    scan_type: ScanType = ScanType.EASM_FULL


class ScanJobResponse(BaseModel):
    id: int
    organization_id: int
    scan_type: ScanType
    status: ScanStatus
    total_targets: int
    processed_targets: int
    summary: Optional[str] = None
    error_log: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
