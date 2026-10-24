import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class ScanType(str, enum.Enum):
    EASM_FULL = "EASM_FULL"
    SUBDOMAIN_DISCOVERY = "SUBDOMAIN_DISCOVERY"
    PORT_SCAN = "PORT_SCAN"
    DRP_SCAN = "DRP_SCAN"
    VULN_SCAN = "VULN_SCAN"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    scan_type = Column(Enum(ScanType), default=ScanType.EASM_FULL)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    
    total_targets = Column(Integer, default=0)
    processed_targets = Column(Integer, default=0)
    
    summary = Column(Text, nullable=True)  # JSON or text summary
    error_log = Column(Text, nullable=True)
    
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="scan_jobs")
