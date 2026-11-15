"""
Centralized EvidenceRecord & Audit Models for OpenRecon 3.0.
Separates raw OSINT/telemetry matches from confirmed vulnerabilities
and tracks full chain of custody + state transitions.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from app.core.database import Base


class FindingValidationState(str, enum.Enum):
    NUEVO = "NUEVO"
    PENDIENTE_DE_VERIFICACION = "PENDIENTE_DE_VERIFICACION"
    CONFIRMADO = "CONFIRMADO"
    PROBABLE = "PROBABLE"
    FALSO_POSITIVO = "FALSO_POSITIVO"
    NO_REPRODUCIBLE = "NO_REPRODUCIBLE"
    REMEDIADO = "REMEDIADO"


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    related_asset = Column(String(512), nullable=False, index=True)
    source = Column(String(128), nullable=False, index=True)
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_verified_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    technical_evidence = Column(Text, nullable=False)
    detection_method = Column(String(64), nullable=False)
    confidence_level = Column(Float, default=0.5, nullable=False)
    validation_status = Column(
        String(32),
        default=FindingValidationState.NUEVO.value,
        nullable=False,
        index=True,
    )
    is_confirmed_vulnerability = Column(Boolean, default=False, nullable=False)
    external_reference = Column(String(512), nullable=True)
    content_sha256 = Column(String(64), nullable=False, index=True)
    custody_signature = Column(String(128), nullable=False)
    change_history = Column(JSON, default=list, nullable=False)

    __table_args__ = (
        Index("ix_evidence_org_asset", "organization_id", "related_asset"),
        Index("ix_evidence_org_status", "organization_id", "validation_status"),
    )


class EvidenceAuditLog(Base):
    __tablename__ = "evidence_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    actor = Column(String(128), nullable=False)
    previous_status = Column(String(32), nullable=True)
    new_status = Column(String(32), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
