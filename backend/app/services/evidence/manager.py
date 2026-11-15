"""
Central Evidence Manager for OpenRecon 3.0.
Provides a single, auditable, tenant-isolated persistence layer for all findings,
guaranteeing sanitization, custody signatures, and strict separation between
OSINT matches and confirmed vulnerabilities.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.database import enforce_org_isolation
from app.core.evidence_sanitizer import EvidenceSanitizer
from app.models.evidence import EvidenceAuditLog, EvidenceRecord, FindingValidationState


class EvidenceManager:
    def __init__(self, db: Session):
        self.db = db

    def record_finding(
        self,
        organization_id: int,
        related_asset: str,
        source: str,
        technical_evidence: str,
        detection_method: str,
        confidence_level: float = 0.5,
        external_reference: Optional[str] = None,
        actor: str = "system",
        evidence_id: Optional[str] = None,
    ) -> EvidenceRecord:
        if organization_id is None or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")

        ev_id = evidence_id or f"EV-{uuid.uuid4().hex[:12].upper()}"
        sanitized_text = EvidenceSanitizer.sanitize_raw_content(technical_evidence, max_chars=4096)
        sha256 = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()
        custody_sig = EvidenceSanitizer.generate_custody_signature(ev_id, sanitized_text)
        now = datetime.now(timezone.utc)

        clamped_conf = max(0.0, min(1.0, float(confidence_level)))
        initial_history = [
            {
                "timestamp": now.isoformat(),
                "actor": actor,
                "previous_status": None,
                "new_status": FindingValidationState.NUEVO.value,
                "reason": "Initial detection recorded.",
            }
        ]

        record = EvidenceRecord(
            id=ev_id,
            organization_id=organization_id,
            related_asset=related_asset.strip(),
            source=source.strip(),
            discovered_at=now,
            last_verified_at=now,
            technical_evidence=sanitized_text,
            detection_method=detection_method.strip(),
            confidence_level=clamped_conf,
            validation_status=FindingValidationState.NUEVO.value,
            is_confirmed_vulnerability=False,  # OSINT match is never auto-confirmed as a vuln
            external_reference=external_reference,
            content_sha256=sha256,
            custody_signature=custody_sig,
            change_history=initial_history,
        )
        self.db.add(record)
        self.db.flush()
        self.db.add(
            EvidenceAuditLog(
                evidence_id=ev_id,
                organization_id=organization_id,
                actor=actor,
                previous_status=None,
                new_status=FindingValidationState.NUEVO.value,
                reason="Initial detection recorded.",
            )
        )
        self.db.commit()
        self.db.refresh(record)
        return record

    def transition_status(
        self,
        evidence_id: str,
        organization_id: int,
        new_status: FindingValidationState,
        actor: str,
        reason: str,
        is_confirmed_vulnerability: Optional[bool] = None,
    ) -> EvidenceRecord:
        query = enforce_org_isolation(
            self.db.query(EvidenceRecord), EvidenceRecord, organization_id
        )
        record = query.filter(EvidenceRecord.id == evidence_id).first()
        if not record:
            raise LookupError(f"Evidence '{evidence_id}' not found for organization {organization_id}.")

        prev_status = record.validation_status
        now = datetime.now(timezone.utc)
        record.validation_status = new_status.value
        record.last_verified_at = now
        if is_confirmed_vulnerability is not None:
            record.is_confirmed_vulnerability = bool(is_confirmed_vulnerability)
        elif new_status == FindingValidationState.FALSO_POSITIVO:
            record.is_confirmed_vulnerability = False

        history = list(record.change_history or [])
        history.append(
            {
                "timestamp": now.isoformat(),
                "actor": actor,
                "previous_status": prev_status,
                "new_status": new_status.value,
                "reason": reason,
            }
        )
        record.change_history = history

        self.db.add(
            EvidenceAuditLog(
                evidence_id=record.id,
                organization_id=organization_id,
                actor=actor,
                previous_status=prev_status,
                new_status=new_status.value,
                reason=reason,
            )
        )
        self.db.commit()
        self.db.refresh(record)
        return record

    def list_by_organization(
        self,
        organization_id: int,
        validation_status: Optional[str] = None,
        limit: int = 100,
    ) -> List[EvidenceRecord]:
        query = enforce_org_isolation(
            self.db.query(EvidenceRecord), EvidenceRecord, organization_id
        )
        if validation_status:
            query = query.filter(EvidenceRecord.validation_status == validation_status)
        return query.order_by(EvidenceRecord.discovered_at.desc()).limit(limit).all()
