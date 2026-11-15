"""
Common Normalized Finding Contract & Global Deterministic Deduplication Engine.
Inspired by DefectDojo's hash_code deduplication model, adapted for OpenRecon's
multi-engine EASM, DRP, OSINT, Email, Secret, and Vulnerability pipelines.

Guarantees:
- Uniform schema across all engines.
- Deterministic SHA-256 fingerprint per organization, entity, finding type, and canonical key.
- Preservation of independent source evidences (never discards corroborating evidence on dedup).
- Automatic secret/PII sanitization via EvidenceSanitizer.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.evidence_sanitizer import EvidenceSanitizer
from app.models.evidence import FindingValidationState


def compute_finding_fingerprint(
    organization_id: int,
    entity_type: str,
    entity_value: str,
    finding_type: str,
    canonical_key: str,
) -> str:
    """Computes a deterministic SHA-256 fingerprint for global deduplication."""
    parts = [
        str(int(organization_id)),
        entity_type.strip().lower(),
        entity_value.strip().lower(),
        finding_type.strip().lower(),
        canonical_key.strip().lower(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class NormalizedFinding:
    organization_id: int
    entity_type: str  # domain, subdomain, ip, url, email, repo, cve, ioc
    entity_value: str
    finding_type: str  # subdomain_discovery, vulnerability, typosquatting, secret_exposure, breach, account_presence, ioc_match
    source: str
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 0.5  # 0.0 - 1.0
    verification_status: str = FindingValidationState.NUEVO.value
    evidence: str = ""
    source_reference: Optional[str] = None
    investigation_id: Optional[str] = None
    finding_id: str = field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:12].upper()}")
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data: Dict[str, Any] = field(default_factory=dict)
    normalized_data: Dict[str, Any] = field(default_factory=dict)
    expiration: Optional[str] = None
    canonical_key: Optional[str] = None
    fingerprint: str = ""
    sources_seen: List[str] = field(default_factory=list)
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.entity_type = self.entity_type.strip().lower()
        self.entity_value = self.entity_value.strip().lower()
        self.finding_type = self.finding_type.strip().lower()
        self.severity = self.severity.strip().upper()
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.evidence = EvidenceSanitizer.sanitize_raw_content(self.evidence or "", max_chars=2048)

        key = self.canonical_key or self.normalized_data.get("cve_id") or self.normalized_data.get("template_id") or self.normalized_data.get("title") or self.entity_value
        if not self.fingerprint:
            self.fingerprint = compute_finding_fingerprint(
                self.organization_id,
                self.entity_type,
                self.entity_value,
                self.finding_type,
                str(key),
            )
        if self.source and self.source not in self.sources_seen:
            self.sources_seen.append(self.source)
        if self.evidence and not self.evidence_refs:
            self.evidence_refs.append({
                "source": self.source,
                "source_reference": self.source_reference,
                "collected_at": self.last_seen,
                "evidence_sha256": hashlib.sha256(self.evidence.encode("utf-8")).hexdigest(),
                "excerpt": self.evidence[:500],
            })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "organization_id": self.organization_id,
            "investigation_id": self.investigation_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "finding_type": self.finding_type,
            "source": self.source,
            "source_reference": self.source_reference,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
            "confidence": self.confidence,
            "verification_status": self.verification_status,
            "evidence": self.evidence,
            "raw_data": self.raw_data,
            "normalized_data": self.normalized_data,
            "expiration": self.expiration,
            "fingerprint": self.fingerprint,
            "sources_seen": list(self.sources_seen),
            "evidence_refs": list(self.evidence_refs),
        }


class GlobalFindingDeduplicator:
    """
    Deduplicates NormalizedFindings by deterministic fingerprint while
    preserving all independent source evidences and elevating confidence
    when multiple independent sources corroborate the same finding.
    """

    def __init__(self) -> None:
        self._records: Dict[str, NormalizedFinding] = {}

    def ingest(self, finding: NormalizedFinding) -> Dict[str, Any]:
        fp = finding.fingerprint
        if fp not in self._records:
            self._records[fp] = finding
            return {"deduplicated": False, "finding": finding, "corroboration_count": len(finding.sources_seen)}

        existing = self._records[fp]
        existing.last_seen = max(existing.last_seen, finding.last_seen)

        # Preserve independent source attribution & evidence without overwriting
        if finding.source and finding.source not in existing.sources_seen:
            existing.sources_seen.append(finding.source)
        existing_hashes = {ref.get("evidence_sha256") for ref in existing.evidence_refs}
        for ref in finding.evidence_refs:
            if ref.get("evidence_sha256") not in existing_hashes:
                existing.evidence_refs.append(ref)
                existing_hashes.add(ref.get("evidence_sha256"))

        # Keep highest confidence observed
        if finding.confidence > existing.confidence:
            existing.confidence = finding.confidence

        return {
            "deduplicated": True,
            "duplicate_of": existing.finding_id,
            "finding": existing,
            "corroboration_count": len(existing.sources_seen),
        }

    def all_findings(self) -> List[NormalizedFinding]:
        return list(self._records.values())
