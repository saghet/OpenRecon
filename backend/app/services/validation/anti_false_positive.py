"""
8-Stage Anti-False-Positive Validation Engine for OpenRecon 3.0.
Enforces deterministic, evidence-backed finding lifecycle transitions
and prevents AI/LLM assistants from altering CRITICAL/HIGH findings without proof.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from app.core.evidence_sanitizer import EvidenceSanitizer
from app.models.evidence import FindingValidationState
from app.services.validation.finding_contract import compute_finding_fingerprint


@dataclass
class CandidateFinding:
    finding_id: str
    organization_id: int
    asset: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source: str
    raw_evidence: str
    detection_method: str
    confidence: float = 0.5
    second_check_passed: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AntiFalsePositiveEngine:
    """
    Executes the 8-stage validation pipeline:
    1. initial_detection
    2. normalization
    3. deduplication
    4. evidence_verification
    5. independent_second_check
    6. classification
    7. confirmation_or_discard
    8. decision_logging
    """

    def __init__(self) -> None:
        self._seen_fingerprints: Dict[str, str] = {}
        self._preserved_evidences: Dict[str, List[Dict[str, Any]]] = {}
        self.decision_log: List[Dict[str, Any]] = []

    @staticmethod
    def _fingerprint(f: CandidateFinding) -> str:
        return compute_finding_fingerprint(
            organization_id=f.organization_id,
            entity_type=str(f.metadata.get("entity_type", "asset")),
            entity_value=f.asset,
            finding_type=f.detection_method,
            canonical_key=f.title,
        )

    def process_finding(
        self,
        candidate: CandidateFinding,
        second_verifier: Optional[Callable[[CandidateFinding], bool]] = None,
        actor: str = "afp_engine",
        is_ai_actor: bool = False,
    ) -> Dict[str, Any]:
        # AI Guardrail: AI can NEVER auto-confirm or dismiss CRITICAL/HIGH findings
        if is_ai_actor and candidate.severity.upper() in ("CRITICAL", "HIGH"):
            raise PermissionError(
                "AI/LLM actors are forbidden from changing the validation state of CRITICAL/HIGH findings."
            )

        # Stage 1 & 2: Initial Detection & Normalization
        normalized_asset = candidate.asset.strip().lower()
        sanitized_evidence = EvidenceSanitizer.sanitize_raw_content(candidate.raw_evidence, max_chars=2048)

        # Stage 3: Deduplication (preserving independent evidence)
        fp = self._fingerprint(candidate)
        ev_sha = hashlib.sha256(sanitized_evidence.encode("utf-8")).hexdigest()
        ev_entry = {
            "finding_id": candidate.finding_id,
            "source": candidate.source,
            "detection_method": candidate.detection_method,
            "evidence_sha256": ev_sha,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        if fp in self._seen_fingerprints:
            self._preserved_evidences.setdefault(fp, []).append(ev_entry)
            return {
                "finding_id": candidate.finding_id,
                "duplicate_of": self._seen_fingerprints[fp],
                "fingerprint": fp,
                "preserved_evidence_count": len(self._preserved_evidences[fp]),
                "state": FindingValidationState.PENDIENTE_DE_VERIFICACION.value,
                "deduplicated": True,
            }
        self._seen_fingerprints[fp] = candidate.finding_id
        self._preserved_evidences[fp] = [ev_entry]

        # Stage 4: Evidence Verification
        has_technical_evidence = bool(sanitized_evidence and len(sanitized_evidence.strip()) >= 10)
        if not has_technical_evidence:
            state = FindingValidationState.NO_REPRODUCIBLE
            reason = "Insufficient technical evidence to verify finding."
        else:
            # Stage 5: Independent Second Check (when verifier provided)
            second_ok = candidate.second_check_passed
            if second_verifier is not None:
                try:
                    second_ok = bool(second_verifier(candidate))
                except Exception:
                    second_ok = False

            # Stage 6 & 7: Classification & Confirmation/Discard
            if second_ok is False:
                state = FindingValidationState.FALSO_POSITIVO
                reason = "Independent second check failed to reproduce finding (False Positive)."
            elif second_ok is True and candidate.confidence >= 0.8:
                state = FindingValidationState.CONFIRMADO
                reason = "Corroborated by technical evidence and independent second check."
            elif candidate.confidence >= 0.6:
                state = FindingValidationState.PROBABLE
                reason = "Technical evidence present; awaiting independent corroboration."
            else:
                state = FindingValidationState.PENDIENTE_DE_VERIFICACION
                reason = "Low confidence detection; queued for analyst verification."

        # Stage 8: Decision Logging
        decision = {
            "finding_id": candidate.finding_id,
            "organization_id": candidate.organization_id,
            "asset": normalized_asset,
            "severity": candidate.severity.upper(),
            "state": state.value,
            "reason": reason,
            "actor": actor,
            "is_ai_actor": is_ai_actor,
            "evidence_sha256": hashlib.sha256(sanitized_evidence.encode("utf-8")).hexdigest(),
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "deduplicated": False,
        }
        self.decision_log.append(decision)
        return decision
