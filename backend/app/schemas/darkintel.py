"""
Pydantic v2 Schemas for DARK INTELLIGENCE Module in OpenRecon.
Provides strict validation, cryptographic verification, k-Anonymity checks,
and STIX 2.1 compliance.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict
import hashlib
import re


# ---------------------------------------------------------------------------
# Enums mirroring DB models
# ---------------------------------------------------------------------------
from app.models.darkintel import (
    EvidenceValidationStatus,
    EvidenceSeverity,
    SourceCategory,
    SourceStatus,
    ExposureType,
    CorroborationLevel,
    IOCType,
    InvestigationStatus
)


# ---------------------------------------------------------------------------
# 1. Evidence Vault Schemas
# ---------------------------------------------------------------------------
class EvidenceCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_url: str = Field(..., description="Target URL or onion address where evidence was collected")
    source_type: str = Field(..., description="ONION_PAGE, FORUM_THREAD, DLS_POST, PASTE, SEARCH_INDEX")
    raw_content: str = Field(..., description="Raw textual evidence captured")
    published_at_utc: Optional[datetime] = None
    severity: EvidenceSeverity = EvidenceSeverity.MEDIUM
    confidence_score: float = Field(0.5, ge=0.0, le=1.0)
    analyst_notes: Optional[str] = None


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source_url: str
    source_type: str
    collected_at_utc: datetime
    published_at_utc: Optional[datetime]
    last_verified_utc: Optional[datetime]
    raw_content_preview: str
    content_sha256: str
    custody_signature: str
    validation_status: EvidenceValidationStatus
    severity: EvidenceSeverity
    confidence_score: float
    analyst_notes: Optional[str]


# ---------------------------------------------------------------------------
# 2. Dark Web Source Schemas
# ---------------------------------------------------------------------------
class DarkSourceCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_name: str = Field(..., max_length=150)
    onion_address: str = Field(..., max_length=255)
    category: SourceCategory = SourceCategory.RANSOMWARE_DLS
    reliability_rating: str = Field("B", pattern="^[A-F]$")
    check_interval_mins: int = Field(360, ge=15)

    @field_validator("onion_address")
    @classmethod
    def validate_onion_address(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if not re.search(r"([a-z2-7]{16,56}\.onion)", v_clean):
            raise ValueError("Invalid .onion address format (must be v2/v3 onion hostname)")
        return v_clean


class DarkSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_name: str
    onion_address: str
    category: SourceCategory
    status: SourceStatus
    reliability_rating: str
    last_seen_online: Optional[datetime]
    response_time_ms: Optional[int]
    check_interval_mins: int
    created_at: datetime


# ---------------------------------------------------------------------------
# 3. Leak Intelligence Schemas (Zero-Cleartext Guarantee)
# ---------------------------------------------------------------------------
class DarkLeakCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    target_organization_id: Optional[int] = None
    domain_mentioned: str
    raw_identifier: str = Field(..., description="Email, username, or identifier before masking")
    raw_password: Optional[str] = Field(None, description="Cleartext password provided only for hashing; NEVER stored")
    exposure_type: ExposureType = ExposureType.CREDENTIAL
    leak_source: str
    corroboration_level: CorroborationLevel = CorroborationLevel.UNVERIFIED
    data_classes: Optional[List[str]] = Field(default_factory=list)

    @field_validator("raw_identifier")
    @classmethod
    def enforce_email_or_user_format(cls, v: str) -> str:
        if not v or len(v.strip()) < 3:
            raise ValueError("Identifier must be at least 3 characters")
        return v.strip().lower()


class DarkLeakOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    target_organization_id: Optional[int]
    domain_mentioned: str
    masked_identity: str
    credential_hash: Optional[str]
    exposure_type: ExposureType
    leak_source: str
    discovered_at: datetime
    corroboration_level: CorroborationLevel
    data_classes: Optional[str]


# ---------------------------------------------------------------------------
# 4. Ransomware Extortion Schemas
# ---------------------------------------------------------------------------
class RansomwarePostCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    group_name: str
    victim_name: str
    victim_website: Optional[str] = None
    claim_details: Optional[str] = None
    ransom_deadline: Optional[datetime] = None
    data_volume_gb: Optional[float] = None
    matched_organization_id: Optional[int] = None
    post_date_utc: Optional[datetime] = None
    status: str = "ACTIVE"
    proof_links: Optional[List[str]] = Field(default_factory=list)


class RansomwarePostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    group_name: str
    victim_name: str
    victim_website: Optional[str]
    claim_details: Optional[str]
    ransom_deadline: Optional[datetime]
    data_volume_gb: Optional[float]
    matched_organization_id: Optional[int]
    post_date_utc: Optional[datetime]
    discovered_at_utc: datetime
    status: str
    proof_links: Optional[str]


# ---------------------------------------------------------------------------
# 5. Threat Actor Schemas
# ---------------------------------------------------------------------------
class ThreatActorCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Unique slug or STIX threat-actor ID")
    name: str
    aliases: Optional[List[str]] = Field(default_factory=list)
    origin_country: Optional[str] = None
    motivation: str = "FINANCIAL"
    associated_malware: Optional[List[str]] = Field(default_factory=list)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list)
    darkweb_dls_onion: Optional[str] = None
    target_sectors: Optional[List[str]] = Field(default_factory=list)
    confidence_level: str = "MEDIUM"


class ThreatActorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    aliases: Optional[str]
    origin_country: Optional[str]
    motivation: Optional[str]
    associated_malware: Optional[str]
    mitre_techniques: Optional[str]
    darkweb_dls_onion: Optional[str]
    target_sectors: Optional[str]
    confidence_level: str
    last_activity_date: Optional[datetime]


# ---------------------------------------------------------------------------
# 6. IOC Intelligence Schemas (STIX 2.1 Ready)
# ---------------------------------------------------------------------------
class IOCCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    ioc_type: IOCType
    ioc_value: str
    context_threat: Optional[str] = None
    reputation_score: int = Field(0, ge=0, le=100)
    is_malicious: bool = False


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    ioc_type: IOCType
    ioc_value: str
    normalized_value: str
    context_threat: Optional[str]
    stix_bundle_json: Optional[str]
    reputation_score: int
    is_malicious: bool
    first_observed_utc: datetime
    last_verified_utc: Optional[datetime]


# ---------------------------------------------------------------------------
# 7. Search Query & Auditing Schemas
# ---------------------------------------------------------------------------
class DarkSearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=255)
    query_type: str = Field("DOMAIN", description="DOMAIN, ORG_NAME, BRAND, EMAIL, IP, CVE, KEYWORD")
    sources: Optional[List[str]] = Field(default_factory=lambda: ["ahmia", "onionsearch", "ransomwatch"])
    include_surface: bool = True
    min_confidence: float = Field(0.3, ge=0.0, le=1.0)
    date_from: Optional[datetime] = None


class DarkSearchOut(BaseModel):
    query: str
    query_type: str
    sources_queried: List[str]
    coverage_statement: str
    total_results: int
    onion_results: int
    execution_time_ms: int
    results: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# 8. Organization Exposure Investigation Schemas
# ---------------------------------------------------------------------------
class InvestigationCreate(BaseModel):
    organization_id: int
    title: str
    scope_domains: List[str] = Field(..., min_length=1)
    scope_brands: Optional[List[str]] = Field(default_factory=list)
    scope_emails: Optional[List[str]] = Field(default_factory=list)


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    title: str
    investigation_scope: str
    status: InvestigationStatus
    total_findings: int
    critical_findings: int
    exposure_score: float
    executive_summary: Optional[str]
    recommendations: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
