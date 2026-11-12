"""
Pydantic Schemas for the Email Intelligence Module.
Strict validation and type safety under Pydantic v2.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr, field_validator
import re


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class InvestigationCreateRequest(BaseModel):
    target_email: str = Field(..., description="Target email address for OSINT investigation")
    case_id: str = Field(..., min_length=2, max_length=100, description="Legal/Operational case identifier")
    title: str = Field(..., min_length=3, max_length=255, description="Investigation title")
    description: Optional[str] = Field(None, max_length=1000, description="Contextual notes")
    tags: Optional[List[str]] = Field(default_factory=list, description="Categorization tags")
    authorization_justification: str = Field(..., min_length=5, description="Legal basis or RoE justification")

    @field_validator("target_email")
    @classmethod
    def validate_email_syntax(cls, v: str) -> str:
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError(f"Invalid email address syntax: '{v}'. Must satisfy RFC 5322.")
        domain = clean.split("@")[-1]
        # Anti-SSRF check on email domain
        blocked_domains = ["localhost", "127.0.0.1", "0.0.0.0", "internal", "local", "169.254.169.254"]
        if domain in blocked_domains or domain.endswith(".local") or domain.endswith(".internal"):
            raise ValueError(f"Target email domain '{domain}' is blocked by anti-SSRF policy.")
        return clean


class LeakFinding(BaseModel):
    source: str
    leak_date: Optional[str] = None
    query_date: str
    exposed_data_types: List[str]
    confidence_level: str = "HIGH"
    verifiable_reference: Optional[str] = None
    corporate_services_count: int = 0
    user_services_count: int = 0
    computer_name_preview: Optional[str] = None
    operating_system: Optional[str] = None
    ip_address_preview: Optional[str] = None
    raw_evidence_sha256: str


class AccountFinding(BaseModel):
    platform: str
    status: str  # CONFIRMED, PROBABLE, NOT_FOUND, INCONCLUSIVE, QUERY_ERROR
    query_date: str
    check_method: str
    evidence_snippet: Optional[str] = None
    profile_url: Optional[str] = None
    avatar_url: Optional[str] = None
    username: Optional[str] = None
    confidence_level: str = "HIGH"
    raw_evidence_sha256: str


class PasteFinding(BaseModel):
    source: str
    paste_url: str
    discovered_date: str
    minimal_context: Optional[str] = None
    classification: str = "PUBLIC_TEXT"
    evidence_snippet: Optional[str] = None
    raw_evidence_sha256: str


class DomainAnalysisFinding(BaseModel):
    domain: str
    mail_provider: Optional[str] = "Unknown"
    mx_records: List[Dict[str, Any]] = Field(default_factory=list)
    spf_record: Optional[str] = None
    spf_status: str = "MISSING"  # VALID, SOFTFAIL, NEUTRAL, MISSING, SYNTAX_ERROR
    dmarc_record: Optional[str] = None
    dmarc_status: str = "MISSING"  # REJECT, QUARANTINE, NONE, MISSING, SYNTAX_ERROR
    dkim_status: str = "UNKNOWN"
    dns_security_score: int = 0  # 0 to 100
    weaknesses: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class EmailVariantFinding(BaseModel):
    base_email: str
    variant_email: str
    domain_type: str
    pattern_type: str
    classification: str = "HYPOTHESIS_UNVERIFIED"
    passive_mx_valid: bool = False


class InvestigationSummary(BaseModel):
    id: str
    case_id: str
    title: str
    target_email: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    authorization_justification: str
    status: str
    progress: int
    exposure_score: float
    risk_level: str
    risk_explanation: Optional[str] = None
    total_findings: int
    created_at: str
    updated_at: str
    leaks_count: int = 0
    accounts_confirmed_count: int = 0
    accounts_total_checked: int = 0
    pastes_count: int = 0
    variants_count: int = 0
    domain_security_score: int = 0
