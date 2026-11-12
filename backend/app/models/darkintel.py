"""
SQLAlchemy Data Models for DARK INTELLIGENCE Module in OpenRecon.
Comprehensive schemas covering:
- Evidence Vault (Cryptographic SHA-256 chain of custody)
- Dark Web Sources & Onion Services
- Leak Intelligence (k-Anonymity hashed credentials)
- Ransomware Intelligence (DLS syndicates and victims)
- Threat Actor Intelligence (Profiles & MITRE ATT&CK mapping)
- IOC Intelligence (STIX 2.1 indicators)
- Search Auditing & Coverage Transparency
- Organization Exposure Investigations
"""

import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Enum,
    ForeignKey,
    Text,
    Float,
    Boolean,
    Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class EvidenceValidationStatus(str, enum.Enum):
    DETECTED = "DETECTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CORROBORATED = "CORROBORATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISCARDED = "DISCARDED"


class EvidenceSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SourceCategory(str, enum.Enum):
    RANSOMWARE_DLS = "RANSOMWARE_DLS"
    FORUM = "FORUM"
    PASTE = "PASTE"
    MARKET = "MARKET"
    INDEX = "INDEX"
    C2_BLOG = "C2_BLOG"
    SURFACE_MIRROR = "SURFACE_MIRROR"


class SourceStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    OFFLINE = "OFFLINE"
    UNRESPONSIVE = "UNRESPONSIVE"
    REDIRECT = "REDIRECT"
    BLOCKED = "BLOCKED"


class ExposureType(str, enum.Enum):
    CREDENTIAL = "CREDENTIAL"
    VPN_CONFIG = "VPN_CONFIG"
    SQL_DUMP = "SQL_DUMP"
    INTERNAL_DOC = "INTERNAL_DOC"
    CLOUD_SECRET = "CLOUD_SECRET"
    EMPLOYEE_PII = "EMPLOYEE_PII"
    ACCESS_BROKER = "ACCESS_BROKER"


class CorroborationLevel(str, enum.Enum):
    UNVERIFIED = "UNVERIFIED"
    PROBABLE = "PROBABLE"
    VERIFIED = "VERIFIED"


class IOCType(str, enum.Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    ONION_URL = "ONION_URL"
    CRYPTO_WALLET = "CRYPTO_WALLET"
    CVE_ID = "CVE_ID"


class InvestigationStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"


# ---------------------------------------------------------------------------
# 1. Evidence Vault: Inmutable Cryptographic Record
# ---------------------------------------------------------------------------
class DarkEvidenceVault(Base):
    """
    Forensic repository of all collected threat intelligence evidence.
    Each item is uniquely identified and indexed by its SHA-256 raw content hash.
    """
    __tablename__ = "darkintel_evidence_vault"

    id = Column(String(64), primary_key=True, index=True)  # SHA-256 of raw_content
    source_url = Column(Text, nullable=False)
    source_type = Column(String(50), nullable=False)  # ONION_PAGE, FORUM_THREAD, DLS_POST, PASTE
    collected_at_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    published_at_utc = Column(DateTime, nullable=True)
    last_verified_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    raw_content_preview = Column(Text, nullable=False)  # Sanitized textual snippet (max 4KB)
    content_sha256 = Column(String(64), nullable=False, index=True)
    custody_signature = Column(String(128), nullable=False)  # HMAC-SHA256 authentication tag
    validation_status = Column(Enum(EvidenceValidationStatus), default=EvidenceValidationStatus.DETECTED, index=True)
    severity = Column(Enum(EvidenceSeverity), default=EvidenceSeverity.MEDIUM, index=True)
    confidence_score = Column(Float, default=0.5)  # 0.0 to 1.0
    analyst_notes = Column(Text, nullable=True)

    # Relationships
    leaks = relationship("DarkLeak", back_populates="evidence", cascade="all, delete-orphan")
    ransomware_posts = relationship("DarkRansomwarePost", back_populates="evidence", cascade="all, delete-orphan")
    iocs = relationship("DarkIOC", back_populates="evidence", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# 2. Dark Web Sources & Onion Tracking
# ---------------------------------------------------------------------------
class DarkSource(Base):
    """
    Tracked dark web sites, onion services, and threat discovery feeds.
    """
    __tablename__ = "darkintel_sources"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_name = Column(String(150), nullable=False)
    onion_address = Column(String(255), unique=True, nullable=False, index=True)
    category = Column(Enum(SourceCategory), default=SourceCategory.RANSOMWARE_DLS, index=True)
    status = Column(Enum(SourceStatus), default=SourceStatus.ACTIVE, index=True)
    reliability_rating = Column(String(10), default="B")  # Admiralty Scale A-F
    last_seen_online = Column(DateTime, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    check_interval_mins = Column(Integer, default=360)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# 3. Leak Intelligence & Compromised Identity Tracking
# ---------------------------------------------------------------------------
class DarkLeak(Base):
    """
    Exposed information and credential findings.
    NEVER stores plaintext passwords; stores masked identity and SHA-256 credential hash.
    """
    __tablename__ = "darkintel_leaks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("darkintel_evidence_vault.id", ondelete="CASCADE"), nullable=False, index=True)
    target_organization_id = Column(Integer, nullable=True, index=True)
    domain_mentioned = Column(String(255), nullable=False, index=True)
    masked_identity = Column(String(255), nullable=False)  # e.g., j****n@acme.corp
    credential_hash = Column(String(64), nullable=True)  # SHA-256 hash for k-anonymity matching
    exposure_type = Column(Enum(ExposureType), default=ExposureType.CREDENTIAL, index=True)
    leak_source = Column(String(100), nullable=False)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    corroboration_level = Column(Enum(CorroborationLevel), default=CorroborationLevel.UNVERIFIED, index=True)
    data_classes = Column(Text, nullable=True)  # JSON-encoded array: ["emails", "passwords", "financial"]

    evidence = relationship("DarkEvidenceVault", back_populates="leaks")


# ---------------------------------------------------------------------------
# 4. Ransomware Extortion Intelligence
# ---------------------------------------------------------------------------
class DarkRansomwarePost(Base):
    """
    Announced corporate victims from dedicated leak sites (DLS).
    """
    __tablename__ = "darkintel_ransomware_posts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("darkintel_evidence_vault.id", ondelete="CASCADE"), nullable=False, index=True)
    group_name = Column(String(100), nullable=False, index=True)
    victim_name = Column(String(255), nullable=False, index=True)
    victim_website = Column(String(255), nullable=True, index=True)
    claim_details = Column(Text, nullable=True)
    ransom_deadline = Column(DateTime, nullable=True)
    data_volume_gb = Column(Float, nullable=True)
    matched_organization_id = Column(Integer, nullable=True, index=True)
    post_date_utc = Column(DateTime, nullable=True)
    discovered_at_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String(50), default="ACTIVE")  # ACTIVE, NEGOTIATING, DATA_LEAKED, REMOVED
    proof_links = Column(Text, nullable=True)  # JSON-encoded list of sample URLs

    evidence = relationship("DarkEvidenceVault", back_populates="ransomware_posts")


# ---------------------------------------------------------------------------
# 5. Threat Actor Intelligence
# ---------------------------------------------------------------------------
class DarkThreatActor(Base):
    """
    Threat Actor dossier, aliases, motivation, and MITRE ATT&CK mapping.
    """
    __tablename__ = "darkintel_threat_actors"

    id = Column(String(64), primary_key=True, index=True)  # Slug or STIX ID
    name = Column(String(150), unique=True, nullable=False, index=True)
    aliases = Column(Text, nullable=True)  # JSON array: ["ALPHV", "Noberus"]
    origin_country = Column(String(10), nullable=True)
    motivation = Column(String(50), default="FINANCIAL")
    associated_malware = Column(Text, nullable=True)  # JSON array
    mitre_techniques = Column(Text, nullable=True)  # JSON array of T-codes: ["T1190", "T1486"]
    darkweb_dls_onion = Column(String(255), nullable=True)
    target_sectors = Column(Text, nullable=True)  # JSON array
    confidence_level = Column(String(20), default="MEDIUM")
    last_activity_date = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# 6. IOC Intelligence & STIX 2.1 Indicators
# ---------------------------------------------------------------------------
class DarkIOC(Base):
    """
    Extracted Indicators of Compromise normalized for STIX 2.1 export.
    """
    __tablename__ = "darkintel_iocs"

    id = Column(String(64), primary_key=True, index=True)  # STIX indicator UUID
    evidence_id = Column(String(64), ForeignKey("darkintel_evidence_vault.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(Enum(IOCType), nullable=False, index=True)
    ioc_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False, index=True)
    context_threat = Column(String(150), nullable=True)
    stix_bundle_json = Column(Text, nullable=True)
    reputation_score = Column(Integer, default=0)  # 0 to 100
    is_malicious = Column(Boolean, default=False)  # Conservative: False until validated
    first_observed_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_verified_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    evidence = relationship("DarkEvidenceVault", back_populates="iocs")


# ---------------------------------------------------------------------------
# 7. Search Auditing & Coverage Transparency
# ---------------------------------------------------------------------------
class DarkSearchQuery(Base):
    """
    Audit log of all Dark Web searches with coverage transparency.
    """
    __tablename__ = "darkintel_search_queries"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    query_string = Column(Text, nullable=False)
    query_type = Column(String(50), default="DOMAIN")  # DOMAIN, ORG_NAME, BRAND, EMAIL, IP, CVE, KEYWORD
    filters_applied = Column(Text, nullable=True)  # JSON object
    sources_queried = Column(Text, nullable=False)  # JSON array of sources checked
    results_count = Column(Integer, default=0)
    onion_results_count = Column(Integer, default=0)
    executed_by = Column(String(100), default="analyst")
    executed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ---------------------------------------------------------------------------
# 8. Organization Exposure Investigations
# ---------------------------------------------------------------------------
class DarkInvestigation(Base):
    """
    Holistic exposure investigation correlating surface, dark web, leaks, and CVEs.
    """
    __tablename__ = "darkintel_investigations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    investigation_scope = Column(Text, nullable=False)  # JSON list of domains, brands, emails
    status = Column(Enum(InvestigationStatus), default=InvestigationStatus.PENDING, index=True)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    exposure_score = Column(Float, default=0.0)
    executive_summary = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
