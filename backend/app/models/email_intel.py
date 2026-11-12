"""
SQLAlchemy Data Models for EMAIL INTELLIGENCE Module in OpenRecon.
Comprehensive schemas covering:
- Investigations (State lifecycle: PENDING, RUNNING, PAUSED, CANCELLED, COMPLETED, FAILED)
- Evidence Vault (Cryptographic SHA-256 chain of custody and forensic traceability)
- Leaks (HudsonRock info-stealers & breach disclosures with strict K-Anonymity)
- Accounts (Digital service presence with confidence levels)
- Pastes (Public text repository mentions)
- Domain Analysis (MX, SPF, DMARC, DKIM, DNS security posture)
- Generated Variants (Permutation hypotheses without network interaction)
"""

import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Text,
    Float,
    Boolean,
    Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class InvestigationStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, enum.Enum):
    INFORMATIVE = "INFORMATIVE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccountCheckStatus(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    NOT_FOUND = "NOT_FOUND"
    INCONCLUSIVE = "INCONCLUSIVE"
    QUERY_ERROR = "QUERY_ERROR"


class EmailIntelInvestigation(Base):
    __tablename__ = "email_intel_investigations"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    target_email = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    authorization_justification = Column(Text, nullable=False)
    status = Column(String(30), default=InvestigationStatus.PENDING.value, index=True)
    progress = Column(Integer, default=0)
    exposure_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default=RiskLevel.INFORMATIVE.value)
    risk_explanation = Column(Text, nullable=True)
    total_findings = Column(Integer, default=0)
    created_by = Column(String(100), default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    evidences = relationship("EmailIntelEvidence", back_populates="investigation", cascade="all, delete-orphan")
    leaks = relationship("EmailIntelLeak", back_populates="investigation", cascade="all, delete-orphan")
    accounts = relationship("EmailIntelAccount", back_populates="investigation", cascade="all, delete-orphan")
    pastes = relationship("EmailIntelPaste", back_populates="investigation", cascade="all, delete-orphan")
    domain_analysis = relationship("EmailIntelDomainAnalysis", back_populates="investigation", cascade="all, delete-orphan")
    generated_variants = relationship("EmailIntelGeneratedVariant", back_populates="investigation", cascade="all, delete-orphan")


class EmailIntelEvidence(Base):
    __tablename__ = "email_intel_evidence"

    id = Column(String(64), primary_key=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type = Column(String(50), nullable=False)
    source_name = Column(String(100), nullable=False)
    collected_at_utc = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    raw_content_preview = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False, index=True)
    custody_signature = Column(String(128), nullable=False)
    validation_status = Column(String(30), default="DETECTED")
    confidence_score = Column(Float, default=0.5)

    investigation = relationship("EmailIntelInvestigation", back_populates="evidences")


class EmailIntelLeak(Base):
    __tablename__ = "email_intel_leaks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("email_intel_evidence.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(100), nullable=False)
    leak_date = Column(String(50), nullable=True)
    query_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    exposed_data_types = Column(Text, nullable=False)
    confidence_level = Column(String(20), default="HIGH")
    verifiable_reference = Column(Text, nullable=True)
    corporate_services_count = Column(Integer, default=0)
    user_services_count = Column(Integer, default=0)
    computer_name_preview = Column(String(100), nullable=True)
    operating_system = Column(String(100), nullable=True)
    ip_address_preview = Column(String(50), nullable=True)

    investigation = relationship("EmailIntelInvestigation", back_populates="leaks")


class EmailIntelAccount(Base):
    __tablename__ = "email_intel_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("email_intel_evidence.id", ondelete="CASCADE"), nullable=False)
    platform = Column(String(100), nullable=False, index=True)
    status = Column(String(30), nullable=False, index=True)
    query_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    check_method = Column(String(100), nullable=False)
    evidence_snippet = Column(Text, nullable=True)
    profile_url = Column(Text, nullable=True)
    avatar_url = Column(Text, nullable=True)
    username = Column(String(150), nullable=True)
    confidence_level = Column(String(20), default="HIGH")

    investigation = relationship("EmailIntelInvestigation", back_populates="accounts")


class EmailIntelPaste(Base):
    __tablename__ = "email_intel_pastes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("email_intel_evidence.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(100), nullable=False)
    paste_url = Column(Text, nullable=False)
    discovered_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    minimal_context = Column(Text, nullable=True)
    classification = Column(String(50), default="PUBLIC_TEXT")
    evidence_snippet = Column(Text, nullable=True)

    investigation = relationship("EmailIntelInvestigation", back_populates="pastes")


class EmailIntelDomainAnalysis(Base):
    __tablename__ = "email_intel_domain_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    mail_provider = Column(String(150), nullable=True)
    mx_records_json = Column(Text, nullable=True)
    spf_record = Column(Text, nullable=True)
    spf_status = Column(String(50), nullable=True)
    dmarc_record = Column(Text, nullable=True)
    dmarc_status = Column(String(50), nullable=True)
    dkim_status = Column(String(50), nullable=True)
    dns_security_score = Column(Integer, default=0)
    weaknesses_json = Column(Text, nullable=True)
    recommendations_json = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    investigation = relationship("EmailIntelInvestigation", back_populates="domain_analysis")


class EmailIntelGeneratedVariant(Base):
    __tablename__ = "email_intel_generated_variants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("email_intel_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    base_email = Column(String(255), nullable=False)
    variant_email = Column(String(255), nullable=False)
    domain_type = Column(String(50), nullable=False)
    pattern_type = Column(String(50), nullable=False)
    classification = Column(String(50), default="HYPOTHESIS_UNVERIFIED")
    passive_mx_valid = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    investigation = relationship("EmailIntelInvestigation", back_populates="generated_variants")
