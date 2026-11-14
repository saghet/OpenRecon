import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Enum, ForeignKey, Text, Float, Boolean, UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class IndicatorInputType(str, enum.Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    URL = "URL"


class ProviderQueryStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    NO_DATA = "NO_DATA"
    KEY_NOT_CONFIGURED = "KEY_NOT_CONFIGURED"
    INVALID_KEY = "INVALID_KEY"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    SKIPPED_DISABLED = "SKIPPED_DISABLED"


class DomainRiskTier(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


class RelationshipConfidenceType(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class DomainInvestigation(Base):
    """Expediente persistente de investigación de dominio, IP o URL."""
    __tablename__ = "domain_investigations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    target_input = Column(String(1024), nullable=False)
    normalized_domain = Column(String(512), nullable=False, index=True)
    input_type = Column(Enum(IndicatorInputType), nullable=False, default=IndicatorInputType.DOMAIN)
    trigger_source = Column(String(64), nullable=False, default="MANUAL")  # MANUAL, EASM, DRP

    status = Column(String(32), nullable=False, default="PENDING", index=True)  # PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
    risk_tier = Column(Enum(DomainRiskTier), nullable=False, default=DomainRiskTier.UNKNOWN, index=True)
    technical_risk_score = Column(Float, nullable=True)
    external_reputation_score = Column(Float, nullable=True)
    confidence_score = Column(Float, nullable=False, default=0.0)
    risk_explanation = Column(Text, nullable=True)

    summary_json = Column(Text, nullable=True)
    correlation_graph_json = Column(Text, nullable=True)
    limitations_json = Column(Text, nullable=True)

    cache_expires_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    provider_results = relationship(
        "DomainProviderResult", back_populates="investigation", cascade="all, delete-orphan"
    )
    indicators = relationship(
        "DomainIndicator", back_populates="investigation", cascade="all, delete-orphan"
    )
    reputation_history = relationship(
        "DomainReputationHistory", back_populates="investigation", cascade="all, delete-orphan"
    )


class DomainProviderResult(Base):
    """Resultado individual y trazable por cada fuente de inteligencia consultada."""
    __tablename__ = "domain_provider_results"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("domain_investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    provider_name = Column(String(64), nullable=False, index=True)  # rdap_whois, virustotal, otx, dns, crt_sh, abuseipdb, urlhaus, threatfox, talos
    status = Column(Enum(ProviderQueryStatus), nullable=False)
    from_cache = Column(Boolean, default=False)
    latency_ms = Column(Integer, nullable=True)
    queried_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text, nullable=True)
    data_json = Column(Text, nullable=True)

    investigation = relationship("DomainInvestigation", back_populates="provider_results")


class DomainIndicator(Base):
    """Indicadores de compromiso y entidades relacionadas descubiertas en la investigación."""
    __tablename__ = "domain_indicators"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("domain_investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    indicator_type = Column(String(64), nullable=False, index=True)  # IP, SUBDOMAIN, ASN, CERT, URL, MALWARE, PULSE, NAMESERVER, MX
    indicator_value = Column(String(1024), nullable=False, index=True)
    source = Column(String(64), nullable=False)
    relationship_type = Column(Enum(RelationshipConfidenceType), nullable=False, default=RelationshipConfidenceType.OBSERVED)
    confidence = Column(Integer, nullable=False, default=50)  # 0-100
    evidence = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("DomainInvestigation", back_populates="indicators")


class DomainReputationHistory(Base):
    """Registro histórico de cambios de reputación y riesgo por dominio y organización."""
    __tablename__ = "domain_reputation_history"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(Integer, ForeignKey("domain_investigations.id", ondelete="CASCADE"), nullable=False, index=True)

    normalized_domain = Column(String(512), nullable=False, index=True)
    risk_tier = Column(Enum(DomainRiskTier), nullable=False)
    external_reputation_score = Column(Float, nullable=True)
    vt_malicious = Column(Integer, nullable=True)
    vt_suspicious = Column(Integer, nullable=True)
    otx_pulses = Column(Integer, nullable=True)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)

    investigation = relationship("DomainInvestigation", back_populates="reputation_history")


class ProviderCredential(Base):
    """Almacenamiento cifrado de API Keys por organización y proveedor."""
    __tablename__ = "domain_provider_credentials"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider_name", name="uq_org_provider_cred"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(64), nullable=False, index=True)
    encrypted_api_key = Column(Text, nullable=False)
    masked_hint = Column(String(32), nullable=False)
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
