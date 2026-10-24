import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text, Float, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base


class SeverityLevel(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskType(str, enum.Enum):
    TYPOSQUATTING = "TYPOSQUATTING"
    PHISHING_CERT = "PHISHING_CERT"
    EXPOSED_SECRET = "EXPOSED_SECRET"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    RANSOMWARE_MENTION = "RANSOMWARE_MENTION"


class PortService(Base):
    __tablename__ = "port_services"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), default="tcp")
    service_name = Column(String(128), nullable=True)  # http, https, ssh, smtp, etc.
    banner = Column(Text, nullable=True)
    web_title = Column(String(512), nullable=True)
    status_code = Column(Integer, nullable=True)
    tech_stack = Column(Text, nullable=True)  # JSON or comma-separated: nginx, wordpress, php
    ssl_issuer = Column(String(255), nullable=True)
    ssl_expiry = Column(DateTime, nullable=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", back_populates="ports")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    title = Column(String(512), nullable=False)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.INFO, index=True)
    cve_id = Column(String(64), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)  # Exploit Prediction Scoring System
    cisa_kev = Column(Boolean, default=False)  # Is it in CISA Known Exploited Vulns?
    
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    detector = Column(String(64), default="nuclei")
    template_id = Column(String(128), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="vulnerabilities")


class DigitalRiskFinding(Base):
    __tablename__ = "digital_risk_findings"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    risk_type = Column(Enum(RiskType), nullable=False, index=True)
    target_value = Column(String(512), nullable=False)  # e.g. domain-lookalike.com, or user@company.com
    details = Column(Text, nullable=True)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    source = Column(String(128), default="certstream")
    is_resolved = Column(Boolean, default=False)
    
    detected_at = Column(DateTime, default=datetime.utcnow)
