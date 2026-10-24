import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base


class AssetType(str, enum.Enum):
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    seed_id = Column(Integer, ForeignKey("seeds.id", ondelete="SET NULL"), nullable=True)
    
    asset_type = Column(Enum(AssetType), nullable=False, default=AssetType.SUBDOMAIN)
    value = Column(String(512), nullable=False, index=True)  # e.g., vpn.company.com or 198.51.100.1
    ip_address = Column(String(128), nullable=True, index=True)
    asn = Column(String(64), nullable=True)
    cloud_provider = Column(String(64), nullable=True)  # AWS, Azure, GCP, Cloudflare, etc.
    
    is_live = Column(Boolean, default=True)
    discovery_source = Column(String(128), nullable=True)  # crt.sh, subfinder, dnsx, etc.
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="assets")
    seed = relationship("Seed", back_populates="assets")
    ports = relationship("PortService", back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
