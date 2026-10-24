import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class SeedType(str, enum.Enum):
    DOMAIN = "DOMAIN"
    IP_RANGE = "IP_RANGE"
    ASN = "ASN"
    KEYWORD = "KEYWORD"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    seeds = relationship("Seed", back_populates="organization", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="organization", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="organization", cascade="all, delete-orphan")


class Seed(Base):
    __tablename__ = "seeds"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    seed_type = Column(Enum(SeedType), nullable=False, default=SeedType.DOMAIN)
    value = Column(String(512), nullable=False, index=True)
    is_active = Column(Integer, default=1)  # 1: True, 0: False
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="seeds")
    assets = relationship("Asset", back_populates="seed")
