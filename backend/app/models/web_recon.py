"""
Web Reconnaissance, Historical Endpoint Discovery & Tool Execution Models for OpenRecon 3.0.
Integrates selective WebCopilot capabilities natively into OpenRecon's PostgreSQL/SQLite schema.
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class DiscoveredEndpoint(Base):
    """Historical or crawled web endpoint linked to an EASM Asset."""

    __tablename__ = "discovered_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(64), nullable=True, index=True)

    url = Column(Text, nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)
    canonical_key = Column(String(64), nullable=False, index=True)
    scheme = Column(String(16), default="https", nullable=False)
    host = Column(String(255), nullable=False, index=True)
    path = Column(Text, default="/", nullable=False)
    method = Column(String(16), default="GET", nullable=False)

    query_params = Column(JSON, default=list, nullable=False)
    has_params = Column(Boolean, default=False, nullable=False, index=True)
    gf_categories = Column(JSON, default=list, nullable=False)
    sources = Column(JSON, default=list, nullable=False)
    status_code = Column(Integer, nullable=True)

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    asset = relationship("Asset")

    __table_args__ = (
        Index("ix_endpoint_org_canonical", "organization_id", "canonical_key"),
        Index("ix_endpoint_org_host", "organization_id", "host"),
    )


class WebScanExecution(Base):
    """Execution telemetry and audit log for each WebCopilotAdapter tool run."""

    __tablename__ = "web_scan_executions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(64), nullable=True, index=True)

    tool_name = Column(String(64), nullable=False, index=True)
    tool_version = Column(String(64), nullable=True)
    status = Column(String(32), default="COMPLETED", nullable=False, index=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    items_processed = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    parameters_used = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    finished_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class WebOrgPolicy(Base):
    """Per-organization authorization policy for optional active/OOB web checks."""

    __tablename__ = "web_org_policies"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    interactsh_enabled = Column(Boolean, default=False, nullable=False)
    interactsh_server = Column(String(255), nullable=True)
    interactsh_token_encrypted = Column(Text, nullable=True)

    sqlmap_enabled = Column(Boolean, default=False, nullable=False)
    nuclei_allow_intrusive = Column(Boolean, default=False, nullable=False)
    max_concurrency = Column(Integer, default=5, nullable=False)
    rate_limit_rps = Column(Integer, default=15, nullable=False)

    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
