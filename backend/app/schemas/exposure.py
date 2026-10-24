from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.models.exposure import SeverityLevel, RiskType


class PortServiceBase(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    banner: Optional[str] = None
    web_title: Optional[str] = None
    status_code: Optional[int] = None
    tech_stack: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_expiry: Optional[datetime] = None


class PortServiceResponse(PortServiceBase):
    id: int
    asset_id: int
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityBase(BaseModel):
    title: str
    severity: SeverityLevel = SeverityLevel.INFO
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    cisa_kev: bool = False
    description: Optional[str] = None
    remediation: Optional[str] = None
    detector: str = "nuclei"
    template_id: Optional[str] = None


class VulnerabilityResponse(VulnerabilityBase):
    id: int
    asset_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DigitalRiskFindingBase(BaseModel):
    risk_type: RiskType
    target_value: str
    details: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    source: str = "certstream"
    is_resolved: bool = False


class DigitalRiskFindingResponse(DigitalRiskFindingBase):
    id: int
    organization_id: int
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)
