from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DomainInvestigateRequest(BaseModel):
    organization_id: int = Field(..., ge=1)
    target: str = Field(..., min_length=1, max_length=1024, description="Dominio, subdominio, IPv4, IPv6 o URL")
    use_cache: bool = Field(default=True)
    cache_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    enabled_providers: Optional[List[str]] = Field(
        default=None,
        description="Lista opcional de proveedores a consultar; si es None consulta todos los habilitados."
    )
    enforce_roe_scope: bool = Field(
        default=False,
        description="Si True, exige que el objetivo pertenezca a los Seeds activos de la organización."
    )
    authorized_scope: Optional[List[str]] = Field(
        default=None,
        description="Lista explícita de dominios semilla autorizados (RoE) enviados por el gateway."
    )


class ProviderCredentialUpsert(BaseModel):
    organization_id: int = Field(..., ge=1)
    provider_name: str = Field(..., min_length=2, max_length=64)
    api_key: str = Field(..., min_length=4, max_length=512)
    is_enabled: bool = Field(default=True)


class ProviderCredentialStatusOut(BaseModel):
    provider_name: str
    is_configured: bool
    is_enabled: bool
    masked_hint: Optional[str] = None
    updated_at: Optional[datetime] = None


class ProviderResultOut(BaseModel):
    provider_name: str
    status: str
    from_cache: bool = False
    latency_ms: Optional[int] = None
    queried_at: datetime
    error_message: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class DomainIndicatorOut(BaseModel):
    id: int
    indicator_type: str
    indicator_value: str
    source: str
    relationship_type: str
    confidence: int
    evidence: Optional[str] = None
    first_seen: datetime


class DomainInvestigationOut(BaseModel):
    id: int
    organization_id: int
    asset_id: Optional[int] = None
    target_input: str
    normalized_domain: str
    input_type: str
    trigger_source: str
    status: str
    risk_tier: str
    technical_risk_score: Optional[float] = None
    external_reputation_score: Optional[float] = None
    confidence_score: float
    risk_explanation: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    correlation_graph: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    provider_results: List[ProviderResultOut] = Field(default_factory=list)
    indicators: List[DomainIndicatorOut] = Field(default_factory=list)
    cache_expires_at: Optional[datetime] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class DomainHistoryItemOut(BaseModel):
    id: int
    normalized_domain: str
    input_type: str
    trigger_source: str
    status: str
    risk_tier: str
    technical_risk_score: Optional[float] = None
    external_reputation_score: Optional[float] = None
    confidence_score: float
    created_at: datetime
    completed_at: Optional[datetime] = None
