"""
Centralized Settings Hub API (/api/v1/settings) for OpenRecon 3.0.
Aggregates internal runtime governance, WebOrgPolicy (RoE), encrypted external
OSINT/CTI provider credentials, and external platform integrations (OpenCTI/MISP/DeepSeek)
without ever exposing plaintext secrets.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import require_api_token
from app.core.config import settings
from app.core.database import get_db
from app.core.security_guard import SecurityGovernanceGuard
from app.models.domain_intel import ProviderCredential
from app.models.web_recon import WebOrgPolicy
from app.services.domain_intel.service import SUPPORTED_PROVIDERS

router = APIRouter()


class RuntimeSettingsUpdate(BaseModel):
    safe_mode: Optional[bool] = None
    max_concurrent_tasks: Optional[int] = Field(default=None, ge=1, le=50)
    rate_limit_rps: Optional[int] = Field(default=None, ge=1, le=100)
    enable_external_binaries: Optional[bool] = None


@router.get("/overview")
def get_settings_overview(
    organization_id: int = Query(default=1, ge=1),
    db: Session = Depends(get_db),
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    db_url = settings.DATABASE_URL or ""
    db_engine = "postgresql" if db_url.startswith("postgres") else "sqlite"

    policy = (
        db.query(WebOrgPolicy)
        .filter(WebOrgPolicy.organization_id == organization_id)
        .first()
    )
    web_policy = {
        "interactsh_enabled": policy.interactsh_enabled if policy else False,
        "interactsh_server": policy.interactsh_server if policy else None,
        "has_interactsh_token": bool(policy and policy.interactsh_token_encrypted),
        "sqlmap_enabled": policy.sqlmap_enabled if policy else False,
        "nuclei_allow_intrusive": policy.nuclei_allow_intrusive if policy else False,
        "max_concurrency": policy.max_concurrency if policy else settings.MAX_CONCURRENT_TASKS,
        "rate_limit_rps": policy.rate_limit_rps if policy else settings.RATE_LIMIT_RPS,
    }

    cred_rows = (
        db.query(ProviderCredential)
        .filter(ProviderCredential.organization_id == organization_id)
        .all()
    )
    by_name = {r.provider_name: r for r in cred_rows}
    external_apis: List[Dict[str, Any]] = []
    for pname in SUPPORTED_PROVIDERS:
        r = by_name.get(pname)
        external_apis.append({
            "provider_name": pname,
            "is_configured": r is not None,
            "is_enabled": bool(r.is_enabled) if r else True,
            "masked_hint": r.masked_hint if r else None,
            "updated_at": r.updated_at.isoformat() if (r and r.updated_at) else None,
        })

    return {
        "organization_id": organization_id,
        "internal": {
            "project_name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "safe_mode": bool(settings.SAFE_MODE),
            "max_concurrent_tasks": int(settings.MAX_CONCURRENT_TASKS),
            "rate_limit_rps": int(settings.RATE_LIMIT_RPS),
            "enable_external_binaries": bool(settings.ENABLE_EXTERNAL_BINARIES),
            "tor_proxy_url": settings.TOR_PROXY_URL,
            "tor_verify_ssl": bool(settings.TOR_VERIFY_SSL),
            "database_engine": db_engine,
            "redis_configured": bool(settings.REDIS_URL),
            "api_token_protected": bool(settings.OPENRECON_API_TOKEN),
            "master_key_configured": bool(settings.OPENRECON_MASTER_KEY),
            "kill_switch": SecurityGovernanceGuard.is_kill_switch_active(),
        },
        "web_policy": web_policy,
        "external_apis": external_apis,
        "platforms": {
            "opencti": {
                "configured": bool(settings.OPENCTI_URL and settings.OPENCTI_TOKEN),
                "url": settings.OPENCTI_URL or None,
            },
            "misp": {
                "configured": bool(settings.MISP_URL and settings.MISP_KEY),
                "url": settings.MISP_URL or None,
            },
            "deepseek_ai": {
                "configured": bool(settings.DEEPSEEK_API_KEY),
                "model": settings.DEEPSEEK_MODEL,
                "base_url": settings.DEEPSEEK_BASE_URL,
            },
        },
    }


@router.put("/runtime")
def update_runtime_settings(
    payload: RuntimeSettingsUpdate,
    _operator: str = Depends(require_api_token),
) -> Dict[str, Any]:
    if payload.safe_mode is not None:
        settings.SAFE_MODE = payload.safe_mode
    if payload.max_concurrent_tasks is not None:
        settings.MAX_CONCURRENT_TASKS = payload.max_concurrent_tasks
    if payload.rate_limit_rps is not None:
        settings.RATE_LIMIT_RPS = payload.rate_limit_rps
    if payload.enable_external_binaries is not None:
        settings.ENABLE_EXTERNAL_BINARIES = payload.enable_external_binaries

    return {
        "updated": True,
        "safe_mode": bool(settings.SAFE_MODE),
        "max_concurrent_tasks": int(settings.MAX_CONCURRENT_TASKS),
        "rate_limit_rps": int(settings.RATE_LIMIT_RPS),
        "enable_external_binaries": bool(settings.ENABLE_EXTERNAL_BINARIES),
    }
