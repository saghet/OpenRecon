"""
API Authentication & Authorization Guard for OpenRecon FastAPI Microservice.
Validates X-OpenRecon-Token or Authorization: Bearer <token> when
OPENRECON_API_TOKEN is configured in environment/settings.
"""

import hmac
from typing import Optional
from fastapi import Header, HTTPException, status

from app.core.config import settings


def require_api_token(
    x_openrecon_token: Optional[str] = Header(default=None, alias="X-OpenRecon-Token"),
    authorization: Optional[str] = Header(default=None),
) -> str:
    """
    Enforces API token authentication on protected endpoints when OPENRECON_API_TOKEN is set.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected = settings.OPENRECON_API_TOKEN
    if not expected:
        # Local single-node mode when no token is configured
        return "local-operator"

    provided = x_openrecon_token
    if not provided and authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()

    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing OpenRecon API authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "authenticated-operator"
