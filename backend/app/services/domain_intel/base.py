import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

from app.core.domain_security import DomainSecurityError, validate_outbound_url
from app.models.domain_intel import ProviderQueryStatus


@dataclass
class ProviderResponse:
    provider_name: str
    status: ProviderQueryStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    latency_ms: int = 0
    queried_at: datetime = field(default_factory=datetime.utcnow)
    from_cache: bool = False


class AsyncRateLimiter:
    """Rate limiter asíncrono por proveedor basado en intervalo mínimo entre peticiones."""

    def __init__(self, min_interval_seconds: float = 0.25):
        self.min_interval = min_interval_seconds
        self._locks: Dict[str, asyncio.Lock] = {}
        self._last_call: Dict[str, float] = {}

    async def wait(self, key: str) -> None:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        async with self._locks[key]:
            now = time.monotonic()
            last = self._last_call.get(key, 0.0)
            wait_for = self.min_interval - (now - last)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_call[key] = time.monotonic()


async def safe_http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
    max_redirects: int = 2,
) -> httpx.Response:
    """
    Ejecuta GET HTTPS validando cada redirección contra política anti-SSRF.
    """
    current_url = validate_outbound_url(url)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            resp = await client.get(current_url, headers=headers, params=params)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    break
                if loc.startswith("/"):
                    # Redirección relativa al mismo host HTTPS ya validado
                    from urllib.parse import urljoin
                    loc = urljoin(current_url, loc)
                current_url = validate_outbound_url(loc)
                params = None
                continue
            return resp
    raise DomainSecurityError("Demasiadas redirecciones externas o bucle de redirección bloqueado.")
