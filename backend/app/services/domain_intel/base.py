import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import httpx

from app.core.config import settings
from app.core.domain_security import DomainSecurityError, validate_outbound_url
from app.models.domain_intel import ProviderQueryStatus


class DomainIntelCache:
    """TTL cache supporting Redis when REDIS_URL is configured, with in-memory fallback."""

    _MEM: Dict[str, Tuple[float, Any]] = {}

    def __init__(self, namespace: str = "domain_intel"):
        self.namespace = namespace
        self._redis = None
        if settings.REDIS_URL:
            try:
                import redis  # type: ignore
                self._redis = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
            except Exception:
                self._redis = None

    def _key(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    def get(self, key: str) -> Optional[Any]:
        full = self._key(key)
        if self._redis is not None:
            try:
                raw = self._redis.get(full)
                if raw:
                    return json.loads(raw)
            except Exception:
                pass
        entry = self._MEM.get(full)
        if not entry:
            return None
        expires_at, val = entry
        if time.monotonic() > expires_at:
            self._MEM.pop(full, None)
            return None
        return val

    def set(self, key: str, value: Any, ttl_seconds: int = 1800) -> None:
        if ttl_seconds <= 0:
            return
        full = self._key(key)
        if self._redis is not None:
            try:
                self._redis.setex(full, ttl_seconds, json.dumps(value, default=str))
                return
            except Exception:
                pass
        self._MEM[full] = (time.monotonic() + ttl_seconds, value)

    @classmethod
    def clear_memory(cls) -> None:
        cls._MEM.clear()


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


async def safe_http_get_with_retry(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
    max_redirects: int = 2,
    max_retries: int = 2,
    backoff_seconds: float = 0.6,
) -> httpx.Response:
    """Wrapper sobre safe_http_get con reintentos controlados ante 429/5xx o errores transitorios."""
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            resp = await safe_http_get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                max_redirects=max_redirects,
            )
            if resp.status_code in (429, 502, 503, 504) and attempt < max_retries:
                await asyncio.sleep(backoff_seconds * (attempt + 1))
                continue
            return resp
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(backoff_seconds * (attempt + 1))
                continue
            raise
    if last_exc:
        raise last_exc
    raise httpx.RequestError("Max retries exceeded")
