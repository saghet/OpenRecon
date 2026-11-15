"""
Standardized Connector Architecture for OpenRecon 3.0.
Every OSINT, EASM, CTI, and Breach provider implements BaseConnector
with uniform identity, rate limiting, timeouts, error handling, and normalization.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.core.observability import metrics_registry

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ConnectorStatus(str, Enum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"
    ERROR = "ERROR"


@dataclass
class ConnectorConfig:
    connector_id: str
    name: str
    version: str
    source: str
    timeout: float = 10.0
    rate_limit_rps: float = 5.0
    enabled: bool = True
    max_retries: int = 1
    backoff_base_seconds: float = 0.25
    failure_threshold: int = 3
    recovery_timeout_seconds: float = 30.0
    cache_ttl_seconds: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedConnectorResult:
    connector_id: str
    source: str
    target: str
    success: bool
    status: ConnectorStatus
    records: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    latency_ms: int = 0
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BaseConnector(ABC):
    """Abstract base class for all OpenRecon external intelligence connectors."""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.status: ConnectorStatus = (
            ConnectorStatus.READY if config.enabled else ConnectorStatus.DISABLED
        )
        self._last_request_ts: float = 0.0
        self._rate_lock = asyncio.Lock()
        self._circuit_state: CircuitState = CircuitState.CLOSED
        self._consecutive_failures: int = 0
        self._circuit_opened_at: float = 0.0
        self._cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}

    async def _respect_rate_limit(self) -> None:
        if self.config.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / self.config.rate_limit_rps
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_ts
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_ts = time.monotonic()

    @abstractmethod
    async def _fetch_raw(self, target: str, **kwargs) -> Any:
        """Performs the underlying provider query."""

    @abstractmethod
    def normalize(self, raw_data: Any, target: str) -> List[Dict[str, Any]]:
        """Normalizes provider-specific payloads into OpenRecon standard records."""

    async def health_check(self) -> Dict[str, Any]:
        return {
            "connector_id": self.config.connector_id,
            "name": self.config.name,
            "version": self.config.version,
            "source": self.config.source,
            "status": self.status.value,
        }

    def metadata(self) -> Dict[str, Any]:
        return {
            "connector_id": self.config.connector_id,
            "name": self.config.name,
            "version": self.config.version,
            "source": self.config.source,
            "timeout": self.config.timeout,
            "rate_limit_rps": self.config.rate_limit_rps,
            "enabled": self.config.enabled,
            "status": self.status.value,
        }

    async def execute(self, target: str, **kwargs) -> NormalizedConnectorResult:
        if not self.config.enabled or self.status == ConnectorStatus.DISABLED:
            return NormalizedConnectorResult(
                connector_id=self.config.connector_id,
                source=self.config.source,
                target=target,
                success=False,
                status=ConnectorStatus.DISABLED,
                error="Connector is disabled.",
            )

        # Circuit breaker check
        if self._circuit_state == CircuitState.OPEN:
            if (time.monotonic() - self._circuit_opened_at) >= self.config.recovery_timeout_seconds:
                self._circuit_state = CircuitState.HALF_OPEN
            else:
                metrics_registry.inc_provider_error(f"{self.config.connector_id}:circuit_open")
                return NormalizedConnectorResult(
                    connector_id=self.config.connector_id,
                    source=self.config.source,
                    target=target,
                    success=False,
                    status=ConnectorStatus.DEGRADED,
                    error=f"Circuit breaker OPEN for '{self.config.connector_id}'.",
                )

        cache_key = f"{target}:{sorted(kwargs.items())}"
        if self.config.cache_ttl_seconds > 0 and cache_key in self._cache:
            exp_ts, cached_records = self._cache[cache_key]
            if time.monotonic() < exp_ts:
                return NormalizedConnectorResult(
                    connector_id=self.config.connector_id,
                    source=self.config.source,
                    target=target,
                    success=True,
                    status=ConnectorStatus.READY,
                    records=cached_records,
                    latency_ms=0,
                )

        t0 = time.monotonic()
        last_error: Optional[str] = None
        last_status = ConnectorStatus.ERROR
        attempts = max(1, 1 + self.config.max_retries)

        for attempt in range(attempts):
            await self._respect_rate_limit()
            try:
                raw = await asyncio.wait_for(
                    self._fetch_raw(target, **kwargs),
                    timeout=self.config.timeout,
                )
                normalized = self.normalize(raw, target)
                latency = int((time.monotonic() - t0) * 1000)
                metrics_registry.observe_task(f"connector:{self.config.connector_id}", (time.monotonic() - t0))
                self.status = ConnectorStatus.READY
                self._consecutive_failures = 0
                self._circuit_state = CircuitState.CLOSED
                if self.config.cache_ttl_seconds > 0:
                    self._cache[cache_key] = (time.monotonic() + self.config.cache_ttl_seconds, normalized)
                return NormalizedConnectorResult(
                    connector_id=self.config.connector_id,
                    source=self.config.source,
                    target=target,
                    success=True,
                    status=ConnectorStatus.READY,
                    records=normalized,
                    latency_ms=latency,
                )
            except asyncio.TimeoutError:
                last_status = ConnectorStatus.DEGRADED
                last_error = f"Connector '{self.config.connector_id}' timed out after {self.config.timeout}s"
                logger.warning(last_error)
            except Exception as exc:
                last_status = ConnectorStatus.ERROR
                last_error = str(exc)
                logger.warning(f"Connector '{self.config.connector_id}' error: {exc}")

            if attempt < attempts - 1:
                await asyncio.sleep(self.config.backoff_base_seconds * (2 ** attempt))

        metrics_registry.inc_provider_error(self.config.connector_id)
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.config.failure_threshold:
            self._circuit_state = CircuitState.OPEN
            self._circuit_opened_at = time.monotonic()

        self.status = last_status
        latency = int((time.monotonic() - t0) * 1000)
        return NormalizedConnectorResult(
            connector_id=self.config.connector_id,
            source=self.config.source,
            target=target,
            success=False,
            status=last_status,
            error=last_error,
            latency_ms=latency,
        )
