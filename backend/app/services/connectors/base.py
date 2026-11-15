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
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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

        await self._respect_rate_limit()
        t0 = time.monotonic()
        try:
            raw = await asyncio.wait_for(
                self._fetch_raw(target, **kwargs),
                timeout=self.config.timeout,
            )
            normalized = self.normalize(raw, target)
            latency = int((time.monotonic() - t0) * 1000)
            self.status = ConnectorStatus.READY
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
            latency = int((time.monotonic() - t0) * 1000)
            self.status = ConnectorStatus.DEGRADED
            err = f"Connector '{self.config.connector_id}' timed out after {self.config.timeout}s"
            logger.warning(err)
            return NormalizedConnectorResult(
                connector_id=self.config.connector_id,
                source=self.config.source,
                target=target,
                success=False,
                status=ConnectorStatus.DEGRADED,
                error=err,
                latency_ms=latency,
            )
        except Exception as exc:
            latency = int((time.monotonic() - t0) * 1000)
            self.status = ConnectorStatus.ERROR
            err = f"Connector '{self.config.connector_id}' error: {exc}"
            logger.warning(err)
            return NormalizedConnectorResult(
                connector_id=self.config.connector_id,
                source=self.config.source,
                target=target,
                success=False,
                status=ConnectorStatus.ERROR,
                error=str(exc),
                latency_ms=latency,
            )
