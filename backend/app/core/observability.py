"""
Observability, Structured Logging, Correlation IDs & Prometheus Metrics for OpenRecon 3.0.
"""

import contextvars
import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")


class JsonLogFormatter(logging.Formatter):
    """Structured JSON formatter with Correlation ID and secret-safe message."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": correlation_id_ctx.get("-"),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class MetricsRegistry:
    """Thread-safe lightweight Prometheus-compatible metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.http_requests: Dict[Tuple[str, str, int], int] = defaultdict(int)
        self.http_duration_sum: Dict[str, float] = defaultdict(float)
        self.http_duration_count: Dict[str, int] = defaultdict(int)
        self.provider_errors: Dict[str, int] = defaultdict(int)
        self.task_durations: Dict[str, float] = defaultdict(float)
        self.task_counts: Dict[str, int] = defaultdict(int)

    def observe_http(self, method: str, path: str, status_code: int, duration_s: float) -> None:
        with self._lock:
            self.http_requests[(method, path, status_code)] += 1
            self.http_duration_sum[path] += duration_s
            self.http_duration_count[path] += 1

    def inc_provider_error(self, provider: str) -> None:
        with self._lock:
            self.provider_errors[provider] += 1

    def observe_task(self, task_type: str, duration_s: float) -> None:
        with self._lock:
            self.task_durations[task_type] += duration_s
            self.task_counts[task_type] += 1

    def render_prometheus_text(self) -> str:
        lines = [
            "# HELP openrecon_http_requests_total Total HTTP requests handled by OpenRecon API",
            "# TYPE openrecon_http_requests_total counter",
        ]
        with self._lock:
            for (method, path, code), val in sorted(self.http_requests.items()):
                lines.append(
                    f'openrecon_http_requests_total{{method="{method}",path="{path}",status="{code}"}} {val}'
                )
            lines.append("# HELP openrecon_http_request_duration_seconds_sum Cumulative HTTP request duration")
            lines.append("# TYPE openrecon_http_request_duration_seconds_sum counter")
            for path, val in sorted(self.http_duration_sum.items()):
                lines.append(f'openrecon_http_request_duration_seconds_sum{{path="{path}"}} {val:.6f}')

            lines.append("# HELP openrecon_provider_errors_total Total errors per external intelligence provider")
            lines.append("# TYPE openrecon_provider_errors_total counter")
            for provider, val in sorted(self.provider_errors.items()):
                lines.append(f'openrecon_provider_errors_total{{provider="{provider}"}} {val}')

            lines.append("# HELP openrecon_task_duration_seconds_sum Cumulative background task duration")
            lines.append("# TYPE openrecon_task_duration_seconds_sum counter")
            for ttype, val in sorted(self.task_durations.items()):
                lines.append(f'openrecon_task_duration_seconds_sum{{task_type="{ttype}"}} {val:.6f}')

        return "\n".join(lines) + "\n"


metrics_registry = MetricsRegistry()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        corr_id = request.headers.get("X-Correlation-ID") or f"req-{uuid.uuid4().hex[:12]}"
        token = correlation_id_ctx.set(corr_id)
        t0 = time.monotonic()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Correlation-ID"] = corr_id
            return response
        finally:
            duration = time.monotonic() - t0
            metrics_registry.observe_http(request.method, request.url.path, status_code, duration)
            correlation_id_ctx.reset(token)
