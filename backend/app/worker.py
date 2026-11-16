"""
Independent Recon Worker for OpenRecon 3.0.
Consumes queued ScanJobs via Redis (openrecon:queue:scans) with PostgreSQL polling fallback,
enforcing Kill-Switch, graceful shutdown (SIGTERM/SIGINT), and isolated execution.
"""

import asyncio
import logging
import signal
import sys
import time
from typing import Optional

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security_guard import SecurityGovernanceGuard
from app.models.scan import ScanJob, ScanStatus
from app.services.scanner_orchestrator import ScannerOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("openrecon.worker")

_SHUTDOWN_EVENT = False
_QUEUE_KEY = "openrecon:queue:scans"


def _handle_signal(signum, _frame):
    global _SHUTDOWN_EVENT
    logger.info(f"Received signal {signum}; draining recon worker gracefully...")
    _SHUTDOWN_EVENT = True


def _pop_next_job_id() -> Optional[int]:
    if settings.REDIS_URL:
        try:
            import redis  # type: ignore

            client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
            item = client.blpop(_QUEUE_KEY, timeout=3)
            if item and len(item) == 2:
                return int(item[1])
        except Exception as exc:
            logger.debug(f"Redis queue poll fallback to DB: {exc}")

    db = SessionLocal()
    try:
        job = (
            db.query(ScanJob)
            .filter(ScanJob.status == ScanStatus.PENDING)
            .order_by(ScanJob.created_at.asc())
            .first()
        )
        return job.id if job else None
    finally:
        db.close()


async def worker_loop() -> None:
    logger.info("OpenRecon independent recon-worker started.")
    while not _SHUTDOWN_EVENT:
        if SecurityGovernanceGuard.is_kill_switch_active().get("active"):
            await asyncio.sleep(3.0)
            continue

        job_id = _pop_next_job_id()
        if job_id is None:
            await asyncio.sleep(2.0)
            continue

        db = SessionLocal()
        try:
            logger.info(f"Executing ScanJob {job_id} in isolated recon-worker")
            orchestrator = ScannerOrchestrator(db)
            await orchestrator.execute_scan(job_id)
        except Exception as exc:
            logger.exception(f"Worker error processing ScanJob {job_id}: {exc}")
        finally:
            db.close()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        asyncio.run(worker_loop())
    except KeyboardInterrupt:
        sys.exit(0)
