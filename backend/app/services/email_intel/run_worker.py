"""
Standalone CLI Worker for Email Intelligence.
Usage: python -m app.services.email_intel.run_worker <INVESTIGATION_ID>
Can be spawned by PHP api.php or FastAPI BackgroundTasks.
"""

import sys
import asyncio
import os
import logging

# Ensure backend is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.email_intel.orchestrator import EmailIntelOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("email_intel.worker")


async def main():
    if len(sys.argv) < 2:
        logger.error("Error: Missing investigation ID parameter.")
        print("Usage: python -m app.services.email_intel.run_worker <INV_ID>")
        sys.exit(1)

    inv_id = sys.argv[1].strip()
    logger.info(f"Starting Email Intelligence worker execution for: {inv_id}")
    orchestrator = EmailIntelOrchestrator()
    await orchestrator.run_investigation(inv_id)
    logger.info(f"Worker finished execution for {inv_id}")


if __name__ == "__main__":
    asyncio.run(main())
