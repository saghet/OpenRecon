"""
Parallel Multi-Engine Search Adapter for Dark Intelligence.
Inspired by OnionSearch and TorBot architecture:
- Dispatches concurrent asynchronous queries across independent dark web search engines.
- Enforces per-engine timeouts so a stalled or blocking engine never delays the overall response.
- Aggregates, normalizes, and deduplicates findings into standard CTI objects.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any

from app.services.cti.ahmia_adapter import AhmiaAdapter
from app.services.cti.dark_search_engine import DarkSearchEngine
from app.services.cti.dark_collector_service import SQLITE_PATH

logger = logging.getLogger("openrecon.multi_engine_adapter")


class MultiEngineSearchAdapter:
    """
    Parallel query orchestrator for Dark Web search engines.
    """

    def __init__(
        self,
        sqlite_db_path: str = SQLITE_PATH,
        tor_proxy: Optional[str] = None
    ):
        self.sqlite_db_path = sqlite_db_path
        self.tor_proxy = tor_proxy
        self.ahmia_adapter = AhmiaAdapter(tor_proxy=self.tor_proxy)
        self.search_engine = DarkSearchEngine(sqlite_db_path=self.sqlite_db_path, tor_proxy=self.tor_proxy)

    async def search_all_engines(
        self,
        query: str,
        limit_per_engine: int = 15,
        engine_timeout: float = 8.0
    ) -> Dict[str, Any]:
        """
        Executes concurrent queries against all active engines with isolated timeouts.
        """
        tasks = [
            self._query_with_timeout("ahmia", self.ahmia_adapter.search(query, limit=limit_per_engine), timeout=engine_timeout),
            self._query_with_timeout("local_vault", self._search_vault(query, limit=limit_per_engine), timeout=engine_timeout),
            self._query_with_timeout("ransomware_dls", self._search_ransomware(query, limit=limit_per_engine), timeout=engine_timeout)
        ]

        engine_results = await asyncio.gather(*tasks, return_exceptions=True)

        combined_results = []
        engine_status = {}

        for item in engine_results:
            if isinstance(item, tuple) and len(item) == 3:
                name, success, data = item
                engine_status[name] = {"success": success, "count": len(data) if success else 0}
                if success and isinstance(data, list):
                    combined_results.extend(data)
            elif isinstance(item, Exception):
                logger.warning(f"Engine query exception: {item}")

        # Deduplicate
        seen_urls = set()
        deduped = []
        for r in combined_results:
            url = r.get("source_url") or r.get("url") or ""
            if url and url not in seen_urls:
                seen_urls.add(url)
                deduped.append(r)
            elif not url:
                deduped.append(r)

        return {
            "query": query,
            "engine_status": engine_status,
            "total_deduplicated_results": len(deduped),
            "results": deduped
        }

    async def _query_with_timeout(self, name: str, coro, timeout: float) -> Tuple[str, bool, List[Dict[str, Any]]]:
        try:
            res = await asyncio.wait_for(coro, timeout=timeout)
            return (name, True, res if isinstance(res, list) else [])
        except asyncio.TimeoutError:
            logger.debug(f"Engine '{name}' timed out after {timeout}s.")
            return (name, False, [])
        except Exception as e:
            logger.debug(f"Engine '{name}' error: {e}")
            return (name, False, [])

    async def _search_vault(self, query: str, limit: int) -> List[Dict[str, Any]]:
        return self.search_engine._search_evidence_vault(query, min_confidence=0.3)[:limit]

    async def _search_ransomware(self, query: str, limit: int) -> List[Dict[str, Any]]:
        return self.search_engine._search_ransomware_posts(query)[:limit]
