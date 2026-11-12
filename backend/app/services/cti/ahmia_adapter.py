"""
Ahmia Dark Web Search Adapter for OpenRecon.
Provides clean, BSD-3 compliant search client against the Ahmia .onion search index.
Supports both public surface gateway (https://ahmia.fi) and internal Tor hidden service.
"""

import logging
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import quote_plus
import httpx

from app.core.config import settings
from app.core.tor_guard import TorSecurityGuard
from app.core.evidence_sanitizer import EvidenceSanitizer

logger = logging.getLogger("openrecon.ahmia_adapter")


class AhmiaAdapter:
    """
    Client for querying the Ahmia dark web search index.
    """

    AHMIA_PUBLIC_URL = "https://ahmia.fi/search/?q="
    AHMIA_ONION_HOST = "juhanurmih5wu7bv7fv36unvxz76jdmh2beussrqfprnv4mxurghqayd.onion"
    AHMIA_ONION_URL = f"http://{AHMIA_ONION_HOST}/search/?q="

    _CACHE: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
    CACHE_TTL_SECS = 900  # 15 mins cache

    def __init__(self, tor_proxy: Optional[str] = None):
        self.tor_proxy = tor_proxy or settings.TOR_PROXY_URL

    async def search(
        self,
        query: str,
        limit: int = 15,
        use_tor: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Executes search on Ahmia with cache check and fallback.
        """
        query_clean = query.strip()
        if not query_clean:
            return []

        # Check cache
        cache_key = f"{query_clean}|{use_tor}"
        now = time.time()
        if cache_key in self._CACHE:
            ts, cached_data = self._CACHE[cache_key]
            if now - ts < self.CACHE_TTL_SECS:
                return cached_data[:limit]

        results = []
        if use_tor:
            results = await self._search_via_tor(query_clean, limit)

        # Fallback or default: surface gateway
        if not results:
            results = await self._search_via_surface(query_clean, limit)

        # Save to cache
        self._CACHE[cache_key] = (now, results)
        return results[:limit]

    async def _search_via_surface(self, query: str, limit: int) -> List[Dict[str, Any]]:
        results = []
        url = f"{self.AHMIA_PUBLIC_URL}{quote_plus(query)}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    results = self._parse_ahmia_html(resp.text, limit)
        except Exception as e:
            logger.warning(f"Ahmia surface gateway search error: {e}")

        return results

    async def _search_via_tor(self, query: str, limit: int) -> List[Dict[str, Any]]:
        results = []
        url = f"{self.AHMIA_ONION_URL}{quote_plus(query)}"
        try:
            res = await TorSecurityGuard.fetch_onion_safe(url, tor_proxy=self.tor_proxy, timeout=15.0)
            if res.get("success") and res.get("content"):
                results = self._parse_ahmia_html(res["content"], limit)
        except Exception as e:
            logger.warning(f"Ahmia onion search error: {e}")

        return results

    def _parse_ahmia_html(self, html: str, limit: int) -> List[Dict[str, Any]]:
        results = []
        # Result items are contained in <li class="result">
        items = re.findall(r'<li class="result">(.*?)</li>', html, re.DOTALL)
        for idx, item in enumerate(items[:limit]):
            title_match = re.search(r'<h4><a href="([^"]+)">(.*?)</a></h4>', item, re.DOTALL)
            snippet_match = re.search(r'<p>(.*?)</p>', item, re.DOTALL)
            time_match = re.search(r'<span class="lastSeen">(.*?)</span>', item, re.DOTALL)

            if title_match:
                raw_url = title_match.group(1).strip()
                title = re.sub(r'<[^>]+>', '', title_match.group(2)).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet_match.group(1)).strip() if snippet_match else ""
                last_seen = re.sub(r'<[^>]+>', '', time_match.group(1)).strip() if time_match else ""

                # Extract actual onion host
                onion_match = re.search(r'([a-z2-7]{16,56}\.onion)', raw_url)
                onion_url = f"http://{onion_match.group(1)}" if onion_match else raw_url

                results.append({
                    "id": f"ahmia-{idx}",
                    "title": title or "Ahmia Onion Result",
                    "source": "Ahmia Dark Web Index",
                    "source_url": onion_url,
                    "is_onion": True,
                    "snippet": snippet[:300],
                    "last_seen": last_seen,
                    "severity": "MEDIUM",
                    "confidence_score": 0.85
                })

        return results
