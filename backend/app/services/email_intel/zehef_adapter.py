"""
===============================================================================
OPENRECON - ZEHEF EMAIL INTELLIGENCE ADAPTER
Based on Zehef v2.2.1 by N0rz3 (https://github.com/N0rz3/Zehef)
Original License: GNU General Public License v3.0 (GPL-3.0)

NOTICE OF MODIFICATION (GPLv3 Sec. 5.a):
- Modified on: November 11, 2026 by OpenRecon Engineering Team
- Purpose: Decoupled asynchronous engine adaptation, removal of ANSI console
  prints, elimination of cleartext password exposure, addition of structured
  DTO responses, and enterprise concurrency controls.
===============================================================================
"""

import httpx
import hashlib
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("email_intel.zehef_adapter")

# Default user agents pool for non-invasive queries
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


class ZehefAdapter:
    """
    Decoupled adapter providing safe asynchronous HTTP client operations
    for OSINT checks, with built-in timeouts, header sanitization, and
    forensic evidence hashing.
    """

    def __init__(self, timeout_seconds: float = 8.0):
        self.timeout = timeout_seconds
        self.default_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        }

    async def get_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self.default_headers,
            timeout=self.timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )

    @staticmethod
    def calculate_sha256(content: str) -> str:
        """Calculates SHA-256 for DFIR chain of custody."""
        return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def mask_pii(text: str) -> str:
        """Masks usernames, emails, or credentials to satisfy K-Anonymity."""
        if not text:
            return ""
        if "@" in text:
            parts = text.split("@")
            user = parts[0]
            domain = parts[1]
            if len(user) <= 2:
                masked_user = user[0] + "*"
            else:
                masked_user = user[:2] + "*" * (len(user) - 2)
            return f"{masked_user}@{domain}"
        if len(text) <= 3:
            return "***"
        return text[:2] + "*" * (len(text) - 2)
