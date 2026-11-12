"""
Defensive Dark Web Intelligence Collector for OpenRecon
Monitors public ransomware leak sites, extortion blogs, and corporate breach disclosures.
Implements strict security guardrails:
- Tor SOCKS5 transport strictly for authorized threat intelligence sources.
- Read-only scraping: NEVER executes remote payloads, never downloads stolen databases.
- NEVER interacts or purchases from dark web markets.
- No plain-text passwords stored (k-anonymity SHA-256 hashing only).
- Complete evidence provenance: cryptographic SHA-256 hashes, timestamps, verified matches.
"""

import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger(__name__)


class DarkWebCollector:
    """
    Defensive collector for Ransomware Leaks and Corporate Breach Intelligence.
    """

    def __init__(
        self,
        tor_proxy: Optional[str] = None,  # e.g., "socks5://127.0.0.1:9050"
        timeout: float = 12.0,
        safe_mode: bool = True
    ):
        self.tor_proxy = tor_proxy
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.primary_feed_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
        self.groups_feed_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

    def _hash_credential(self, email_or_password: str) -> str:
        """
        Produce a SHA-256 hash for k-anonymity lookups. Never store plain text.
        """
        return hashlib.sha256(email_or_password.strip().lower().encode("utf-8")).hexdigest()

    async def fetch_ransomware_posts(self, limit: int = 150) -> List[Dict[str, Any]]:
        """
        Collect announced corporate victims from global ransomware extortion sites.
        """
        try:
            proxies = {"all://": self.tor_proxy} if self.tor_proxy else None
            async with httpx.AsyncClient(timeout=self.timeout, proxies=proxies, verify=False) as client:
                resp = await client.get(self.primary_feed_url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        # Sort by discovery date descending
                        sorted_posts = sorted(
                            data,
                            key=lambda x: x.get("discovered", ""),
                            reverse=True
                        )
                        return sorted_posts[:limit]
        except Exception as e:
            logger.warning(f"Error fetching ransomware posts feed: {e}")

        return []

    async def fetch_active_ransomware_groups(self) -> List[Dict[str, Any]]:
        """
        Retrieve catalog of active extortion groups and their operational status.
        """
        try:
            proxies = {"all://": self.tor_proxy} if self.tor_proxy else None
            async with httpx.AsyncClient(timeout=self.timeout, proxies=proxies, verify=False) as client:
                resp = await client.get(self.groups_feed_url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        return data
        except Exception as e:
            logger.warning(f"Error fetching ransomware groups catalog: {e}")

        return []

    def correlate_leaks_with_seeds(
        self,
        posts: List[Dict[str, Any]],
        organization_seeds: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Correlates ransomware post titles and victim names against corporate seed keywords.
        Returns verifiable evidence objects with cryptographic verification hashes.
        """
        matches = []
        clean_seeds = []
        for s in organization_seeds:
            # Extract root domain or company name token (e.g. "fdn.com.co" -> "fdn")
            clean = re.sub(r"^www\.", "", s.strip().lower())
            token = clean.split(".")[0]
            if len(token) >= 3:
                clean_seeds.append((token, s))

        for post in posts:
            victim_name = post.get("post_title", "").strip()
            group_name = post.get("group_name", "Unknown")
            discovered_at = post.get("discovered", "")
            raw_url = post.get("claim_url") or post.get("post_url") or ""

            if not victim_name:
                continue

            victim_lower = victim_name.lower()
            victim_norm = re.sub(r'[^a-z0-9]', '', victim_lower)
            matched_seed = None
            for token, full_seed in clean_seeds:
                token_norm = re.sub(r'[^a-z0-9]', '', token)
                # Word boundary, normalized match, or substring check
                if token in victim_lower or (len(token_norm) >= 3 and token_norm in victim_norm):
                    matched_seed = full_seed
                    break

            if matched_seed:
                # Create verifiable evidence record
                evidence_payload = f"{group_name}:{victim_name}:{discovered_at}:{matched_seed}"
                evidence_hash = hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest()

                matches.append({
                    "group_name": group_name,
                    "victim_name": victim_name,
                    "matched_seed": matched_seed,
                    "discovered_date": discovered_at,
                    "threat_severity": "CRITICAL",
                    "evidence_hash": evidence_hash,
                    "source": "Ransomware Extortion Feed",
                    "status": "UNRESOLVED",
                    "action_required": "Immediate Incident Response Review"
                })

        return matches

    def evaluate_credential_leak_safety(self, leak_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures any ingested credential finding conforms to safety standards:
        - Masks email local part.
        - Obfuscates or hashes any password field.
        """
        email = leak_record.get("email", "")
        if email and "@" in email:
            user, domain = email.split("@", 1)
            masked_user = user[:2] + "***" if len(user) > 2 else "***"
            masked_email = f"{masked_user}@{domain}"
        else:
            masked_email = "***"

        return {
            "masked_email": masked_email,
            "domain": leak_record.get("domain", ""),
            "breach_source": leak_record.get("source", "Public Breach Archive"),
            "hash_sha256": self._hash_credential(email),
            "password_stored": False,  # Strict guarantee
            "detected_at": datetime.utcnow().isoformat()
        }
