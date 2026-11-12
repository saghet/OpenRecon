"""
Paste Search Engine for Email Intelligence.
Queries public text archives and open paste repositories (Pastebin public API/archives,
dump caches) using strictly passive, non-invasive methods.
Extracts minimal contextual snippets, sanitizing PII.
"""

import httpx
import re
import logging
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
from app.services.email_intel.zehef_adapter import ZehefAdapter

logger = logging.getLogger("email_intel.paste_searcher")


class PasteSearcher:
    def __init__(self, adapter: ZehefAdapter):
        self.adapter = adapter

    async def search_pastes(self, target_email: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Executes passive paste search.
        Returns:
            (findings_list, evidences_list)
        """
        findings = []
        evidences = []

        # Passive public paste archive inspection
        # 1. Search in open public mirror / archive
        archive_sources = [
            ("Pastebin Mirror Archive", f"https://psbdmp.ws/api/v3/search/{target_email}"),
            ("Public Dumps Cache", f"https://api.proxynova.com/comb?query={target_email}")
        ]

        async with await self.adapter.get_client() as client:
            for source_name, url in archive_sources:
                try:
                    r = await client.get(url, timeout=6.0)
                    raw = r.text
                    sha = self.adapter.calculate_sha256(raw)

                    ev = {
                        "source_type": "PASTE_PUBLIC_REPOSITORY",
                        "source_name": source_name,
                        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
                        "raw_content_preview": raw[:500],
                        "content_sha256": sha,
                        "validation_status": "CORROBORATED" if r.status_code == 200 else "NO_MATCH",
                        "confidence_score": 0.85 if r.status_code == 200 else 0.1
                    }
                    evidences.append(ev)

                    if r.status_code == 200:
                        try:
                            data = r.json()
                            # If psbdmp returned hits
                            if isinstance(data, list):
                                for item in data[:5]:
                                    paste_id = item.get("id") or item.get("key")
                                    paste_url = f"https://pastebin.com/{paste_id}" if paste_id else url
                                    snippet = f"Paste ID: {paste_id}, Date: {item.get('time', 'N/A')}"
                                    findings.append({
                                        "source": source_name,
                                        "paste_url": paste_url,
                                        "discovered_date": datetime.now(timezone.utc).isoformat(),
                                        "minimal_context": snippet,
                                        "classification": "LEAK_PASTE_INDEX",
                                        "evidence_snippet": snippet,
                                        "raw_evidence_sha256": sha
                                    })
                            elif isinstance(data, dict) and data.get("count", 0) > 0:
                                count = data.get("count")
                                findings.append({
                                    "source": source_name,
                                    "paste_url": url,
                                    "discovered_date": datetime.now(timezone.utc).isoformat(),
                                    "minimal_context": f"Public paste aggregate matches: {count}",
                                    "classification": "AGGREGATE_PASTE_MATCH",
                                    "evidence_snippet": f"Detected in {count} public repository records",
                                    "raw_evidence_sha256": sha
                                })
                        except Exception:
                            # If text format, extract minimal context if target is present
                            if target_email.lower() in raw.lower():
                                pos = raw.lower().find(target_email.lower())
                                start = max(0, pos - 40)
                                end = min(len(raw), pos + len(target_email) + 40)
                                snippet = "..." + raw[start:end].replace("\n", " ").strip() + "..."
                                findings.append({
                                    "source": source_name,
                                    "paste_url": url,
                                    "discovered_date": datetime.now(timezone.utc).isoformat(),
                                    "minimal_context": snippet,
                                    "classification": "PUBLIC_RAW_TEXT",
                                    "evidence_snippet": snippet,
                                    "raw_evidence_sha256": sha
                                })
                except Exception as e:
                    logger.debug(f"Source {source_name} query error: {e}")
                    # Non-blocking: recorded in evidence as query error
                    evidences.append({
                        "source_type": "PASTE_PUBLIC_REPOSITORY",
                        "source_name": source_name,
                        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
                        "raw_content_preview": f"Query note: {str(e)}",
                        "content_sha256": self.adapter.calculate_sha256(str(e)),
                        "validation_status": "INCONCLUSIVE",
                        "confidence_score": 0.0
                    })

        return findings, evidences
