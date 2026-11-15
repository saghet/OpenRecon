"""
STIX 2.1 Import/Export, Deduplication, TLP Markings & TAXII 2.1 Client for OpenRecon 3.0.
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.tls_config import get_httpx_verify

TLP_MARKING_DEFINITIONS = {
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


class STIX21TaxiiService:
    """Handles STIX 2.1 bundle import/export with TLP, expiration, deduplication, and TAXII 2.1."""

    @staticmethod
    def build_stix21_bundle(
        indicators: List[Dict[str, Any]],
        tlp: str = "TLP:AMBER",
        default_ttl_days: int = 30,
    ) -> Dict[str, Any]:
        tlp_upper = tlp.upper() if tlp.upper() in TLP_MARKING_DEFINITIONS else "TLP:AMBER"
        tlp_ref = TLP_MARKING_DEFINITIONS[tlp_upper]
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat().replace("+00:00", "Z")
        valid_until = (now + timedelta(days=default_ttl_days)).isoformat().replace("+00:00", "Z")

        identity_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "openrecon.platform")
        identity_id = f"identity--{identity_uuid}"
        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "name": "OpenRecon 3.0 CTI Platform",
                "identity_class": "system",
                "created": now_iso,
                "modified": now_iso,
            }
        ]

        seen_patterns = set()
        for ind in indicators:
            pattern = ind.get("pattern")
            if not pattern:
                ioc_type = ind.get("type", "domain-name")
                val = ind.get("value", "")
                if not val:
                    continue
                pattern = f"[{ioc_type}:value = '{val}']"

            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)

            det_uuid = uuid.UUID(hashlib.md5(pattern.encode("utf-8")).hexdigest())
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{det_uuid}",
                    "created": now_iso,
                    "modified": now_iso,
                    "name": ind.get("name") or f"IoC: {ind.get('value', pattern)}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ind.get("valid_from") or now_iso,
                    "valid_until": ind.get("valid_until") or valid_until,
                    "confidence": max(0, min(100, int(ind.get("confidence", 75)))),
                    "created_by_ref": identity_id,
                    "object_marking_refs": [tlp_ref],
                    "labels": [ind.get("source", "openrecon"), tlp_upper.lower()],
                }
            )

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    @staticmethod
    def parse_and_deduplicate_stix_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Imports and deduplicates STIX 2.1 objects, extracting TLP, confidence, and expiration."""
        if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
            raise ValueError("Invalid STIX 2.1 bundle: missing 'type=bundle' or 'objects' list.")

        marking_lookup = {v: k for k, v in TLP_MARKING_DEFINITIONS.items()}
        dedup_map: Dict[str, Dict[str, Any]] = {}
        skipped = 0

        for obj in bundle["objects"]:
            obj_type = obj.get("type")
            if obj_type not in ("indicator", "vulnerability", "threat-actor", "intrusion-set"):
                skipped += 1
                continue

            key = f"{obj_type}:{obj.get('pattern') or obj.get('name') or obj.get('id')}"
            markings = [marking_lookup[m] for m in obj.get("object_marking_refs", []) if m in marking_lookup]
            tlp = markings[0] if markings else "TLP:AMBER"

            if key not in dedup_map:
                dedup_map[key] = {
                    "stix_id": obj.get("id"),
                    "type": obj_type,
                    "name": obj.get("name"),
                    "pattern": obj.get("pattern"),
                    "confidence": obj.get("confidence", 50),
                    "valid_from": obj.get("valid_from"),
                    "valid_until": obj.get("valid_until"),
                    "tlp": tlp,
                }
            else:
                # Keep highest confidence on duplicate
                if obj.get("confidence", 0) > dedup_map[key]["confidence"]:
                    dedup_map[key]["confidence"] = obj.get("confidence", 0)

        return {
            "imported_count": len(dedup_map),
            "skipped_count": skipped,
            "items": list(dedup_map.values()),
        }

    @staticmethod
    async def fetch_taxii21_objects(
        collection_objects_url: str,
        api_token: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """Queries a TAXII 2.1 collection objects endpoint using strict TLS verification."""
        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": "OpenRecon-TAXII21/3.0",
        }
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        async with httpx.AsyncClient(timeout=timeout, verify=get_httpx_verify()) as client:
            resp = await client.get(collection_objects_url, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"TAXII 2.1 endpoint returned HTTP {resp.status_code}")
            data = resp.json()
            objects = data.get("objects", [])
            return STIX21TaxiiService.parse_and_deduplicate_stix_bundle(
                {"type": "bundle", "objects": objects}
            )
