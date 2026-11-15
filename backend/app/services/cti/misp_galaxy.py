"""
MISP Galaxy Local Loader, Versioned Index & CorrelationGraphEngine Integration.
Source: https://github.com/MISP/misp-galaxy (CC0-1.0 / BSD-2-Clause).
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.tls_config import get_httpx_verify
from app.services.correlation.graph_engine import CorrelationGraphEngine

logger = logging.getLogger(__name__)

_DEFAULT_GALAXY_URLS = {
    "threat-actor": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "ransomware": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json",
    "mitre-attack-pattern": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json",
}


class MISPGalaxyService:
    """
    Downloads, validates, versions, deduplicates, and indexes MISP Galaxy clusters
    locally, and enriches CorrelationGraphEngine with evidence-backed edges.
    """

    def __init__(self, cache_dir: Optional[str] = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "misp_galaxy"))
        self.cache_dir = cache_dir or base_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.index: Dict[str, Dict[str, Any]] = {}
        self.manifest_path = os.path.join(self.cache_dir, "manifest.json")

    @staticmethod
    def validate_cluster_payload(payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise ValueError("MISP Galaxy payload must be a JSON object.")
        if "values" not in payload or not isinstance(payload["values"], list):
            raise ValueError("MISP Galaxy payload missing 'values' list.")

    def ingest_cluster_payload(self, cluster_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.validate_cluster_payload(payload)
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        cluster_file = os.path.join(self.cache_dir, f"{cluster_name}.json")
        with open(cluster_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        manifest = self._load_manifest()
        prev_sha = (manifest.get("clusters", {}).get(cluster_name) or {}).get("sha256")
        manifest.setdefault("clusters", {})[cluster_name] = {
            "sha256": sha256,
            "version": payload.get("version", 1),
            "uuid": payload.get("uuid"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(payload.get("values", [])),
            "changed": prev_sha != sha256,
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        self.rebuild_index()
        return manifest["clusters"][cluster_name]

    def _load_manifest(self) -> Dict[str, Any]:
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"clusters": {}}

    def rebuild_index(self) -> int:
        """Rebuilds deduplicated lookup index across all locally cached galaxy files."""
        new_index: Dict[str, Dict[str, Any]] = {}
        for fname in sorted(os.listdir(self.cache_dir)):
            if not fname.endswith(".json") or fname == "manifest.json":
                continue
            cluster_name = fname[:-5]
            fpath = os.path.join(self.cache_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                self.validate_cluster_payload(payload)
            except Exception as e:
                logger.warning(f"Skipping invalid MISP Galaxy cache file {fname}: {e}")
                continue

            for item in payload.get("values", []):
                val = str(item.get("value", "")).strip()
                if not val:
                    continue
                meta = item.get("meta") or {}
                synonyms = [str(s).strip() for s in (meta.get("synonyms") or []) if s]
                entry = {
                    "uuid": item.get("uuid"),
                    "value": val,
                    "cluster": cluster_name,
                    "description": (item.get("description") or "")[:300],
                    "synonyms": synonyms,
                    "refs": (meta.get("refs") or [])[:5],
                    "country": meta.get("country"),
                }
                for key in [val.lower()] + [s.lower() for s in synonyms]:
                    if key not in new_index:
                        new_index[key] = entry
        self.index = new_index
        return len(self.index)

    async def sync_official_clusters(self, clusters: Optional[List[str]] = None, timeout: float = 15.0) -> Dict[str, Any]:
        targets = clusters or list(_DEFAULT_GALAXY_URLS.keys())
        summary: Dict[str, Any] = {}
        async with httpx.AsyncClient(timeout=timeout, verify=get_httpx_verify()) as client:
            for name in targets:
                url = _DEFAULT_GALAXY_URLS.get(name)
                if not url:
                    continue
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        summary[name] = self.ingest_cluster_payload(name, resp.json())
                    else:
                        summary[name] = {"error": f"HTTP {resp.status_code}"}
                except Exception as exc:
                    summary[name] = {"error": str(exc)}
        return summary

    def lookup(self, name: str) -> Optional[Dict[str, Any]]:
        if not self.index:
            self.rebuild_index()
        return self.index.get(name.strip().lower())

    def enrich_correlation_graph(
        self,
        graph: CorrelationGraphEngine,
        actor_or_threat_names: List[str],
        target_node_id: Optional[str] = None,
    ) -> int:
        """
        Enriches CorrelationGraphEngine only when an exact MISP Galaxy cluster match exists.
        Every edge includes explicit source, evidence (cluster UUID), and confidence.
        """
        if not self.index:
            self.rebuild_index()
        added = 0
        for raw_name in actor_or_threat_names:
            match = self.lookup(raw_name)
            if not match:
                continue
            actor_id = f"actor:{match['value'].lower()}"
            graph.add_node(
                actor_id,
                match["value"],
                "ACTOR",
                metadata={"cluster": match["cluster"], "uuid": match["uuid"], "country": match.get("country")},
            )
            if target_node_id and target_node_id in graph.nodes:
                graph.add_edge(
                    actor_id,
                    target_node_id,
                    relationship="MISP_GALAXY_ATTRIBUTED_TO",
                    confidence=90,
                    source="MISP-Galaxy",
                    is_inferred=False,
                    evidence=f"cluster={match['cluster']} uuid={match['uuid']} value={match['value']}",
                )
                added += 1
        return added
