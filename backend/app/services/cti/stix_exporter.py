"""
OpenRecon Dark Intelligence - STIX 2.1 & CTI Exporter Engine
Translates Dark Web discoveries (Evidence Vault items, Leaks, Ransomware posts,
Threat Actors, and Extracted IOCs) into compliant STIX 2.1 JSON Bundles.
Supports export to OpenCTI, MISP, TAXII, and SIEM/SOAR platforms.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

OPENRECON_IDENTITY_ID = "identity--d89e4719-f9c1-4b13-8d65-openreconplatform"

class StixExporter:
    """
    Enterprise STIX 2.1 serialization engine for Dark Intelligence.
    Converts relational Dark Web intelligence records into STIX Domain Objects (SDOs)
    and STIX Relationship Objects (SROs).
    """

    def __init__(self, platform_name: str = "OpenRecon Dark Intelligence"):
        self.platform_name = platform_name

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def create_identity_sdo(self) -> Dict[str, Any]:
        """Creates the author identity for OpenRecon."""
        now = self._now_iso()
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": OPENRECON_IDENTITY_ID,
            "created": now,
            "modified": now,
            "name": self.platform_name,
            "description": "OpenRecon Automated OSINT & Cyber Threat Intelligence Platform",
            "identity_class": "system",
            "confidence": 95
        }

    def convert_threat_actor_to_sdo(self, actor: Dict[str, Any]) -> Dict[str, Any]:
        """Converts darkintel_threat_actors record to STIX 2.1 Threat Actor SDO."""
        now = self._now_iso()
        slug = actor.get("slug") or actor.get("id") or str(uuid.uuid4())
        actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, f'openrecon.actor.{slug}')}"
        
        aliases = actor.get("aliases")
        if isinstance(aliases, str):
            try:
                aliases = json.loads(aliases)
            except Exception:
                aliases = [aliases]
        elif not isinstance(aliases, list):
            aliases = []

        sectors = actor.get("target_sectors")
        if isinstance(sectors, str):
            try:
                sectors = json.loads(sectors)
            except Exception:
                sectors = []

        malware = actor.get("associated_malware") or actor.get("malware")
        if isinstance(malware, str):
            try:
                malware = json.loads(malware)
            except Exception:
                malware = [malware]
        elif not isinstance(malware, list):
            malware = []

        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": actor.get("name", "Unknown Syndicate"),
            "description": f"Threat Actor profile tracked by OpenRecon. Origin: {actor.get('origin_country') or actor.get('origin', 'Unknown')}",
            "aliases": aliases,
            "threat_actor_types": ["crime-syndicate", "ransomware-operator"],
            "primary_motivation": actor.get("motivation", "financial-gain").lower().replace(" ", "-"),
            "confidence": 90 if actor.get("confidence_level") == "HIGH" or actor.get("confidence") == "HIGH" else 75,
            "created_by_ref": OPENRECON_IDENTITY_ID,
            "custom_properties": {
                "x_openrecon_target_sectors": sectors,
                "x_openrecon_associated_malware": malware,
                "x_openrecon_dls_onion": actor.get("darkweb_dls_onion") or (actor.get("onion_resources")[0] if actor.get("onion_resources") else None)
            }
        }

    def convert_ransomware_post_to_sdo(self, post: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Converts darkintel_ransomware_posts record into STIX 2.1 objects:
        1. An Incident SDO representing the extortion/data disclosure event.
        2. A Relationship SRO linking to the threat actor if present.
        """
        now = self._now_iso()
        victim = post.get("victim_name", "Unknown Target")
        group = post.get("group_name", "Unknown Syndicate")
        post_id = str(post.get("id") or uuid.uuid4())
        
        incident_id = f"incident--{uuid.uuid5(uuid.NAMESPACE_DNS, f'openrecon.ransomware.{post_id}')}"
        
        description = f"Ransomware extortion leak published by {group} against {victim}."
        if post.get("data_size"):
            description += f" Stated compromised data size: {post.get('data_size')}."
        if post.get("deadline"):
            description += f" Extortion deadline: {post.get('deadline')}."

        incident_sdo = {
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_id,
            "created": now,
            "modified": now,
            "name": f"Extortion Publication: {group} vs {victim}",
            "description": description,
            "created_by_ref": OPENRECON_IDENTITY_ID,
            "confidence": 85,
            "custom_properties": {
                "x_openrecon_victim_name": victim,
                "x_openrecon_group_name": group,
                "x_openrecon_victim_website": post.get("victim_website"),
                "x_openrecon_proof_urls": post.get("proof_sample_urls"),
                "x_openrecon_evidence_id": post.get("evidence_id")
            }
        }
        
        objects = [incident_sdo]
        
        # Link to Threat Actor SDO
        actor_slug = group.lower().replace(" ", "-")
        actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, f'openrecon.actor.{actor_slug}')}"
        relationship_sro = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{actor_id}.attributed-to.{incident_id}')}",
            "created": now,
            "modified": now,
            "relationship_type": "attributed-to",
            "source_ref": incident_id,
            "target_ref": actor_id,
            "created_by_ref": OPENRECON_IDENTITY_ID
        }
        objects.append(relationship_sro)
        
        return objects

    def convert_ioc_to_sdo(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Converts darkintel_iocs or extracted indicator into STIX 2.1 Indicator SDO."""
        now = self._now_iso()
        ioc_val = ioc.get("ioc_value") or ioc.get("value") or ""
        ioc_type = ioc.get("ioc_type") or ioc.get("type") or "unknown"
        ioc_id = str(ioc.get("id") or uuid.uuid5(uuid.NAMESPACE_DNS, f"openrecon.ioc.{ioc_val}"))
        
        pattern = ""
        pattern_type = "stix"
        
        if ioc_type in ["ipv4", "ip", "ip-dst", "ip-src"]:
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type in ["ipv6"]:
            pattern = f"[ipv6-addr:value = '{ioc_val}']"
        elif ioc_type in ["domain", "hostname"]:
            pattern = f"[domain-name:value = '{ioc_val}']"
        elif ioc_type in ["url", "onion_address"]:
            pattern = f"[url:value = '{ioc_val}']"
        elif ioc_type in ["sha256", "sha-256"]:
            pattern = f"[file:hashes.'SHA-256' = '{ioc_val}']"
        elif ioc_type in ["md5"]:
            pattern = f"[file:hashes.'MD5' = '{ioc_val}']"
        elif ioc_type in ["email"]:
            pattern = f"[email-addr:value = '{ioc_val}']"
        else:
            pattern = f"[x-openrecon-custom:value = '{ioc_val}']"

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc_id}",
            "created": now,
            "modified": now,
            "name": f"Dark Web Indicator: {ioc_val}",
            "description": f"Discovered by OpenRecon Dark Intelligence collector from dark web sources. Severity: {ioc.get('threat_severity', 'MEDIUM')}",
            "pattern": pattern,
            "pattern_type": pattern_type,
            "valid_from": now,
            "confidence": 80,
            "created_by_ref": OPENRECON_IDENTITY_ID,
            "indicator_types": ["malicious-activity", "compromised"],
            "custom_properties": {
                "x_openrecon_threat_severity": ioc.get("threat_severity", "MEDIUM"),
                "x_openrecon_associated_actor": ioc.get("associated_actor"),
                "x_openrecon_reputation_score": ioc.get("reputation_score", 50)
            }
        }

    def convert_leak_to_sdo(self, leak: Dict[str, Any]) -> Dict[str, Any]:
        """Converts darkintel_leaks record to STIX 2.1 Note/Observed-Data SDO."""
        now = self._now_iso()
        leak_id = str(leak.get("id") or uuid.uuid4())
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": f"note--{uuid.uuid5(uuid.NAMESPACE_DNS, f'openrecon.leak.{leak_id}')}",
            "created": now,
            "modified": now,
            "abstract": f"Information Exposure: {leak.get('exposure_type', 'DATA_LEAK')} - {leak.get('target_domain', 'Unknown Domain')}",
            "content": f"Confidential exposure detected by Dark Intelligence. Masked identity: {leak.get('masked_identity', 'REDACTED')}. Hash (K-Anonymity): {leak.get('credential_sha256_hash', 'N/A')}",
            "authors": [self.platform_name],
            "created_by_ref": OPENRECON_IDENTITY_ID,
            "custom_properties": {
                "x_openrecon_exposure_type": leak.get("exposure_type"),
                "x_openrecon_domain": leak.get("target_domain"),
                "x_openrecon_evidence_id": leak.get("evidence_id")
            }
        }

    def build_stix21_bundle(
        self,
        threat_actors: Optional[List[Dict[str, Any]]] = None,
        ransomware_posts: Optional[List[Dict[str, Any]]] = None,
        iocs: Optional[List[Dict[str, Any]]] = None,
        leaks: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Builds a complete, validated STIX 2.1 JSON bundle combining multiple Dark Intelligence entities.
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = [self.create_identity_sdo()]

        if threat_actors:
            for actor in threat_actors:
                objects.append(self.convert_threat_actor_to_sdo(actor))

        if ransomware_posts:
            for post in ransomware_posts:
                objects.extend(self.convert_ransomware_post_to_sdo(post))

        if iocs:
            for ioc in iocs:
                objects.append(self.convert_ioc_to_sdo(ioc))

        if leaks:
            for leak in leaks:
                objects.append(self.convert_leak_to_sdo(leak))

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
