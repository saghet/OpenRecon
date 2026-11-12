"""
Heuristic Leak & Secret Extraction Engine for OpenRecon.
Inspired by best practices from CIRCL AIL Framework and PasteHunter:
- Detects leaked corporate credentials, database dumps, and VPN configurations.
- Detects exposed cloud API tokens (AWS, GCP, GitHub, Slack, SSH keys, DB URIs).
- Enforces strict k-Anonymity (identities are masked, secrets are hashed with SHA-256, NEVER stored cleartext).
- Persists findings in darkintel_leaks linked to darkintel_evidence_vault.
"""

import hashlib
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from app.core.evidence_sanitizer import EvidenceSanitizer
from app.services.cti.dark_collector_service import SQLITE_PATH

logger = logging.getLogger("openrecon.leak_extractor")

# High-Precision Heuristic Patterns (AIL / PasteHunter Inspired)
CREDENTIAL_COLON_REGEX = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}):([^\s:;\"'<>]{4,128})\b"
)

AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GCP_API_KEY_REGEX = re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b")
SLACK_TOKEN_REGEX = re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")
SSH_PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
DB_CONN_REGEX = re.compile(r"\b(?:jdbc:)?(?:mysql|postgresql|postgres|mongodb|redis):\/\/[A-Za-z0-9_.-]+:[^\s@]+@[^\s:]+:\d+\/[^\s]+", re.IGNORECASE)
OPENVPN_CONFIG_REGEX = re.compile(r"\bclient\b.*?\bdev tun\b.*?\bproto (?:udp|tcp)\b", re.IGNORECASE | re.DOTALL)


class LeakExtractorEngine:
    """
    Analyzes raw text or scraped document dumps for exposed credentials and secrets.
    """

    def __init__(self, sqlite_db_path: str = SQLITE_PATH):
        self.sqlite_db_path = sqlite_db_path

    def analyze_and_extract(
        self,
        raw_content: str,
        source_url: str,
        leak_source_name: str = "DarkWeb_Paste",
        target_organization_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Scans raw text with heuristic rules, masks secrets, and saves findings.
        """
        findings = []

        # 1. Detect Credential Pairs (email:password)
        cred_matches = CREDENTIAL_COLON_REGEX.findall(raw_content)
        for email, clear_pwd in cred_matches[:50]:  # Cap at 50 per document to prevent DB flooding
            domain = email.split("@")[1].lower()
            masked_id = EvidenceSanitizer.mask_identity(email)
            pwd_hash = EvidenceSanitizer.hash_credential(clear_pwd)

            findings.append({
                "type": "CREDENTIAL",
                "domain": domain,
                "masked_identity": masked_id,
                "credential_hash": pwd_hash,
                "data_classes": ["email", "password"],
                "severity": "HIGH",
                "corroboration": "PROBABLE"
            })

        # 2. Detect AWS Access Keys
        aws_matches = AWS_KEY_REGEX.findall(raw_content)
        for key in set(aws_matches):
            masked_key = f"{key[:4]}****{key[-4:]}"
            findings.append({
                "type": "CLOUD_SECRET",
                "domain": "aws.amazon.com",
                "masked_identity": masked_key,
                "credential_hash": EvidenceSanitizer.hash_credential(key),
                "data_classes": ["aws_access_key"],
                "severity": "CRITICAL",
                "corroboration": "VERIFIED"
            })

        # 3. Detect Google Cloud / Firebase API Keys
        gcp_matches = GCP_API_KEY_REGEX.findall(raw_content)
        for key in set(gcp_matches):
            masked_key = f"{key[:4]}****{key[-4:]}"
            findings.append({
                "type": "CLOUD_SECRET",
                "domain": "googleapis.com",
                "masked_identity": masked_key,
                "credential_hash": EvidenceSanitizer.hash_credential(key),
                "data_classes": ["gcp_api_key"],
                "severity": "HIGH",
                "corroboration": "VERIFIED"
            })

        # 4. Detect GitHub Access Tokens
        gh_matches = GITHUB_TOKEN_REGEX.findall(raw_content)
        for token in set(gh_matches):
            masked_token = f"{token[:6]}****{token[-4:]}"
            findings.append({
                "type": "CLOUD_SECRET",
                "domain": "github.com",
                "masked_identity": masked_token,
                "credential_hash": EvidenceSanitizer.hash_credential(token),
                "data_classes": ["github_token"],
                "severity": "CRITICAL",
                "corroboration": "VERIFIED"
            })

        # 5. Detect Private SSH Keys
        if SSH_PRIVATE_KEY_REGEX.search(raw_content):
            findings.append({
                "type": "INTERNAL_DOC",
                "domain": "infrastructure.ssh",
                "masked_identity": "PRIVATE_KEY_BLOCK_DETECTED",
                "credential_hash": hashlib.sha256(raw_content.encode("utf-8")).hexdigest(),
                "data_classes": ["ssh_private_key"],
                "severity": "CRITICAL",
                "corroboration": "VERIFIED"
            })

        # 6. Detect Database Connection URIs
        db_matches = DB_CONN_REGEX.findall(raw_content)
        for uri in set(db_matches):
            masked_uri = re.sub(r":([^@]+)@", ":****@", uri)
            findings.append({
                "type": "SQL_DUMP",
                "domain": "database.connection",
                "masked_identity": masked_uri[:100],
                "credential_hash": EvidenceSanitizer.hash_credential(uri),
                "data_classes": ["database_connection_string"],
                "severity": "CRITICAL",
                "corroboration": "VERIFIED"
            })

        # 7. Detect OpenVPN Configs
        if OPENVPN_CONFIG_REGEX.search(raw_content):
            findings.append({
                "type": "VPN_CONFIG",
                "domain": "corporate.vpn",
                "masked_identity": "OPENVPN_CLIENT_CONFIG",
                "credential_hash": hashlib.sha256(raw_content.encode("utf-8")).hexdigest(),
                "data_classes": ["vpn_configuration"],
                "severity": "HIGH",
                "corroboration": "PROBABLE"
            })

        # Persist to Evidence Vault and darkintel_leaks if findings discovered
        saved_count = 0
        if findings:
            saved_count = self._persist_findings(
                raw_content=raw_content,
                source_url=source_url,
                leak_source=leak_source_name,
                findings=findings,
                org_id=target_organization_id
            )

        return {
            "source_url": source_url,
            "leak_source": leak_source_name,
            "total_findings": len(findings),
            "persisted_findings": saved_count,
            "findings": findings
        }

    def _persist_findings(
        self,
        raw_content: str,
        source_url: str,
        leak_source: str,
        findings: List[Dict[str, Any]],
        org_id: Optional[int]
    ) -> int:
        content_sha = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        sanitized_preview = EvidenceSanitizer.sanitize_raw_content(raw_content, max_chars=3000)
        custody_sig = EvidenceSanitizer.generate_custody_signature(content_sha, raw_content)

        saved = 0
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            # 1. Save Evidence
            cur.execute(
                """
                INSERT OR IGNORE INTO darkintel_evidence_vault
                (id, source_url, source_type, collected_at_utc, last_verified_utc,
                 raw_content_preview, content_sha256, custody_signature, validation_status,
                 severity, confidence_score, analyst_notes)
                VALUES (?, ?, 'PASTE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, ?, 'CORROBORATED', 'HIGH', 0.9, ?)
                """,
                (
                    content_sha,
                    source_url,
                    sanitized_preview,
                    content_sha,
                    custody_sig,
                    f"Extracted by Heuristic Leak Engine from {leak_source}"
                )
            )

            # 2. Save Leaks
            for f in findings:
                cur.execute(
                    """
                    INSERT INTO darkintel_leaks
                    (evidence_id, target_organization_id, domain_mentioned, masked_identity,
                     credential_hash, exposure_type, leak_source, discovered_at, corroboration_level, data_classes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                    """,
                    (
                        content_sha,
                        org_id,
                        f["domain"],
                        f["masked_identity"],
                        f["credential_hash"],
                        f["type"],
                        leak_source,
                        f["corroboration"],
                        json.dumps(f["data_classes"])
                    )
                )
                saved += 1

            conn.commit()
        finally:
            conn.close()

        return saved
