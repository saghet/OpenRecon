"""
GitHub Secret & Repository Intelligence Service for OpenRecon 3.0.
- Uses GitHub REST API with strict TLS verification (get_httpx_verify()).
- Supports decoupled CLI execution of gitleaks / trufflehog when installed.
- Classifies findings into ACTIVE, REVOKED, POTENTIAL, UNVERIFIED.
- NEVER authenticates with or tests discovered credentials.
- NEVER stores cleartext secrets (always redacted + SHA-256 fingerprinted).
"""

import hashlib
import json
import logging
import re
import shutil
import subprocess
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

from app.core.evidence_sanitizer import EvidenceSanitizer
from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import get_httpx_verify
from app.services.connectors.base import BaseConnector, ConnectorConfig

logger = logging.getLogger(__name__)

_SECRET_SIGNATURES = [
    ("GITHUB_PAT", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("OPENAI_OR_DEEPSEEK_KEY", re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b")),
    ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
]


class SecretLifecycleState(str, Enum):
    POTENTIAL = "POTENTIAL"
    UNVERIFIED = "UNVERIFIED"
    REVOKED = "REVOKED"
    ACTIVE = "ACTIVE"


class GitHubIntelConnector(BaseConnector):
    """
    Passive GitHub public repository & commit secret-exposure intelligence connector.
    """

    def __init__(self, github_token: Optional[str] = None, timeout: float = 10.0):
        super().__init__(
            ConnectorConfig(
                connector_id="github-intel-v1",
                name="GitHub Secret & Repo Intelligence",
                version="1.0.0",
                source="GitHub REST API / Decoupled Scanners",
                timeout=timeout,
                rate_limit_rps=2.0,
            )
        )
        self.github_token = github_token or ""
        self.has_gitleaks = shutil.which("gitleaks") is not None
        self.has_trufflehog = shutil.which("trufflehog") is not None

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "OpenRecon-GitHubIntel/3.0",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    async def _fetch_raw(self, target: str, **kwargs) -> Dict[str, Any]:
        ks = SecurityGovernanceGuard.is_kill_switch_active()
        if ks.get("active"):
            raise RuntimeError(f"Emergency Kill Switch ACTIVE: {ks.get('reason')}")

        org_or_user = target.strip()
        if not re.match(r"^[a-zA-Z0-9-]{1,39}$", org_or_user):
            raise ValueError(f"Invalid GitHub organization/user identifier: '{org_or_user}'")

        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            verify=get_httpx_verify(),
            follow_redirects=False,
        ) as client:
            repos_resp = await client.get(
                f"https://api.github.com/users/{org_or_user}/repos",
                params={"per_page": 20, "sort": "updated"},
                headers=self._headers(),
            )
            if repos_resp.status_code != 200:
                raise RuntimeError(f"GitHub API HTTP {repos_resp.status_code}")
            repos = repos_resp.json()

            commit_samples: List[Dict[str, Any]] = []
            for repo in repos[:5]:
                full_name = repo.get("full_name")
                if not full_name:
                    continue
                c_resp = await client.get(
                    f"https://api.github.com/repos/{full_name}/commits",
                    params={"per_page": 5},
                    headers=self._headers(),
                )
                if c_resp.status_code == 200:
                    for c in c_resp.json():
                        commit_samples.append(
                            {
                                "repo": full_name,
                                "sha": c.get("sha", ""),
                                "url": c.get("html_url", ""),
                                "message": (c.get("commit", {}) or {}).get("message", ""),
                            }
                        )
            return {"org": org_or_user, "repos": repos, "commits": commit_samples}

    def scan_text_for_secret_indicators(self, text: str, repo: str, ref: str) -> List[Dict[str, Any]]:
        """
        Detects secret patterns in commit/file text without ever storing or using the secret.
        """
        findings: List[Dict[str, Any]] = []
        if not text:
            return findings
        lowered = text.lower()
        is_revoked_hint = any(w in lowered for w in ("revoked", "rotated", "expired", "example", "dummy", "test_key"))

        for rule_name, pattern in _SECRET_SIGNATURES:
            for match in pattern.finditer(text):
                raw_secret = match.group(0)
                fingerprint = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
                state = SecretLifecycleState.REVOKED if is_revoked_hint else SecretLifecycleState.POTENTIAL
                findings.append(
                    {
                        "repo": repo,
                        "reference": ref,
                        "rule": rule_name,
                        "lifecycle_state": state.value,
                        "secret_sha256": fingerprint,
                        "redacted_preview": EvidenceSanitizer.redact_secrets_in_text(text[:240]),
                        "active_usage_attempted": False,
                    }
                )
        return findings

    def normalize(self, raw_data: Any, target: str) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for c in raw_data.get("commits", []):
            hits = self.scan_text_for_secret_indicators(
                c.get("message", ""),
                repo=c.get("repo", ""),
                ref=c.get("sha", ""),
            )
            normalized.extend(hits)
        return normalized

    @staticmethod
    def run_gitleaks_cli(repo_path: str) -> Dict[str, Any]:
        """Decoupled CLI wrapper for gitleaks (MIT) when installed locally."""
        if not shutil.which("gitleaks"):
            return {"available": False, "findings": [], "reason": "gitleaks binary not installed"}
        proc = subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--no-banner", "--report-format", "json", "--report-path", "-"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw_out = proc.stdout.strip()
        if not raw_out:
            return {"available": True, "findings": []}
        try:
            items = json.loads(raw_out)
        except json.JSONDecodeError:
            return {"available": True, "findings": [], "error": "Invalid JSON from gitleaks"}

        sanitized = []
        for item in items:
            secret_val = str(item.get("Secret") or "")
            sanitized.append(
                {
                    "rule": item.get("RuleID"),
                    "file": item.get("File"),
                    "commit": item.get("Commit"),
                    "lifecycle_state": SecretLifecycleState.UNVERIFIED.value,
                    "secret_sha256": hashlib.sha256(secret_val.encode("utf-8")).hexdigest() if secret_val else None,
                    "active_usage_attempted": False,
                }
            )
        return {"available": True, "findings": sanitized}
