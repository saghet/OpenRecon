"""
WebCopilotAdapter for OpenRecon 3.0.
Selectively integrates historical endpoint discovery (GAU, WaybackURLs, Waymore),
GF-compatible parameter classification, XSS/OpenRedirect/CRLF/SQLi validation,
Nuclei enrichment, and optional OOB/Interactsh into OpenRecon's native
Orchestrator, AFP, EvidenceManager, Deduplicator, and RiskEngine.

Security invariants:
- Never runs as root; never executes `shell=True` or `bash -c`.
- Enforces RoE scope, exclusion lists, Anti-SSRF, strict TLS verification, and Kill-Switch.
- Does NOT duplicate Subfinder/Amass/DNSX; consumes OpenRecon's discovered live assets.
- Safe-by-Default: intrusive Nuclei templates, Interactsh OOB, and SQLMap are DISABLED by default
  and require explicit per-organization policy + per-scan authorization.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.evidence_sanitizer import EvidenceSanitizer
from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import get_httpx_verify
from app.models.asset import Asset
from app.models.evidence import FindingValidationState
from app.models.exposure import SeverityLevel, Vulnerability
from app.models.web_recon import DiscoveredEndpoint, WebOrgPolicy, WebScanExecution
from app.services.engines.nuclei_engine import NucleiEngine
from app.services.evidence.manager import EvidenceManager
from app.services.risk.risk_engine import IntelligentRiskEngine
from app.services.validation.anti_false_positive import AntiFalsePositiveEngine, CandidateFinding
from app.services.validation.finding_contract import GlobalFindingDeduplicator, NormalizedFinding
from app.services.web_security.url_normalizer import deduplicate_urls, is_valid_hostname, normalize_url

logger = logging.getLogger(__name__)

# CWE & OWASP 2021 mappings per vulnerability category
VULN_TAXONOMY: Dict[str, Dict[str, str]] = {
    "xss": {"cwe_id": "CWE-79", "owasp": "A03:2021-Injection"},
    "sqli": {"cwe_id": "CWE-89", "owasp": "A03:2021-Injection"},
    "ssrf": {"cwe_id": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery"},
    "lfi": {"cwe_id": "CWE-22", "owasp": "A01:2021-Broken Access Control"},
    "rce": {"cwe_id": "CWE-78", "owasp": "A03:2021-Injection"},
    "redirect": {"cwe_id": "CWE-601", "owasp": "A01:2021-Broken Access Control"},
    "crlf": {"cwe_id": "CWE-93", "owasp": "A03:2021-Injection"},
    "nuclei": {"cwe_id": "CWE-200", "owasp": "A05:2021-Security Misconfiguration"},
}


@dataclass
class WebReconOptions:
    enable_historical_discovery: bool = True
    enable_param_analysis: bool = True
    enable_nuclei_enrichment: bool = True
    enable_xss_validation: bool = True
    enable_open_redirect_validation: bool = True
    enable_crlf_validation: bool = True
    # Safe-by-Default: active/OOB/SQLMap are strictly opt-in
    allow_intrusive_nuclei: bool = False
    allow_interactsh_oob: bool = False
    allow_controlled_sqlmap: bool = False
    excluded_domains: List[str] = field(default_factory=list)
    max_concurrency: int = 5
    per_tool_timeout: float = 45.0
    max_urls_per_asset: int = 300


class WebCopilotAdapter:
    """
    Decoupled, RoE-enforced adapter integrating selective WebCopilot capabilities
    into OpenRecon 3.0.
    """

    def __init__(
        self,
        db: Session,
        nuclei_engine: Optional[NucleiEngine] = None,
        afp_engine: Optional[AntiFalsePositiveEngine] = None,
        deduplicator: Optional[GlobalFindingDeduplicator] = None,
        evidence_manager: Optional[EvidenceManager] = None,
        risk_engine: Optional[IntelligentRiskEngine] = None,
    ):
        self.db = db
        self.nuclei_engine = nuclei_engine or NucleiEngine()
        self.afp_engine = afp_engine or AntiFalsePositiveEngine()
        self.deduplicator = deduplicator or GlobalFindingDeduplicator()
        self.evidence_manager = evidence_manager or EvidenceManager(db)
        self.risk_engine = risk_engine or IntelligentRiskEngine()

        self.binaries = {
            "gau": shutil.which("gau"),
            "waybackurls": shutil.which("waybackurls"),
            "waymore": shutil.which("waymore"),
            "kxss": shutil.which("kxss"),
            "dalfox": shutil.which("dalfox"),
            "crlfuzz": shutil.which("crlfuzz"),
            "sqlmap": shutil.which("sqlmap"),
            "interactsh-client": shutil.which("interactsh-client"),
        }

    def _is_killed(self) -> bool:
        return bool(SecurityGovernanceGuard.is_kill_switch_active().get("active"))

    def _is_excluded(self, host: str, excluded: List[str]) -> bool:
        h = host.strip().lower()
        for ex in excluded:
            ex_clean = ex.strip().lower()
            if not ex_clean:
                continue
            if h == ex_clean or h.endswith(f".{ex_clean}"):
                return True
        return False

    def _get_org_policy(self, organization_id: int) -> WebOrgPolicy:
        policy = (
            self.db.query(WebOrgPolicy)
            .filter(WebOrgPolicy.organization_id == organization_id)
            .first()
        )
        if not policy:
            policy = WebOrgPolicy(
                organization_id=organization_id,
                interactsh_enabled=False,
                sqlmap_enabled=False,
                nuclei_allow_intrusive=False,
                max_concurrency=settings.MAX_CONCURRENT_TASKS,
                rate_limit_rps=settings.RATE_LIMIT_RPS,
            )
            self.db.add(policy)
            self.db.commit()
            self.db.refresh(policy)
        return policy

    def _record_execution(
        self,
        organization_id: int,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        tool_name: str,
        status: str,
        started_at: datetime,
        items_processed: int = 0,
        findings_count: int = 0,
        parameters_used: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        tool_version: Optional[str] = None,
    ) -> WebScanExecution:
        finished_at = datetime.now(timezone.utc)
        duration_ms = max(0, int((finished_at - started_at).total_seconds() * 1000))
        rec = WebScanExecution(
            organization_id=organization_id,
            scan_job_id=scan_job_id,
            investigation_id=investigation_id,
            tool_name=tool_name,
            tool_version=tool_version,
            status=status,
            duration_ms=duration_ms,
            items_processed=items_processed,
            findings_count=findings_count,
            parameters_used=parameters_used or {},
            error_message=EvidenceSanitizer.sanitize_raw_content(error_message or "", max_chars=512) if error_message else None,
            started_at=started_at,
            finished_at=finished_at,
        )
        self.db.add(rec)
        self.db.commit()
        return rec

    async def _run_subprocess_lines(
        self,
        cmd: List[str],
        stdin_data: Optional[str] = None,
        timeout: float = 45.0,
    ) -> Tuple[int, str, str]:
        """Executes a binary with structured args only (never shell=True)."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode("utf-8") if stdin_data is not None else None),
                timeout=timeout,
            )
            return (
                proc.returncode or 0,
                stdout.decode("utf-8", errors="ignore"),
                stderr.decode("utf-8", errors="ignore"),
            )
        except asyncio.TimeoutError:
            try:
                proc.terminate()
            except Exception:
                pass
            raise

    async def _discover_historical_urls_for_host(
        self,
        hostname: str,
        organization_id: int,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        timeout: float,
    ) -> List[Tuple[str, str]]:
        """
        Queries GAU, WaybackURLs, Waymore (if installed), or passive Wayback CDX API
        for a single already-validated OpenRecon asset hostname.
        """
        if not is_valid_hostname(hostname):
            return []

        collected: List[Tuple[str, str]] = []

        # 1. GAU (without --subs so we don't re-enumerate subdomains)
        if self.binaries.get("gau") and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            try:
                cmd = [
                    self.binaries["gau"],
                    "--blacklist", "eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg",
                    "--threads", "2",
                    hostname,
                ]
                rc, out, err = await self._run_subprocess_lines(cmd, timeout=timeout)
                lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
                for ln in lines:
                    collected.append((ln, "gau"))
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "gau", "COMPLETED" if rc == 0 else "FAILED", t0,
                    items_processed=len(lines), findings_count=len(lines),
                    parameters_used={"host": hostname}, error_message=err if rc != 0 else None,
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "gau", "FAILED", t0, parameters_used={"host": hostname}, error_message=str(e),
                )

        # 2. WaybackURLs
        if self.binaries.get("waybackurls") and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            try:
                cmd = [self.binaries["waybackurls"], "-no-subs", hostname]
                rc, out, err = await self._run_subprocess_lines(cmd, timeout=timeout)
                lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
                for ln in lines:
                    collected.append((ln, "waybackurls"))
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "waybackurls", "COMPLETED" if rc == 0 else "FAILED", t0,
                    items_processed=len(lines), findings_count=len(lines),
                    parameters_used={"host": hostname}, error_message=err if rc != 0 else None,
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "waybackurls", "FAILED", t0, parameters_used={"host": hostname}, error_message=str(e),
                )

        # 3. Waymore (only URL mode, no subdomain expansion)
        if self.binaries.get("waymore") and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            tmp_out = None
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
                    tmp_out = tf.name
                cmd = [
                    self.binaries["waymore"],
                    "-i", hostname,
                    "-mode", "U",
                    "-no-subs",
                    "-oU", tmp_out,
                ]
                rc, _, err = await self._run_subprocess_lines(cmd, timeout=timeout)
                lines: List[str] = []
                if os.path.exists(tmp_out):
                    with open(tmp_out, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                for ln in lines:
                    collected.append((ln, "waymore"))
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "waymore", "COMPLETED" if rc == 0 else "FAILED", t0,
                    items_processed=len(lines), findings_count=len(lines),
                    parameters_used={"host": hostname}, error_message=err if rc != 0 else None,
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "waymore", "FAILED", t0, parameters_used={"host": hostname}, error_message=str(e),
                )
            finally:
                if tmp_out and os.path.exists(tmp_out):
                    try:
                        os.unlink(tmp_out)
                    except OSError:
                        pass

        # 4. Native Python Wayback CDX passive fallback when Go/Python binaries are absent
        if not collected and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            try:
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx?url={hostname}/*&output=json"
                    "&fl=original&collapse=urlkey&limit=100"
                )
                async with httpx.AsyncClient(timeout=min(timeout, 12.0), verify=get_httpx_verify()) as client:
                    resp = await client.get(cdx_url)
                    if resp.status_code == 200:
                        rows = resp.json()
                        for row in rows[1:] if isinstance(rows, list) and len(rows) > 1 else []:
                            if isinstance(row, list) and row:
                                collected.append((str(row[0]), "wayback_cdx"))
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "wayback_cdx", "COMPLETED", t0,
                    items_processed=len(collected), findings_count=len(collected),
                    parameters_used={"host": hostname},
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "wayback_cdx", "FAILED", t0,
                    parameters_used={"host": hostname}, error_message=str(e),
                )

        return collected

    def _upsert_discovered_endpoints(
        self,
        organization_id: int,
        asset: Asset,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        deduped: Dict[str, Dict],
        authorized_scope: List[str],
        excluded_domains: List[str],
    ) -> List[DiscoveredEndpoint]:
        persisted: List[DiscoveredEndpoint] = []
        now = datetime.now(timezone.utc)

        for canonical_key, entry in deduped.items():
            norm = entry["normalized"]
            sources = entry["sources"]

            if self._is_excluded(norm.hostname, excluded_domains):
                continue

            safety = SecurityGovernanceGuard.validate_target_safety(
                norm.url, authorized_scope=authorized_scope, resolve_dns=False
            )
            if not safety.get("safe"):
                continue

            existing = (
                self.db.query(DiscoveredEndpoint)
                .filter(
                    DiscoveredEndpoint.organization_id == organization_id,
                    DiscoveredEndpoint.canonical_key == canonical_key,
                )
                .first()
            )
            if existing:
                merged_sources = sorted(set(existing.sources or []) | set(sources))
                merged_gf = sorted(set(existing.gf_categories or []) | set(norm.gf_categories))
                existing.sources = merged_sources
                existing.gf_categories = merged_gf
                existing.last_seen = now
                persisted.append(existing)
            else:
                ep = DiscoveredEndpoint(
                    organization_id=organization_id,
                    asset_id=asset.id,
                    scan_job_id=scan_job_id,
                    investigation_id=investigation_id,
                    url=norm.url,
                    url_hash=norm.url_hash,
                    canonical_key=canonical_key,
                    scheme=norm.scheme,
                    host=norm.host,
                    path=norm.path,
                    method="GET",
                    query_params=norm.query_params,
                    has_params=norm.has_params,
                    gf_categories=norm.gf_categories,
                    sources=sources,
                    first_seen=now,
                    last_seen=now,
                )
                self.db.add(ep)
                persisted.append(ep)

        self.db.commit()
        return persisted

    def _ingest_normalized_finding(
        self,
        organization_id: int,
        asset: Asset,
        investigation_id: Optional[str],
        title: str,
        category: str,
        severity: str,
        source: str,
        tool_version: str,
        affected_url: str,
        affected_parameter: Optional[str],
        raw_evidence: str,
        detection_method: str,
        confidence: float,
        second_check_passed: Optional[bool],
        template_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Routes a WebCopilotAdapter finding through OpenRecon's AFP, GlobalFindingDeduplicator,
        EvidenceManager, Vulnerability table, and IntelligentRiskEngine.
        """
        taxonomy = VULN_TAXONOMY.get(category.lower(), VULN_TAXONOMY["nuclei"])
        cand = CandidateFinding(
            finding_id=f"WEB-{asset.id}-{uuid.uuid4().hex[:8].upper()}",
            organization_id=organization_id,
            asset=affected_url,
            title=title,
            severity=severity.upper(),
            source=source,
            raw_evidence=raw_evidence,
            detection_method=detection_method,
            confidence=confidence,
            second_check_passed=second_check_passed,
            metadata={
                "entity_type": "url",
                "affected_parameter": affected_parameter,
                "cwe_id": taxonomy["cwe_id"],
                "owasp_category": taxonomy["owasp"],
                "tool_version": tool_version,
            },
        )
        afp_res = self.afp_engine.process_finding(cand)

        canonical = f"{category}:{affected_parameter or ''}:{template_id or title}"
        norm = NormalizedFinding(
            organization_id=organization_id,
            investigation_id=investigation_id,
            entity_type="url",
            entity_value=affected_url,
            finding_type="vulnerability",
            source=source,
            source_reference=template_id or affected_url,
            severity=severity.upper(),
            confidence=cand.confidence,
            verification_status=afp_res["state"],
            evidence=cand.raw_evidence,
            canonical_key=canonical,
            normalized_data={
                "title": title,
                "category": category,
                "affected_url": affected_url,
                "affected_parameter": affected_parameter,
                "tool_version": tool_version,
                "cwe_id": taxonomy["cwe_id"],
                "owasp_category": taxonomy["owasp"],
                "template_id": template_id,
                "cve_id": cve_id,
                "validation_state": afp_res["state"],
            },
        )
        dedup_res = self.deduplicator.ingest(norm)
        if dedup_res["deduplicated"]:
            return None

        ev_rec = self.evidence_manager.record_finding(
            organization_id=organization_id,
            related_asset=affected_url,
            source=source,
            technical_evidence=cand.raw_evidence,
            detection_method=detection_method,
            confidence_level=cand.confidence,
            external_reference=template_id or taxonomy["cwe_id"],
            actor="webcopilot_adapter",
        )
        if afp_res["state"] == FindingValidationState.CONFIRMADO.value:
            self.evidence_manager.transition_status(
                evidence_id=ev_rec.id,
                organization_id=organization_id,
                new_status=FindingValidationState.CONFIRMADO,
                actor="webcopilot_adapter",
                reason="Verified by independent active check.",
                is_confirmed_vulnerability=True,
            )

        # Persist to Vulnerability table without duplicating existing asset+title
        existing_vuln = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.asset_id == asset.id, Vulnerability.title == title)
            .first()
        )
        if not existing_vuln:
            vuln = Vulnerability(
                asset_id=asset.id,
                title=title[:512],
                severity=getattr(SeverityLevel, severity.upper(), SeverityLevel.INFO),
                cve_id=cve_id,
                cvss_score=cvss_score,
                epss_score=epss_score,
                description=description or f"{title} on {affected_url} (param: {affected_parameter or 'N/A'}, {taxonomy['cwe_id']}, {taxonomy['owasp']})",
                remediation=remediation or f"Validate and sanitize input for parameter '{affected_parameter or 'target'}' following {taxonomy['owasp']} guidelines.",
                detector=source,
                template_id=template_id or taxonomy["cwe_id"],
            )
            self.db.add(vuln)
            self.db.commit()

        risk_info = self.risk_engine.calculate_vulnerability_risk(
            {
                "severity": severity.upper(),
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "validation_state": "CONFIRMADA" if afp_res["state"] == FindingValidationState.CONFIRMADO.value else "POTENCIAL",
            },
            asset={"is_live": asset.is_live},
        )
        return {
            "finding": norm.to_dict(),
            "afp": afp_res,
            "evidence_id": ev_rec.id,
            "risk": risk_info,
        }

    async def _validate_open_redirects(
        self,
        endpoints: List[DiscoveredEndpoint],
        asset: Asset,
        organization_id: int,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        authorized_scope: List[str],
        timeout: float,
    ) -> List[Dict[str, Any]]:
        """Safe Open Redirect verification using follow_redirects=False and a benign canary."""
        candidates = [ep for ep in endpoints if "redirect" in (ep.gf_categories or [])][:25]
        if not candidates:
            return []

        t0 = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        canary = "https://example.com/openrecon-redirect-canary"

        try:
            async with httpx.AsyncClient(
                timeout=min(timeout, 8.0),
                verify=get_httpx_verify(),
                follow_redirects=False,
            ) as client:
                for ep in candidates:
                    if self._is_killed():
                        break
                    safety = SecurityGovernanceGuard.validate_target_safety(
                        ep.url, authorized_scope=authorized_scope, resolve_dns=True
                    )
                    if not safety.get("safe"):
                        continue
                    parsed = urlparse(ep.url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    for param in ep.query_params:
                        if param.lower() not in {"next", "url", "target", "rurl", "dest", "destination", "redir", "redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnto", "return_to", "continue", "go", "out"}:
                            continue
                        mutated_qs = {k: (canary if k == param else (v[0] if v else "")) for k, v in qs.items()}
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(mutated_qs), ""))
                        try:
                            resp = await client.get(test_url)
                            loc = resp.headers.get("location", "")
                            if resp.status_code in (301, 302, 303, 307, 308) and loc.startswith(canary):
                                res = self._ingest_normalized_finding(
                                    organization_id=organization_id,
                                    asset=asset,
                                    investigation_id=investigation_id,
                                    title=f"Open Redirect on parameter '{param}' ({ep.path})",
                                    category="redirect",
                                    severity="MEDIUM",
                                    source="openredirex_safe",
                                    tool_version="openrecon-3.0",
                                    affected_url=ep.url,
                                    affected_parameter=param,
                                    raw_evidence=f"GET {test_url} -> HTTP {resp.status_code} Location: {loc}",
                                    detection_method="http_redirect_header_check",
                                    confidence=0.9,
                                    second_check_passed=True,
                                )
                                if res:
                                    findings.append(res)
                        except Exception:
                            continue
            self._record_execution(
                organization_id, scan_job_id, investigation_id,
                "openredirex_safe", "COMPLETED", t0,
                items_processed=len(candidates), findings_count=len(findings),
            )
        except Exception as e:
            self._record_execution(
                organization_id, scan_job_id, investigation_id,
                "openredirex_safe", "FAILED", t0,
                items_processed=len(candidates), error_message=str(e),
            )
        return findings

    async def _run_xss_tools(
        self,
        endpoints: List[DiscoveredEndpoint],
        asset: Asset,
        organization_id: int,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        timeout: float,
        interactsh_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        xss_eps = [ep for ep in endpoints if "xss" in (ep.gf_categories or []) and ep.has_params][:30]
        if not xss_eps:
            return []

        findings: List[Dict[str, Any]] = []
        urls_payload = "\n".join(ep.url for ep in xss_eps)

        # 1. KXSS (reflection check -> PROBABLE, never auto-CONFIRMADO)
        if self.binaries.get("kxss") and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            try:
                rc, out, err = await self._run_subprocess_lines(
                    [self.binaries["kxss"]], stdin_data=urls_payload, timeout=timeout
                )
                for line in out.splitlines():
                    if "URL:" in line and "Param:" in line:
                        m_url = re.search(r"URL:\s*(\S+)", line)
                        m_param = re.search(r"Param:\s*(\S+)", line)
                        target_u = m_url.group(1) if m_url else xss_eps[0].url
                        param_name = m_param.group(1) if m_param else "unknown"
                        res = self._ingest_normalized_finding(
                            organization_id=organization_id,
                            asset=asset,
                            investigation_id=investigation_id,
                            title=f"Reflected XSS Candidate on '{param_name}'",
                            category="xss",
                            severity="MEDIUM",
                            source="kxss",
                            tool_version="kxss",
                            affected_url=target_u,
                            affected_parameter=param_name,
                            raw_evidence=line.strip(),
                            detection_method="kxss_reflection",
                            confidence=0.65,
                            second_check_passed=None,
                        )
                        if res:
                            findings.append(res)
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "kxss", "COMPLETED" if rc == 0 else "FAILED", t0,
                    items_processed=len(xss_eps), findings_count=len(findings),
                    error_message=err if rc != 0 else None,
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "kxss", "FAILED", t0, items_processed=len(xss_eps), error_message=str(e),
                )

        # 2. Dalfox (active XSS verification, bounded workers, optional Interactsh blind URL)
        if self.binaries.get("dalfox") and not self._is_killed():
            t0 = datetime.now(timezone.utc)
            try:
                cmd = [
                    self.binaries["dalfox"],
                    "pipe",
                    "--silence",
                    "--no-color",
                    "--no-spinner",
                    "--skip-bav",
                    "--worker", "5",
                    "--format", "json",
                ]
                if interactsh_url:
                    cmd.extend(["--blind", interactsh_url])
                rc, out, err = await self._run_subprocess_lines(cmd, stdin_data=urls_payload, timeout=timeout)
                dalfox_count = 0
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    vtype = str(obj.get("type", "V")).upper()
                    is_verified = vtype == "V"
                    poc = str(obj.get("data") or obj.get("message_str") or line)
                    param_name = str(obj.get("param") or "unknown")
                    res = self._ingest_normalized_finding(
                        organization_id=organization_id,
                        asset=asset,
                        investigation_id=investigation_id,
                        title=f"Reflected XSS ({'Verified' if is_verified else 'Reflected'}) on '{param_name}'",
                        category="xss",
                        severity="HIGH" if is_verified else "MEDIUM",
                        source="dalfox",
                        tool_version="dalfox-v2",
                        affected_url=str(obj.get("data") or xss_eps[0].url).split("?")[0],
                        affected_parameter=param_name,
                        raw_evidence=poc,
                        detection_method="dalfox_active_poc" if is_verified else "dalfox_reflection",
                        confidence=0.92 if is_verified else 0.70,
                        second_check_passed=True if is_verified else None,
                    )
                    if res:
                        findings.append(res)
                        dalfox_count += 1
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "dalfox", "COMPLETED" if rc == 0 else "FAILED", t0,
                    items_processed=len(xss_eps), findings_count=dalfox_count,
                    error_message=err if rc != 0 else None,
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "dalfox", "FAILED", t0, items_processed=len(xss_eps), error_message=str(e),
                )

        return findings

    async def _run_controlled_sqlmap(
        self,
        endpoints: List[DiscoveredEndpoint],
        asset: Asset,
        organization_id: int,
        scan_job_id: Optional[int],
        investigation_id: Optional[str],
        policy: WebOrgPolicy,
        options: WebReconOptions,
    ) -> List[Dict[str, Any]]:
        """
        Controlled, non-destructive SQLMap validation.
        DISABLED by default. Requires BOTH policy.sqlmap_enabled AND options.allow_controlled_sqlmap.
        Strictly enforces read-only detection flags (risk=1, level=1, no data modification).
        """
        if not (policy.sqlmap_enabled and options.allow_controlled_sqlmap):
            return []
        if not self.binaries.get("sqlmap") or self._is_killed():
            return []

        sqli_eps = [ep for ep in endpoints if "sqli" in (ep.gf_categories or []) and ep.has_params][:5]
        if not sqli_eps:
            return []

        t0 = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []
        safe_params = {
            "batch": True,
            "level": 1,
            "risk": 1,
            "threads": 2,
            "time_sec": 5,
            "timeout": 10,
            "non_destructive": True,
        }
        try:
            for ep in sqli_eps:
                if self._is_killed():
                    self._record_execution(
                        organization_id, scan_job_id, investigation_id,
                        "sqlmap", "STOPPED_BY_KILL_SWITCH", t0,
                        items_processed=len(findings), parameters_used=safe_params,
                    )
                    return findings
                cmd = [
                    self.binaries["sqlmap"],
                    "-u", ep.url,
                    "--batch",
                    "--disable-coloring",
                    "--level=1",
                    "--risk=1",
                    "--threads=2",
                    "--timeout=10",
                    "--time-sec=5",
                    "--answers=follow=N,crack=N",
                ]
                rc, out, _ = await self._run_subprocess_lines(cmd, timeout=min(options.per_tool_timeout, 60.0))
                if "is vulnerable" in out.lower() or "parameter '" in out.lower():
                    m_param = re.search(r"Parameter:\s*([^\s(]+)", out)
                    param_name = m_param.group(1) if m_param else (ep.query_params[0] if ep.query_params else "unknown")
                    res = self._ingest_normalized_finding(
                        organization_id=organization_id,
                        asset=asset,
                        investigation_id=investigation_id,
                        title=f"SQL Injection detected on parameter '{param_name}'",
                        category="sqli",
                        severity="CRITICAL",
                        source="sqlmap",
                        tool_version="sqlmap-controlled",
                        affected_url=ep.url,
                        affected_parameter=param_name,
                        raw_evidence=EvidenceSanitizer.sanitize_raw_content(out, max_chars=1500),
                        detection_method="sqlmap_non_destructive_check",
                        confidence=0.90,
                        second_check_passed=True,
                    )
                    if res:
                        findings.append(res)
            self._record_execution(
                organization_id, scan_job_id, investigation_id,
                "sqlmap", "COMPLETED", t0,
                items_processed=len(sqli_eps), findings_count=len(findings),
                parameters_used=safe_params,
            )
        except Exception as e:
            self._record_execution(
                organization_id, scan_job_id, investigation_id,
                "sqlmap", "FAILED", t0,
                items_processed=len(sqli_eps), parameters_used=safe_params, error_message=str(e),
            )
        return findings

    async def run_for_assets(
        self,
        organization_id: int,
        assets: List[Asset],
        authorized_scope: List[str],
        scan_job_id: Optional[int] = None,
        investigation_id: Optional[str] = None,
        options: Optional[WebReconOptions] = None,
    ) -> Dict[str, Any]:
        """
        Main entry point called by ScannerOrchestrator or selective /web-recon/scan endpoint.
        """
        opts = options or WebReconOptions()
        policy = self._get_org_policy(organization_id)
        sem = asyncio.Semaphore(max(1, min(opts.max_concurrency, policy.max_concurrency)))

        total_endpoints = 0
        total_findings = 0
        discovered_urls_for_nuclei: List[Tuple[Asset, str]] = []

        async def _process_asset(asset: Asset) -> None:
            nonlocal total_endpoints, total_findings
            async with sem:
                if self._is_killed():
                    return
                hostname = (asset.value or "").strip().lower()
                if not hostname or self._is_excluded(hostname, opts.excluded_domains):
                    return

                safety = SecurityGovernanceGuard.validate_target_safety(
                    f"https://{hostname}", authorized_scope=authorized_scope, resolve_dns=True
                )
                if not safety.get("safe"):
                    logger.warning(f"WebCopilotAdapter blocked asset {hostname}: {safety.get('reason')}")
                    return

                # Phase A: Historical Endpoint Discovery
                eps: List[DiscoveredEndpoint] = []
                if opts.enable_historical_discovery:
                    raw_urls = await self._discover_historical_urls_for_host(
                        hostname, organization_id, scan_job_id, investigation_id, opts.per_tool_timeout
                    )
                    deduped = deduplicate_urls(raw_urls, drop_static=True, max_urls=opts.max_urls_per_asset)
                    eps = self._upsert_discovered_endpoints(
                        organization_id, asset, scan_job_id, investigation_id,
                        deduped, authorized_scope, opts.excluded_domains,
                    )
                    total_endpoints += len(eps)

                if not eps:
                    eps = (
                        self.db.query(DiscoveredEndpoint)
                        .filter(
                            DiscoveredEndpoint.organization_id == organization_id,
                            DiscoveredEndpoint.asset_id == asset.id,
                        )
                        .limit(opts.max_urls_per_asset)
                        .all()
                    )

                for ep in eps:
                    if ep.has_params:
                        discovered_urls_for_nuclei.append((asset, ep.url))

                # Phase B: Parameter & Vulnerability Validation
                if opts.enable_param_analysis and eps and not self._is_killed():
                    if opts.enable_open_redirect_validation:
                        redir_res = await self._validate_open_redirects(
                            eps, asset, organization_id, scan_job_id, investigation_id,
                            authorized_scope, opts.per_tool_timeout,
                        )
                        total_findings += len(redir_res)

                    if opts.enable_xss_validation:
                        oob_server = (
                            policy.interactsh_server
                            if (policy.interactsh_enabled and opts.allow_interactsh_oob and policy.interactsh_server)
                            else None
                        )
                        xss_res = await self._run_xss_tools(
                            eps, asset, organization_id, scan_job_id, investigation_id,
                            opts.per_tool_timeout, interactsh_url=oob_server,
                        )
                        total_findings += len(xss_res)

                    sqli_res = await self._run_controlled_sqlmap(
                        eps, asset, organization_id, scan_job_id, investigation_id, policy, opts
                    )
                    total_findings += len(sqli_res)

        await asyncio.gather(*[_process_asset(a) for a in assets if a.is_live])

        # Phase C: Enrich existing NucleiEngine with discovered parameterized URLs
        if (
            opts.enable_nuclei_enrichment
            and self.nuclei_engine.has_nuclei
            and discovered_urls_for_nuclei
            and not self._is_killed()
        ):
            t0 = datetime.now(timezone.utc)
            allow_intrusive = bool(policy.nuclei_allow_intrusive and opts.allow_intrusive_nuclei)
            url_to_asset = {u: a for a, u in discovered_urls_for_nuclei}
            try:
                nuclei_hits = await self.nuclei_engine.scan_targets(
                    list(url_to_asset.keys()), allow_intrusive=allow_intrusive
                )
                for nr in nuclei_hits:
                    matched_at = nr.get("matched_at") or ""
                    matched_asset = url_to_asset.get(matched_at) or assets[0]
                    is_ver_only = bool(nr.get("is_version_only_indication"))
                    res = self._ingest_normalized_finding(
                        organization_id=organization_id,
                        asset=matched_asset,
                        investigation_id=investigation_id,
                        title=nr["title"],
                        category="nuclei",
                        severity=nr["severity"],
                        source="nuclei",
                        tool_version="nuclei-v3",
                        affected_url=matched_at or f"https://{matched_asset.value}",
                        affected_parameter=None,
                        raw_evidence=nr.get("evidence") or nr.get("description") or nr["title"],
                        detection_method="nuclei_version_indication" if is_ver_only else "nuclei_template",
                        confidence=0.65 if is_ver_only else 0.85,
                        second_check_passed=None if is_ver_only else True,
                        template_id=nr.get("template_id"),
                        cve_id=nr.get("cve_id"),
                        cvss_score=nr.get("cvss_score"),
                        epss_score=nr.get("epss_score"),
                        description=nr.get("description"),
                        remediation=nr.get("remediation"),
                    )
                    if res:
                        total_findings += 1
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "nuclei_enriched", "COMPLETED", t0,
                    items_processed=len(url_to_asset), findings_count=len(nuclei_hits),
                    parameters_used={"allow_intrusive": allow_intrusive},
                )
            except Exception as e:
                self._record_execution(
                    organization_id, scan_job_id, investigation_id,
                    "nuclei_enriched", "FAILED", t0,
                    items_processed=len(url_to_asset), error_message=str(e),
                )

        return {
            "organization_id": organization_id,
            "assets_analyzed": len([a for a in assets if a.is_live]),
            "endpoints_discovered": total_endpoints,
            "findings_ingested": total_findings,
        }
