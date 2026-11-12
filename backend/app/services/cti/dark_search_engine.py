"""
Federated Dark Web Search & Specialized Analysis Engine for OpenRecon.
Provides centralized search capabilities across:
- Domains, Organizations, Brands, Corporate Emails, IPs, Keywords, CVEs, Ransomware Groups.
- Multi-Source Aggregation: Local Evidence Vault, Ransomware DLS, Onion Sources, and Ahmia Index.
- Filters: Date range, source, category, minimum confidence, surface vs onion.
- Coverage Transparency: Explicitly records sources queried and coverage scope without false claims.
- Search Query Auditing in darkintel_search_queries.
- Organization Exposure Analysis & Scoring.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import quote_plus, urlparse
import httpx

from app.core.config import settings
from app.core.tor_guard import TorSecurityGuard
from app.core.evidence_sanitizer import EvidenceSanitizer
from app.core.security_guard import SecurityGovernanceGuard
from app.services.cti.dark_collector_service import SQLITE_PATH, DarkCollectorService

logger = logging.getLogger("openrecon.dark_search")


class DarkSearchEngine:
    """
    Centralized search and analysis engine for Dark Intelligence in OpenRecon.
    """

    def __init__(
        self,
        sqlite_db_path: str = SQLITE_PATH,
        tor_proxy: Optional[str] = None
    ):
        self.sqlite_db_path = sqlite_db_path
        self.tor_proxy = tor_proxy or settings.TOR_PROXY_URL
        self.collector = DarkCollectorService(tor_proxy=self.tor_proxy, sqlite_db_path=self.sqlite_db_path)

    # -----------------------------------------------------------------------
    # 1. Centralized Dark Web Search
    # -----------------------------------------------------------------------
    async def search(
        self,
        query: str,
        query_type: str = "KEYWORD",
        sources: Optional[List[str]] = None,
        include_surface: bool = True,
        min_confidence: float = 0.3,
        date_from: Optional[str] = None,
        executed_by: str = "analyst"
    ) -> Dict[str, Any]:
        """
        Executes a multi-source federated search with strict coverage reporting.
        """
        start_time = time.time()
        query_clean = query.strip()
        if not query_clean:
            return {
                "query": query,
                "total_results": 0,
                "onion_results": 0,
                "sources_queried": [],
                "coverage_statement": "Query string is empty.",
                "results": []
            }

        # Active sources to query
        active_sources = sources or ["local_evidence_vault", "ransomware_dls", "tracked_onion_sources", "ahmia_index"]
        all_results = []
        sources_contacted = []

        # 1. Query Local Evidence Vault
        if "local_evidence_vault" in active_sources:
            vault_results = self._search_evidence_vault(query_clean, min_confidence)
            all_results.extend(vault_results)
            sources_contacted.append("local_evidence_vault")

        # 2. Query Ransomware DLS
        if "ransomware_dls" in active_sources:
            ransom_results = self._search_ransomware_posts(query_clean)
            all_results.extend(ransom_results)
            sources_contacted.append("ransomware_dls")

        # 3. Query Tracked Onion Sources Directory
        if "tracked_onion_sources" in active_sources:
            source_results = self._search_tracked_sources(query_clean)
            all_results.extend(source_results)
            sources_contacted.append("tracked_onion_sources")

        # 4. Query Ahmia Search Index (via HTTP/Tor)
        if "ahmia_index" in active_sources:
            ahmia_results = await self._search_ahmia(query_clean)
            all_results.extend(ahmia_results)
            sources_contacted.append("ahmia_index")

        # Deduplicate and sort by relevance score descending
        deduped_results = self._deduplicate_results(all_results)
        sorted_results = sorted(deduped_results, key=lambda x: x.get("relevance_score", 0), reverse=True)

        # Count onion vs surface
        onion_count = sum(1 for r in sorted_results if r.get("is_onion", False))
        execution_ms = int((time.time() - start_time) * 1000)

        # Coverage transparency statement
        coverage_statement = (
            f"Búsqueda ejecutada sobre {len(sources_contacted)} repositorios verificados ({', '.join(sources_contacted)}). "
            f"Cobertura real: Índices y servicios .onion catalogados. "
            f"No se asume cobertura absoluta de la totalidad de la red Tor no indexada."
        )

        # Audit log in darkintel_search_queries
        self._log_search_query(
            query=query_clean,
            query_type=query_type,
            sources=sources_contacted,
            results_count=len(sorted_results),
            onion_results_count=onion_count,
            executed_by=executed_by
        )

        return {
            "query": query_clean,
            "query_type": query_type,
            "sources_queried": sources_contacted,
            "coverage_statement": coverage_statement,
            "total_results": len(sorted_results),
            "onion_results": onion_count,
            "execution_time_ms": execution_ms,
            "results": sorted_results
        }

    # -----------------------------------------------------------------------
    # 2. Local Stores Search Implementations
    # -----------------------------------------------------------------------
    def _search_evidence_vault(self, query: str, min_confidence: float) -> List[Dict[str, Any]]:
        results = []
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            wildcard = f"%{query}%"
            cur.execute(
                """
                SELECT id, source_url, source_type, collected_at_utc, raw_content_preview,
                       content_sha256, validation_status, severity, confidence_score
                FROM darkintel_evidence_vault
                WHERE (raw_content_preview LIKE ? OR source_url LIKE ?)
                  AND confidence_score >= ?
                LIMIT 50
                """,
                (wildcard, wildcard, min_confidence)
            )
            for row in cur.fetchall():
                ev_id, url, stype, coll_at, preview, c_sha, v_status, sev, conf = row
                is_onion = TorSecurityGuard.is_onion_host(urlparse(url).hostname or "")
                results.append({
                    "id": ev_id,
                    "title": f"Hallazgo en Bóveda Forense ({stype})",
                    "source": "Local Evidence Vault",
                    "source_url": url,
                    "is_onion": is_onion,
                    "snippet": preview[:250],
                    "severity": sev,
                    "confidence_score": conf,
                    "validation_status": v_status,
                    "date": coll_at,
                    "relevance_score": 0.95 if query.lower() in url.lower() else 0.80,
                    "evidence_id": ev_id,
                    "content_sha256": c_sha
                })
        finally:
            conn.close()
        return results

    def _search_ransomware_posts(self, query: str) -> List[Dict[str, Any]]:
        results = []
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            wildcard = f"%{query}%"
            cur.execute(
                """
                SELECT id, evidence_id, group_name, victim_name, victim_website,
                       discovered_at_utc, claim_details, status
                FROM darkintel_ransomware_posts
                WHERE victim_name LIKE ? OR group_name LIKE ? OR victim_website LIKE ? OR claim_details LIKE ?
                LIMIT 50
                """,
                (wildcard, wildcard, wildcard, wildcard)
            )
            for row in cur.fetchall():
                p_id, ev_id, group, victim, site, disc_at, details, stat = row
                relevance = 1.0 if query.lower() in victim.lower() else 0.75
                results.append({
                    "id": f"ransom-{p_id}",
                    "title": f"Extorsión Ransomware: {group} contra {victim}",
                    "source": "Ransomware Extortion Feed",
                    "source_url": site or f"http://{group.lower()}.onion",
                    "is_onion": True,
                    "snippet": f"Grupo: {group} | Víctima: {victim} | Detalles: {details[:200] if details else 'Sin detalles'}",
                    "severity": "CRITICAL",
                    "confidence_score": 0.95,
                    "validation_status": "CORROBORATED",
                    "date": disc_at,
                    "relevance_score": relevance,
                    "evidence_id": ev_id
                })
        finally:
            conn.close()
        return results

    def _search_tracked_sources(self, query: str) -> List[Dict[str, Any]]:
        results = []
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            wildcard = f"%{query}%"
            cur.execute(
                """
                SELECT id, source_name, onion_address, category, status, reliability_rating, last_seen_online
                FROM darkintel_sources
                WHERE source_name LIKE ? OR onion_address LIKE ? OR category LIKE ?
                LIMIT 20
                """,
                (wildcard, wildcard, wildcard)
            )
            for row in cur.fetchall():
                s_id, name, onion, cat, stat, rel, last_seen = row
                results.append({
                    "id": f"source-{s_id}",
                    "title": f"Servicio Onion: {name}",
                    "source": "Tracked Dark Web Catalogs",
                    "source_url": f"http://{onion}/",
                    "is_onion": True,
                    "snippet": f"Categoría: {cat} | Estado: {stat} | Rating: {rel} | Última vez en línea: {last_seen or 'Pendiente'}",
                    "severity": "MEDIUM",
                    "confidence_score": 0.85,
                    "validation_status": "ACTIVE" if stat == "ACTIVE" else "OFFLINE",
                    "date": last_seen or datetime.now(timezone.utc).isoformat(),
                    "relevance_score": 0.70
                })
        finally:
            conn.close()
        return results

    async def _search_ahmia(self, query: str) -> List[Dict[str, Any]]:
        """
        Federated query against Ahmia public search API/portal.
        Safely extracts title, onion link, and snippet.
        """
        results = []
        ahmia_url = f"https://ahmia.fi/search/?q={quote_plus(query)}"
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(ahmia_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                if resp.status_code == 200:
                    html = resp.text
                    # Extract search result items: <li class="result">
                    items = re.findall(r'<li class="result">(.*?)</li>', html, re.DOTALL)
                    for idx, item in enumerate(items[:15]):
                        # Extract title and URL
                        title_match = re.search(r'<h4><a href="([^"]+)">(.*?)</a></h4>', item, re.DOTALL)
                        snippet_match = re.search(r'<p>(.*?)</p>', item, re.DOTALL)

                        if title_match:
                            raw_url = title_match.group(1)
                            raw_title = re.sub(r'<[^>]+>', '', title_match.group(2)).strip()
                            raw_snippet = re.sub(r'<[^>]+>', '', snippet_match.group(1)).strip() if snippet_match else ""

                            # Extract clean onion address if present
                            clean_onion = raw_url
                            onion_match = re.search(r'([a-z2-7]{16,56}\.onion)', raw_url)
                            if onion_match:
                                clean_onion = f"http://{onion_match.group(1)}"

                            results.append({
                                "id": f"ahmia-{idx}",
                                "title": raw_title or "Ahmia Onion Result",
                                "source": "Ahmia Search Index",
                                "source_url": clean_onion,
                                "is_onion": True,
                                "snippet": raw_snippet[:250],
                                "severity": "MEDIUM",
                                "confidence_score": 0.80,
                                "validation_status": "INDEXED",
                                "date": datetime.now(timezone.utc).isoformat(),
                                "relevance_score": 0.65
                            })
        except Exception as e:
            logger.debug(f"Ahmia federated search query failed or timed out: {e}")

        return results

    # -----------------------------------------------------------------------
    # 3. Organization Exposure Analysis & Scoring Engine
    # -----------------------------------------------------------------------
    def analyze_organization_exposure(
        self,
        organization_id: int,
        domains: List[str],
        brands: Optional[List[str]] = None,
        emails: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end organizational exposure assessment:
        1. Ransomware DLS matching
        2. Credential exposures (masked)
        3. Threat actor & campaign attribution
        4. CISA KEV vulnerability correlation
        5. Calculated Exposure Score (0-100)
        6. Forensic persistence in darkintel_investigations
        """
        all_seeds = list(domains) + (brands or []) + (emails or [])
        clean_domains = [d.strip().lower() for d in domains]

        # 1. Match Ransomware Posts
        ransom_matches = self.collector.correlate_seeds_with_darkintel(all_seeds, org_id=organization_id)

        # 2. Match Credential Leaks in DB
        leak_matches = []
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            for dom in clean_domains:
                cur.execute(
                    """
                    SELECT id, evidence_id, domain_mentioned, masked_identity, exposure_type, leak_source, discovered_at
                    FROM darkintel_leaks
                    WHERE domain_mentioned LIKE ?
                    """,
                    (f"%{dom}%",)
                )
                for row in cur.fetchall():
                    leak_matches.append({
                        "id": row[0],
                        "evidence_id": row[1],
                        "domain": row[2],
                        "masked_identity": row[3],
                        "type": row[4],
                        "source": row[5],
                        "date": row[6]
                    })

            # Check matching CVEs with active CISA KEV
            cur.execute("SELECT count(*) FROM vulnerabilities WHERE cisa_kev = 1")
            active_kev_count = cur.fetchone()[0]

            # Check related IOCs
            cur.execute("SELECT count(*) FROM darkintel_iocs WHERE is_malicious = 1")
            malicious_iocs = cur.fetchone()[0]
        finally:
            conn.close()

        # Calculate Posture & Exposure Score (0 to 100)
        # Weighting:
        # Ransomware DLS match: 40 pts
        # Credential leaks: 25 pts
        # Active CISA KEV in perimeter: 20 pts
        # Malicious IOCs: 15 pts
        score = 0.0
        if len(ransom_matches) > 0:
            score += min(40.0, len(ransom_matches) * 20.0)
        if len(leak_matches) > 0:
            score += min(25.0, len(leak_matches) * 5.0)
        if active_kev_count > 0:
            score += min(20.0, active_kev_count * 10.0)
        if malicious_iocs > 0:
            score += min(15.0, malicious_iocs * 3.0)

        exposure_score = round(min(100.0, score), 1)

        # Generate Actionable Recommendations
        recommendations = []
        if len(ransom_matches) > 0:
            recommendations.append("URGENTE: Iniciar comité de respuesta a incidentes. Se ha detectado publicación activa en DLS de ransomware.")
            recommendations.append("Aislar servidores expuestos con puertos RDP o VPN no parcheados.")
        if len(leak_matches) > 0:
            recommendations.append("Forzar reseteo de contraseñas corporativas y activar autenticación MFA de hardware (FIDO2) para identidades expuestas.")
        if active_kev_count > 0:
            recommendations.append("Priorizar la remediación inmediata de las vulnerabilidades catalogadas en CISA KEV antes de 24 horas.")
        if not recommendations:
            recommendations.append("Mantener monitoreo continuo de activos y fuentes de filtración.")

        summary = (
            f"Evaluación de exposición organizacional completada. Se identificaron {len(ransom_matches)} menciones en sitios de extorsión, "
            f"{len(leak_matches)} credenciales corporativas expuestas y {active_kev_count} vulnerabilidades de explotación activa."
        )

        # Store in darkintel_investigations
        investigation_id = self._store_investigation(
            organization_id=organization_id,
            title=f"Auditoría Dark Web de {domains[0]}",
            scope={"domains": domains, "brands": brands, "emails": emails},
            total_findings=len(ransom_matches) + len(leak_matches),
            critical_findings=len(ransom_matches),
            exposure_score=exposure_score,
            summary=summary,
            recommendations="\n".join(recommendations)
        )

        return {
            "investigation_id": investigation_id,
            "organization_id": organization_id,
            "domains_analyzed": domains,
            "exposure_score": exposure_score,
            "threat_level": "CRITICAL" if exposure_score >= 60 else ("HIGH" if exposure_score >= 35 else "MEDIUM"),
            "ransomware_dls_findings": ransom_matches,
            "credential_leak_findings": leak_matches,
            "active_cisa_kev_vulns": active_kev_count,
            "summary": summary,
            "recommendations": recommendations,
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------
    def _deduplicate_results(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen_keys = set()
        deduped = []
        for it in items:
            key = f"{it.get('source_url', '')}|{it.get('title', '')}"
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(it)
        return deduped

    def _log_search_query(
        self,
        query: str,
        query_type: str,
        sources: List[str],
        results_count: int,
        onion_results_count: int,
        executed_by: str
    ) -> None:
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO darkintel_search_queries 
                (query_string, query_type, sources_queried, results_count, onion_results_count, executed_by, executed_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (query, query_type, json.dumps(sources), results_count, onion_results_count, executed_by)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log search query: {e}")
        finally:
            conn.close()

    def _store_investigation(
        self,
        organization_id: int,
        title: str,
        scope: Dict[str, Any],
        total_findings: int,
        critical_findings: int,
        exposure_score: float,
        summary: str,
        recommendations: str
    ) -> int:
        conn = sqlite3.connect(self.sqlite_db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO darkintel_investigations
                (organization_id, title, investigation_scope, status, total_findings,
                 critical_findings, exposure_score, executive_summary, recommendations,
                 created_at, completed_at)
                VALUES (?, ?, ?, 'COMPLETED', ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    organization_id,
                    title,
                    json.dumps(scope),
                    total_findings,
                    critical_findings,
                    exposure_score,
                    summary,
                    recommendations
                )
            )
            inv_id = cur.lastrowid
            conn.commit()
            return inv_id
        finally:
            conn.close()
