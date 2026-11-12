"""
Investigation Orchestrator for Email Intelligence.
Coordinates end-to-end OSINT workflows with pause, cancel, and persistence controls.
Operates on the operational SQLite database (openrecon.sqlite) and FastAPI backend.
"""

import asyncio
import uuid
import sqlite3
import json
import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.services.email_intel.zehef_adapter import ZehefAdapter
from app.services.email_intel.leak_searcher import LeakSearcher
from app.services.email_intel.account_searcher import AccountSearcher
from app.services.email_intel.paste_searcher import PasteSearcher
from app.services.email_intel.email_generator import EmailGenerator
from app.services.email_intel.domain_intel_engine import DomainIntelEngine
from app.services.email_intel.risk_scorer import RiskScorer
from app.services.email_intel.schemas import InvestigationCreateRequest

logger = logging.getLogger("email_intel.orchestrator")

def resolve_sqlite_path() -> str:
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "web_dashboard", "openrecon.sqlite")),
        os.path.abspath(os.path.join(os.getcwd(), "web_dashboard", "openrecon.sqlite")),
        os.path.abspath(os.path.join(os.getcwd(), "openrecon.sqlite")),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]

SQLITE_PATH = resolve_sqlite_path()

# In-memory execution registry for task cancellation and pause tokens
ACTIVE_TASKS: Dict[str, Dict[str, Any]] = {}


class EmailIntelOrchestrator:
    def __init__(self, db_path: str = SQLITE_PATH):
        self.db_path = db_path
        self.adapter = ZehefAdapter()
        self.leak_searcher = LeakSearcher(self.adapter)
        self.account_searcher = AccountSearcher(self.adapter)
        self.paste_searcher = PasteSearcher(self.adapter)
        self.email_generator = EmailGenerator()
        self.domain_engine = DomainIntelEngine()
        self.risk_scorer = RiskScorer()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def create_investigation(self, req: InvestigationCreateRequest, analyst_user: str = "admin") -> str:
        """Creates a pending investigation record."""
        inv_id = f"EI-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        tags_str = ",".join(req.tags) if req.tags else ""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO email_intel_investigations (
                        id, case_id, title, target_email, description, tags,
                        authorization_justification, status, progress, created_by,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, ?)
                    """,
                    (
                        inv_id, req.case_id, req.title, req.target_email,
                        req.description or "", tags_str, req.authorization_justification,
                        analyst_user, now_iso, now_iso
                    )
                )
            logger.info(f"Created investigation {inv_id} for target {req.target_email}")
            return inv_id
        finally:
            conn.close()

    async def run_investigation(self, inv_id: str):
        """Executes the investigation workflow asynchronously."""
        conn = self._get_connection()
        target_email = ""
        try:
            row = conn.execute("SELECT target_email, status FROM email_intel_investigations WHERE id = ?", (inv_id,)).fetchone()
            if not row:
                logger.error(f"Investigation {inv_id} not found.")
                return
            target_email = row["target_email"]
        finally:
            conn.close()

        ACTIVE_TASKS[inv_id] = {"status": "RUNNING", "cancel_requested": False, "pause_requested": False}
        self._update_status(inv_id, "RUNNING", 5)

        try:
            domain = target_email.split("@")[-1]

            # Step 1: Domain & DNS Intelligence (Progress: 20%)
            if self._check_cancelled(inv_id): return
            domain_intel = self.domain_engine.analyze_domain(domain)
            self._persist_domain_analysis(inv_id, domain_intel)
            self._update_progress(inv_id, 25)

            # Step 2: Leak Search (Progress: 45%)
            if self._check_cancelled(inv_id): return
            leaks, leak_evidences = await self.leak_searcher.search_leaks(target_email)
            self._persist_leaks(inv_id, leaks, leak_evidences)
            self._update_progress(inv_id, 50)

            # Step 3: Account Search (Progress: 75%)
            if self._check_cancelled(inv_id): return
            accounts, acc_evidences = await self.account_searcher.search_all_accounts(target_email)
            self._persist_accounts(inv_id, accounts, acc_evidences)
            self._update_progress(inv_id, 80)

            # Step 4: Paste Search (Progress: 88%)
            if self._check_cancelled(inv_id): return
            pastes, paste_evidences = await self.paste_searcher.search_pastes(target_email)
            self._persist_pastes(inv_id, pastes, paste_evidences)
            self._update_progress(inv_id, 90)

            # Step 5: Email Variant Generation (Progress: 95%)
            if self._check_cancelled(inv_id): return
            variants = self.email_generator.generate_variants(target_email)
            self._persist_variants(inv_id, variants)
            self._update_progress(inv_id, 95)

            # Step 6: Risk Calculation & Finalization
            exposure_score, risk_level, risk_exp = self.risk_scorer.calculate_risk(
                leaks, accounts, pastes, domain_intel
            )
            total_findings = len(leaks) + len([a for a in accounts if a.get("status") == "CONFIRMED"]) + len(pastes)

            self._finalize_investigation(inv_id, exposure_score, risk_level, risk_exp, total_findings)
            logger.info(f"Investigation {inv_id} completed. Risk: {risk_level} ({exposure_score}/100)")

        except Exception as e:
            logger.error(f"Error in investigation {inv_id}: {e}", exc_info=True)
            self._update_status(inv_id, "FAILED", 100, str(e))
        finally:
            if inv_id in ACTIVE_TASKS:
                del ACTIVE_TASKS[inv_id]

    def pause_investigation(self, inv_id: str) -> bool:
        if inv_id in ACTIVE_TASKS:
            ACTIVE_TASKS[inv_id]["pause_requested"] = True
            self._update_status(inv_id, "PAUSED")
            return True
        return False

    def cancel_investigation(self, inv_id: str) -> bool:
        if inv_id in ACTIVE_TASKS:
            ACTIVE_TASKS[inv_id]["cancel_requested"] = True
        self._update_status(inv_id, "CANCELLED")
        return True

    def _check_cancelled(self, inv_id: str) -> bool:
        task = ACTIVE_TASKS.get(inv_id)
        if not task:
            return True
        if task.get("cancel_requested"):
            self._update_status(inv_id, "CANCELLED")
            return True
        if task.get("pause_requested"):
            self._update_status(inv_id, "PAUSED")
            return True
        return False

    def _update_status(self, inv_id: str, status: str, progress: int = None, error_msg: str = None):
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                if progress is not None:
                    conn.execute(
                        "UPDATE email_intel_investigations SET status = ?, progress = ?, updated_at = ? WHERE id = ?",
                        (status, progress, now_iso, inv_id)
                    )
                else:
                    conn.execute(
                        "UPDATE email_intel_investigations SET status = ?, updated_at = ? WHERE id = ?",
                        (status, now_iso, inv_id)
                    )
                if error_msg:
                    conn.execute(
                        "UPDATE email_intel_investigations SET risk_explanation = ? WHERE id = ?",
                        (f"Failed: {error_msg}", inv_id)
                    )
        finally:
            conn.close()

    def _update_progress(self, inv_id: str, progress: int):
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute(
                    "UPDATE email_intel_investigations SET progress = ?, updated_at = ? WHERE id = ?",
                    (progress, now_iso, inv_id)
                )
        finally:
            conn.close()

    def _finalize_investigation(self, inv_id: str, score: float, level: str, exp: str, findings_count: int):
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE email_intel_investigations
                    SET status = 'COMPLETED', progress = 100, exposure_score = ?,
                        risk_level = ?, risk_explanation = ?, total_findings = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (score, level, exp, findings_count, now_iso, inv_id)
                )
        finally:
            conn.close()

    def _persist_domain_analysis(self, inv_id: str, data: Dict[str, Any]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO email_intel_domain_analysis (
                        investigation_id, domain, mail_provider, mx_records_json,
                        spf_record, spf_status, dmarc_record, dmarc_status,
                        dkim_status, dns_security_score, weaknesses_json,
                        recommendations_json, analyzed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inv_id, data["domain"], data["mail_provider"],
                        json.dumps(data.get("mx_records", [])),
                        data.get("spf_record"), data.get("spf_status"),
                        data.get("dmarc_record"), data.get("dmarc_status"),
                        data.get("dkim_status"), data.get("dns_security_score", 0),
                        json.dumps(data.get("weaknesses", [])),
                        json.dumps(data.get("recommendations", [])),
                        datetime.now(timezone.utc).isoformat()
                    )
                )
        finally:
            conn.close()

    def _persist_leaks(self, inv_id: str, leaks: list, evidences: list):
        conn = self._get_connection()
        try:
            with conn:
                # Save evidences first
                for ev in evidences:
                    ev_id = f"EV-{uuid.uuid4().hex[:8]}"
                    conn.execute(
                        """
                        INSERT INTO email_intel_evidence (
                            id, investigation_id, source_type, source_name,
                            collected_at_utc, raw_content_preview, content_sha256,
                            custody_signature, validation_status, confidence_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ev_id, inv_id, ev["source_type"], ev["source_name"],
                            ev["collected_at_utc"], ev["raw_content_preview"][:1000],
                            ev["content_sha256"], f"SHA256:{ev['content_sha256'][:16]}",
                            ev["validation_status"], ev["confidence_score"]
                        )
                    )

                # Save findings
                for l in leaks:
                    ev_id_ref = ev_id if evidences else f"EV-{uuid.uuid4().hex[:8]}"
                    conn.execute(
                        """
                        INSERT INTO email_intel_leaks (
                            investigation_id, evidence_id, source, leak_date,
                            query_date, exposed_data_types, confidence_level,
                            verifiable_reference, corporate_services_count,
                            user_services_count, computer_name_preview,
                            operating_system, ip_address_preview
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inv_id, ev_id_ref, l["source"], l.get("leak_date"),
                            l["query_date"], json.dumps(l["exposed_data_types"]),
                            l["confidence_level"], l.get("verifiable_reference"),
                            l.get("corporate_services_count", 0),
                            l.get("user_services_count", 0),
                            l.get("computer_name_preview"),
                            l.get("operating_system"),
                            l.get("ip_address_preview")
                        )
                    )
        finally:
            conn.close()

    def _persist_accounts(self, inv_id: str, accounts: list, evidences: list):
        conn = self._get_connection()
        try:
            with conn:
                for idx, a in enumerate(accounts):
                    ev = evidences[idx] if idx < len(evidences) else None
                    ev_id = f"EV-ACC-{uuid.uuid4().hex[:8]}"
                    if ev:
                        conn.execute(
                            """
                            INSERT INTO email_intel_evidence (
                                id, investigation_id, source_type, source_name,
                                collected_at_utc, raw_content_preview, content_sha256,
                                custody_signature, validation_status, confidence_score
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                ev_id, inv_id, ev["source_type"], ev["source_name"],
                                ev["collected_at_utc"], ev["raw_content_preview"][:1000],
                                ev["content_sha256"], f"SHA256:{ev['content_sha256'][:16]}",
                                ev["validation_status"], ev["confidence_score"]
                            )
                        )

                    conn.execute(
                        """
                        INSERT INTO email_intel_accounts (
                            investigation_id, evidence_id, platform, status,
                            query_date, check_method, evidence_snippet,
                            profile_url, avatar_url, username, confidence_level
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inv_id, ev_id, a["platform"], a["status"],
                            a["query_date"], a["check_method"],
                            a.get("evidence_snippet"), a.get("profile_url"),
                            a.get("avatar_url"), a.get("username"),
                            a.get("confidence_level", "HIGH")
                        )
                    )
        finally:
            conn.close()

    def _persist_pastes(self, inv_id: str, pastes: list, evidences: list):
        conn = self._get_connection()
        try:
            with conn:
                for idx, p in enumerate(pastes):
                    ev = evidences[idx] if idx < len(evidences) else None
                    ev_id = f"EV-PST-{uuid.uuid4().hex[:8]}"
                    if ev:
                        conn.execute(
                            """
                            INSERT INTO email_intel_evidence (
                                id, investigation_id, source_type, source_name,
                                collected_at_utc, raw_content_preview, content_sha256,
                                custody_signature, validation_status, confidence_score
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                ev_id, inv_id, ev["source_type"], ev["source_name"],
                                ev["collected_at_utc"], ev["raw_content_preview"][:1000],
                                ev["content_sha256"], f"SHA256:{ev['content_sha256'][:16]}",
                                ev["validation_status"], ev["confidence_score"]
                            )
                        )

                    conn.execute(
                        """
                        INSERT INTO email_intel_pastes (
                            investigation_id, evidence_id, source, paste_url,
                            discovered_date, minimal_context, classification,
                            evidence_snippet
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inv_id, ev_id, p["source"], p["paste_url"],
                            p["discovered_date"], p.get("minimal_context"),
                            p.get("classification", "PUBLIC_TEXT"),
                            p.get("evidence_snippet")
                        )
                    )
        finally:
            conn.close()

    def _persist_variants(self, inv_id: str, variants: list):
        conn = self._get_connection()
        try:
            with conn:
                for v in variants:
                    conn.execute(
                        """
                        INSERT INTO email_intel_generated_variants (
                            investigation_id, base_email, variant_email,
                            domain_type, pattern_type, classification,
                            passive_mx_valid, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inv_id, v["base_email"], v["variant_email"],
                            v["domain_type"], v["pattern_type"],
                            v.get("classification", "HYPOTHESIS_UNVERIFIED"),
                            1 if v.get("passive_mx_valid") else 0,
                            datetime.now(timezone.utc).isoformat()
                        )
                    )
        finally:
            conn.close()
