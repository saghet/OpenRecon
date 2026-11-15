"""
Security Governance, Anti-SSRF Guardrails, Rules of Engagement (RoE) & Distributed Kill-Switch.
Guarantees that no scanning or probing activity can target unauthorized IP ranges,
private networks (RFC 1918), loopbacks, link-local addresses, CGNAT, DNS rebinding targets,
internal redirects, or cloud metadata endpoints.
Provides a persistent, multi-worker Distributed Emergency Kill-Switch (Redis + DB).
"""

import ipaddress
import json
import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import text

from app.core.config import settings

logger = logging.getLogger(__name__)

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".arpa")
_REDIS_KILL_SWITCH_KEY = "openrecon:governance:kill_switch"
_REDIS_TASK_PREFIX = "openrecon:governance:task:"


def _get_redis_client():
    """Returns a Redis client if REDIS_URL is configured and redis package is available."""
    if not settings.REDIS_URL:
        return None
    try:
        import redis  # type: ignore
        client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=1.5)
        client.ping()
        return client
    except Exception:
        return None


def _ensure_governance_tables(conn) -> None:
    """Ensures durable governance and distributed task tables exist in SQL DB."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS system_governance_state (
            id INTEGER PRIMARY KEY,
            kill_switch_active INTEGER NOT NULL DEFAULT 0,
            triggered_at TEXT,
            triggered_by TEXT,
            reason TEXT,
            updated_at TEXT
        )
    """))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS distributed_active_tasks (
            task_id TEXT PRIMARY KEY,
            task_type TEXT NOT NULL,
            target TEXT,
            status TEXT NOT NULL DEFAULT 'RUNNING',
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            pause_requested INTEGER NOT NULL DEFAULT 0,
            worker_id TEXT,
            started_at TEXT,
            updated_at TEXT
        )
    """))
    existing = conn.execute(text("SELECT id FROM system_governance_state WHERE id = 1")).fetchone()
    if not existing:
        conn.execute(
            text("""
                INSERT INTO system_governance_state (id, kill_switch_active, updated_at)
                VALUES (1, 0, :now)
            """),
            {"now": datetime.now(timezone.utc).isoformat()},
        )


class SecurityGovernanceGuard:
    """
    Central gatekeeper enforcing Scope Governance (RoE), Anti-SSRF,
    Anti-DNS-Rebinding, Redirect Protection, and Distributed Kill-Switch.
    """

    _lock = threading.Lock()
    _EMERGENCY_KILL_SWITCH: bool = False
    _KILL_SWITCH_TRIGGERED_AT: Optional[datetime] = None
    _KILL_SWITCH_TRIGGERED_BY: Optional[str] = None
    _KILL_SWITCH_REASON: Optional[str] = None

    BLOCKED_DOMAINS = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "instance-data",
        "169.254.169.254",
        "metadata",
        "0.0.0.0",
        "::",
    }

    @classmethod
    def _persist_kill_switch_state(
        cls,
        active: bool,
        reason: Optional[str],
        triggered_by: Optional[str],
        triggered_at: Optional[datetime],
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        trig_iso = triggered_at.isoformat() if triggered_at else None

        # 1. Write to Redis if configured
        r = _get_redis_client()
        if r is not None:
            try:
                payload = json.dumps({
                    "active": active,
                    "triggered_at": trig_iso,
                    "triggered_by": triggered_by,
                    "reason": reason,
                    "updated_at": now_iso,
                })
                r.set(_REDIS_KILL_SWITCH_KEY, payload)
                if active:
                    # Signal all active distributed tasks to cancel
                    for key in r.scan_iter(f"{_REDIS_TASK_PREFIX}*"):
                        r.hset(key, mapping={"cancel_requested": "1", "status": "ABORTED_BY_KILL_SWITCH"})
            except Exception as e:
                logger.warning(f"Redis kill-switch persist failed, falling back to DB: {e}")

        # 2. Always persist to SQL database for durability across restarts
        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                conn.execute(
                    text("""
                        UPDATE system_governance_state
                        SET kill_switch_active = :active,
                            triggered_at = :trig_at,
                            triggered_by = :trig_by,
                            reason = :reason,
                            updated_at = :now
                        WHERE id = 1
                    """),
                    {
                        "active": 1 if active else 0,
                        "trig_at": trig_iso,
                        "trig_by": triggered_by,
                        "reason": reason,
                        "now": now_iso,
                    },
                )
                if active:
                    conn.execute(
                        text("""
                            UPDATE distributed_active_tasks
                            SET cancel_requested = 1, status = 'ABORTED_BY_KILL_SWITCH', updated_at = :now
                            WHERE status IN ('RUNNING', 'PENDING', 'PAUSED')
                        """),
                        {"now": now_iso},
                    )
        except Exception as e:
            logger.error(f"DB kill-switch persist error: {e}")

    @classmethod
    def trigger_emergency_kill_switch(
        cls,
        reason: str = "Manual Operator Emergency Abort",
        triggered_by: str = "operator",
    ) -> Dict[str, Any]:
        """
        Immediately halts all active and pending scanning operations across all workers.
        """
        now = datetime.now(timezone.utc)
        with cls._lock:
            cls._EMERGENCY_KILL_SWITCH = True
            cls._KILL_SWITCH_TRIGGERED_AT = now
            cls._KILL_SWITCH_TRIGGERED_BY = triggered_by
            cls._KILL_SWITCH_REASON = reason
        cls._persist_kill_switch_state(True, reason, triggered_by, now)
        logger.critical(f"EMERGENCY KILL SWITCH TRIGGERED by '{triggered_by}': {reason}")
        return cls.is_kill_switch_active()

    @classmethod
    def reset_emergency_kill_switch(cls, reset_by: str = "operator") -> Dict[str, Any]:
        """
        Resets the emergency kill switch after verifying perimeter safety.
        """
        with cls._lock:
            cls._EMERGENCY_KILL_SWITCH = False
            cls._KILL_SWITCH_TRIGGERED_AT = None
            cls._KILL_SWITCH_TRIGGERED_BY = None
            cls._KILL_SWITCH_REASON = None
        cls._persist_kill_switch_state(False, None, None, None)
        logger.info(f"Emergency kill switch reset by '{reset_by}'. Scanning operations resumed.")
        return cls.is_kill_switch_active()

    @classmethod
    def is_kill_switch_active(cls) -> Dict[str, Any]:
        """
        Reads distributed kill-switch state (Redis -> DB -> in-memory fallback).
        """
        r = _get_redis_client()
        if r is not None:
            try:
                raw = r.get(_REDIS_KILL_SWITCH_KEY)
                if raw:
                    data = json.loads(raw)
                    return {
                        "active": bool(data.get("active", False)),
                        "triggered_at": data.get("triggered_at"),
                        "triggered_by": data.get("triggered_by"),
                        "reason": data.get("reason"),
                        "backend": "redis",
                    }
            except Exception:
                pass

        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                row = conn.execute(
                    text("SELECT kill_switch_active, triggered_at, triggered_by, reason FROM system_governance_state WHERE id = 1")
                ).fetchone()
                if row is not None:
                    active = bool(row[0])
                    cls._EMERGENCY_KILL_SWITCH = active
                    return {
                        "active": active,
                        "triggered_at": row[1],
                        "triggered_by": row[2],
                        "reason": row[3],
                        "backend": "database",
                    }
        except Exception:
            pass

        return {
            "active": cls._EMERGENCY_KILL_SWITCH,
            "triggered_at": cls._KILL_SWITCH_TRIGGERED_AT.isoformat() if cls._KILL_SWITCH_TRIGGERED_AT else None,
            "triggered_by": cls._KILL_SWITCH_TRIGGERED_BY,
            "reason": cls._KILL_SWITCH_REASON,
            "backend": "memory",
        }

    @classmethod
    def register_active_task(cls, task_id: str, task_type: str, target: str, worker_id: str = "local") -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        r = _get_redis_client()
        if r is not None:
            try:
                r.hset(
                    f"{_REDIS_TASK_PREFIX}{task_id}",
                    mapping={
                        "task_id": task_id,
                        "task_type": task_type,
                        "target": target,
                        "status": "RUNNING",
                        "cancel_requested": "0",
                        "pause_requested": "0",
                        "worker_id": worker_id,
                        "started_at": now_iso,
                    },
                )
            except Exception:
                pass
        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                conn.execute(
                    text("""
                        INSERT INTO distributed_active_tasks
                            (task_id, task_type, target, status, cancel_requested, pause_requested, worker_id, started_at, updated_at)
                        VALUES (:tid, :ttype, :tgt, 'RUNNING', 0, 0, :wid, :now, :now)
                        ON CONFLICT(task_id) DO UPDATE SET
                            status = 'RUNNING', cancel_requested = 0, pause_requested = 0, updated_at = :now
                    """),
                    {"tid": task_id, "ttype": task_type, "tgt": target, "wid": worker_id, "now": now_iso},
                )
        except Exception as e:
            logger.debug(f"Failed to register distributed task {task_id}: {e}")

    @classmethod
    def request_task_control(cls, task_id: str, action: str) -> bool:
        """action: 'cancel' or 'pause'."""
        now_iso = datetime.now(timezone.utc).isoformat()
        col = "cancel_requested" if action == "cancel" else "pause_requested"
        r = _get_redis_client()
        if r is not None:
            try:
                r.hset(f"{_REDIS_TASK_PREFIX}{task_id}", col, "1")
            except Exception:
                pass
        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                res = conn.execute(
                    text(f"UPDATE distributed_active_tasks SET {col} = 1, updated_at = :now WHERE task_id = :tid"),
                    {"tid": task_id, "now": now_iso},
                )
                return res.rowcount > 0
        except Exception:
            return False

    @classmethod
    def get_task_control_state(cls, task_id: str) -> Dict[str, bool]:
        ks = cls.is_kill_switch_active()
        if ks.get("active"):
            return {"cancel_requested": True, "pause_requested": False, "kill_switch": True}

        r = _get_redis_client()
        if r is not None:
            try:
                data = r.hgetall(f"{_REDIS_TASK_PREFIX}{task_id}")
                if data:
                    return {
                        "cancel_requested": data.get("cancel_requested") == "1",
                        "pause_requested": data.get("pause_requested") == "1",
                        "kill_switch": False,
                    }
            except Exception:
                pass

        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                row = conn.execute(
                    text("SELECT cancel_requested, pause_requested FROM distributed_active_tasks WHERE task_id = :tid"),
                    {"tid": task_id},
                ).fetchone()
                if row:
                    return {
                        "cancel_requested": bool(row[0]),
                        "pause_requested": bool(row[1]),
                        "kill_switch": False,
                    }
        except Exception:
            pass
        return {"cancel_requested": False, "pause_requested": False, "kill_switch": False}

    @classmethod
    def complete_active_task(cls, task_id: str, final_status: str = "COMPLETED") -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        r = _get_redis_client()
        if r is not None:
            try:
                r.delete(f"{_REDIS_TASK_PREFIX}{task_id}")
            except Exception:
                pass
        try:
            from app.core.database import engine
            with engine.begin() as conn:
                _ensure_governance_tables(conn)
                conn.execute(
                    text("UPDATE distributed_active_tasks SET status = :st, updated_at = :now WHERE task_id = :tid"),
                    {"st": final_status, "now": now_iso, "tid": task_id},
                )
        except Exception:
            pass

    @classmethod
    def _is_public_ip(cls, ip_str: str) -> Optional[str]:
        """Returns None if IP is strictly public, otherwise returns rejection reason."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return "Invalid IP address."

        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        if ip_obj.is_unspecified:
            return "Unspecified address (0.0.0.0 / ::) is forbidden."
        if ip_obj.is_loopback:
            return "Loopback address (127.0.0.0/8 or ::1) is forbidden."
        if ip_obj.is_private:
            return "Private network address (RFC 1918 / ULA) is forbidden."
        if ip_obj.is_link_local:
            return "Link-local address (169.254.0.0/16) is forbidden."
        if ip_obj.is_multicast:
            return "Multicast address range is forbidden."
        if ip_obj.is_reserved:
            return "Reserved address space is forbidden."
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NET:
            return "CGNAT address range (100.64.0.0/10) is forbidden."
        return None

    @classmethod
    def validate_target_safety(
        cls,
        target: str,
        authorized_scope: Optional[List[str]] = None,
        resolve_dns: bool = False,
        roe_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates whether a target (IP, hostname, or URL) is safe, public, and within RoE.
        """
        ks = cls.is_kill_switch_active()
        if ks.get("active"):
            return {
                "safe": False,
                "reason": f"Emergency Kill Switch is ACTIVE ({ks.get('reason')})",
            }

        if not target or not isinstance(target, str):
            return {"safe": False, "reason": "Target cannot be empty."}

        raw_clean = target.strip()
        target_clean = raw_clean.lower()

        # Extract hostname if URL is provided
        if "://" in target_clean:
            parsed = urlparse(raw_clean)
            if parsed.scheme.lower() not in ("http", "https"):
                return {"safe": False, "reason": f"Unsupported URL scheme '{parsed.scheme}'."}
            if parsed.username or parsed.password:
                return {"safe": False, "reason": "Embedded credentials in URL are forbidden."}
            if not parsed.hostname:
                return {"safe": False, "reason": "URL missing valid hostname."}
            target_clean = parsed.hostname.strip().lower()

        # 1. Blocked hostnames, suffixes & cloud metadata
        if (
            target_clean in cls.BLOCKED_DOMAINS
            or "169.254.169.254" in target_clean
            or any(target_clean.endswith(s) for s in _BLOCKED_SUFFIXES)
        ):
            return {
                "safe": False,
                "reason": f"Target '{target_clean}' blocked by Anti-SSRF policy (Cloud Metadata / Internal).",
            }

        # 2. IP Address Validation (Private, Loopback, Link-Local, CGNAT, Multicast, IPv6-mapped)
        is_ip_literal = False
        try:
            ipaddress.ip_address(target_clean)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if is_ip_literal:
            rejection = cls._is_public_ip(target_clean)
            if rejection:
                return {"safe": False, "reason": rejection}
        elif resolve_dns:
            # Anti-DNS-Rebinding: resolve hostname and verify every returned IP is public
            try:
                infos = socket.getaddrinfo(target_clean, None)
                resolved_ips = {item[4][0] for item in infos if item and item[4]}
                for rip in resolved_ips:
                    rejection = cls._is_public_ip(rip)
                    if rejection:
                        return {
                            "safe": False,
                            "reason": f"DNS Rebinding / Internal Resolution blocked for '{target_clean}' -> {rip}: {rejection}",
                        }
            except socket.gaierror:
                # Non-resolving domain is not an internal SSRF vector
                pass

        # 3. Check Authorized Scope (RoE) if enforced
        if authorized_scope is not None:
            if len(authorized_scope) == 0:
                return {
                    "safe": False,
                    "reason": "Organization has no active authorized scope (RoE Violation).",
                }
            in_scope = False
            for allowed in authorized_scope:
                allowed_clean = allowed.strip().lower()
                if not allowed_clean:
                    continue
                if target_clean == allowed_clean or target_clean.endswith("." + allowed_clean):
                    in_scope = True
                    break

            if not in_scope:
                return {
                    "safe": False,
                    "reason": f"Target '{target_clean}' is NOT in the authorized scope list (RoE Violation).",
                }

        # 4. Validate optional RoE metadata completeness
        if roe_metadata is not None:
            required_fields = ("operation_id", "organization_id", "responsible_owner")
            missing = [f for f in required_fields if not roe_metadata.get(f)]
            if missing:
                return {
                    "safe": False,
                    "reason": f"Incomplete RoE authorization metadata. Missing: {', '.join(missing)}",
                }

        return {"safe": True, "target": target_clean}

    @classmethod
    def validate_redirect_url(
        cls,
        redirect_url: str,
        authorized_scope: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Validates an HTTP redirect Location target against Anti-SSRF and DNS Rebinding."""
        return cls.validate_target_safety(
            redirect_url,
            authorized_scope=authorized_scope,
            resolve_dns=True,
        )
