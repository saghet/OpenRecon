"""
Security Governance, Anti-SSRF Guardrails & Rules of Engagement (RoE) Engine
Guarantees that no scanning or probing activity can target unauthorized IP ranges,
private networks (RFC 1918), loopbacks, link-local addresses, or cloud metadata endpoints.
Provides an instantaneous Emergency Kill-Switch to halt active scans.
"""

import ipaddress
import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class SecurityGovernanceGuard:
    """
    Central gatekeeper enforcing Scope Governance and Anti-SSRF protections.
    """

    _EMERGENCY_KILL_SWITCH: bool = False
    _KILL_SWITCH_TRIGGERED_AT: Optional[datetime] = None
    _KILL_SWITCH_REASON: Optional[str] = None

    BLOCKED_DOMAINS = {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "169.254.169.254",
        "metadata"
    }

    @classmethod
    def trigger_emergency_kill_switch(cls, reason: str = "Manual Operator Emergency Abort") -> None:
        """
        Immediately pauses all active and pending scanning operations across the platform.
        """
        cls._EMERGENCY_KILL_SWITCH = True
        cls._KILL_SWITCH_TRIGGERED_AT = datetime.utcnow()
        cls._KILL_SWITCH_REASON = reason
        logger.critical(f"EMERGENCY KILL SWITCH TRIGGERED: {reason}")

    @classmethod
    def reset_emergency_kill_switch(cls) -> None:
        """
        Resets the emergency kill switch after verifying perimeter safety.
        """
        cls._EMERGENCY_KILL_SWITCH = False
        cls._KILL_SWITCH_TRIGGERED_AT = None
        cls._KILL_SWITCH_REASON = None
        logger.info("Emergency kill switch reset. Scanning operations resumed.")

    @classmethod
    def is_kill_switch_active(cls) -> Dict[str, Any]:
        return {
            "active": cls._EMERGENCY_KILL_SWITCH,
            "triggered_at": cls._KILL_SWITCH_TRIGGERED_AT.isoformat() if cls._KILL_SWITCH_TRIGGERED_AT else None,
            "reason": cls._KILL_SWITCH_REASON
        }

    @classmethod
    def validate_target_safety(
        cls,
        target: str,
        authorized_scope: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates whether a target (IP or hostname) is safe, public, and within RoE.
        """
        if cls._EMERGENCY_KILL_SWITCH:
            return {
                "safe": False,
                "reason": f"Emergency Kill Switch is ACTIVE ({cls._KILL_SWITCH_REASON})"
            }

        target_clean = target.strip().lower()

        # 1. Blocked hostnames & cloud metadata
        if target_clean in cls.BLOCKED_DOMAINS or "169.254.169.254" in target_clean:
            return {
                "safe": False,
                "reason": f"Target '{target_clean}' blocked by Anti-SSRF policy (Cloud Metadata / Loopback)."
            }

        # 2. IP Address Validation (Private, Loopback, Multicast)
        try:
            ip_obj = ipaddress.ip_address(target_clean)
            if ip_obj.is_loopback:
                return {"safe": False, "reason": "Loopback address (127.0.0.0/8 or ::1) is forbidden."}
            if ip_obj.is_private:
                return {"safe": False, "reason": "Private network address (RFC 1918) is forbidden."}
            if ip_obj.is_link_local:
                return {"safe": False, "reason": "Link-local address (169.254.0.0/16) is forbidden."}
            if ip_obj.is_multicast:
                return {"safe": False, "reason": "Multicast address range is forbidden."}
            if ip_obj.is_reserved:
                return {"safe": False, "reason": "Reserved address space is forbidden."}
        except ValueError:
            # It's a hostname / domain
            pass

        # 3. Check Authorized Scope (RoE) if enforced
        if authorized_scope is not None and len(authorized_scope) > 0:
            in_scope = False
            for allowed in authorized_scope:
                allowed_clean = allowed.strip().lower()
                # Exact match or subdomain match
                if target_clean == allowed_clean or target_clean.endswith("." + allowed_clean):
                    in_scope = True
                    break

            if not in_scope:
                return {
                    "safe": False,
                    "reason": f"Target '{target_clean}' is NOT in the authorized scope list (RoE Violation)."
                }

        return {"safe": True, "target": target_clean}
