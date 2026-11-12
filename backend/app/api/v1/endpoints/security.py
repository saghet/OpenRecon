from fastapi import APIRouter, Body
from typing import Optional, List, Dict, Any
from app.core.security_guard import SecurityGovernanceGuard

router = APIRouter()


@router.get("/kill-switch", summary="Get Emergency Kill Switch status")
async def get_kill_switch_status():
    """
    Returns whether the global emergency kill switch is active.
    """
    return SecurityGovernanceGuard.is_kill_switch_active()


@router.post("/kill-switch/trigger", summary="Trigger Emergency Kill Switch")
async def trigger_kill_switch(payload: Dict[str, Any] = Body(...)):
    """
    Halts all active scans and external probing immediately.
    """
    reason = payload.get("reason", "Operator Emergency Halt")
    SecurityGovernanceGuard.trigger_emergency_kill_switch(reason)
    return {
        "status": "TRIGGERED",
        "message": "Emergency Kill Switch is now ACTIVE. All network tasks aborted.",
        "details": SecurityGovernanceGuard.is_kill_switch_active()
    }


@router.post("/kill-switch/reset", summary="Reset Emergency Kill Switch")
async def reset_kill_switch():
    """
    Resets the kill switch allowing scanning tasks to proceed normally.
    """
    SecurityGovernanceGuard.reset_emergency_kill_switch()
    return {
        "status": "RESET",
        "message": "Emergency Kill Switch has been deactivated.",
        "details": SecurityGovernanceGuard.is_kill_switch_active()
    }


@router.post("/validate-target", summary="Validate target against Anti-SSRF and RoE")
async def validate_target(payload: Dict[str, Any]):
    """
    Checks target IP/hostname against loopback, private networks, cloud metadata, and RoE scope.
    """
    target = payload.get("target", "")
    authorized_scope = payload.get("authorized_scope")
    return SecurityGovernanceGuard.validate_target_safety(target, authorized_scope)
