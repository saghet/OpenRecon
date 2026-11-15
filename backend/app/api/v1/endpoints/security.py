from fastapi import APIRouter, Body, Depends
from typing import Optional, List, Dict, Any
from app.core.auth import require_api_token
from app.core.security_guard import SecurityGovernanceGuard

router = APIRouter()


@router.get("/kill-switch", summary="Get Emergency Kill Switch status")
async def get_kill_switch_status():
    """
    Returns whether the global emergency kill switch is active.
    """
    return SecurityGovernanceGuard.is_kill_switch_active()


@router.post("/kill-switch/trigger", summary="Trigger Emergency Kill Switch")
async def trigger_kill_switch(
    payload: Dict[str, Any] = Body(...),
    operator: str = Depends(require_api_token),
):
    """
    Halts all active scans and external probing immediately.
    """
    reason = payload.get("reason", "Operator Emergency Halt")
    triggered_by = payload.get("triggered_by") or operator
    details = SecurityGovernanceGuard.trigger_emergency_kill_switch(reason, triggered_by=triggered_by)
    stopped_scans = {"stopped_scan_ids": 0, "cancelled_tasks": 0, "terminated_processes": 0}
    try:
        from app.api.v1.endpoints.scans import cancel_all_active_scans
        stopped_scans = cancel_all_active_scans()
    except Exception:
        pass
    return {
        "status": "TRIGGERED",
        "message": "Emergency Kill Switch is now ACTIVE. All network tasks aborted.",
        "details": details,
        "stopped_scans": stopped_scans,
    }


@router.post("/kill-switch/reset", summary="Reset Emergency Kill Switch")
async def reset_kill_switch(operator: str = Depends(require_api_token)):
    """
    Resets the kill switch allowing scanning tasks to proceed normally.
    """
    details = SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by=operator)
    return {
        "status": "RESET",
        "message": "Emergency Kill Switch has been deactivated.",
        "details": details
    }


@router.post("/validate-target", summary="Validate target against Anti-SSRF and RoE")
async def validate_target(payload: Dict[str, Any]):
    """
    Checks target IP/hostname against loopback, private networks, cloud metadata, DNS rebinding, and RoE scope.
    """
    target = payload.get("target", "")
    authorized_scope = payload.get("authorized_scope")
    roe_metadata = payload.get("roe_metadata")
    return SecurityGovernanceGuard.validate_target_safety(
        target,
        authorized_scope=authorized_scope,
        resolve_dns=True,
        roe_metadata=roe_metadata,
    )
