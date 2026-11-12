"""
FastAPI Endpoints for EMAIL INTELLIGENCE Module.
Exposes full investigation lifecycle, findings retrieval, forensic export, and knowledge graph mapping.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import List, Dict, Any, Optional
import json
import sqlite3
import os
import io
import csv

from app.services.email_intel.schemas import (
    InvestigationCreateRequest,
    InvestigationSummary,
)
from app.services.email_intel.orchestrator import EmailIntelOrchestrator, SQLITE_PATH

router = APIRouter()
orchestrator = EmailIntelOrchestrator()


def get_db():
    conn = sqlite3.connect(SQLITE_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@router.post("/investigations/start", response_model=Dict[str, Any])
async def start_investigation(
    req: InvestigationCreateRequest,
    background_tasks: BackgroundTasks
):
    """
    Validates input, registers a new Email Intelligence investigation,
    and dispatches background OSINT execution.
    """
    try:
        inv_id = orchestrator.create_investigation(req)
        background_tasks.add_task(orchestrator.run_investigation, inv_id)
        return {
            "success": True,
            "investigation_id": inv_id,
            "target_email": req.target_email,
            "status": "RUNNING",
            "message": "Investigation successfully initialized and dispatched in background."
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal dispatch failure: {str(e)}")


@router.get("/investigations", response_model=List[Dict[str, Any]])
def list_investigations(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = None
):
    """Lists investigations with summary counts and exposure scores."""
    conn = get_db()
    try:
        query = "SELECT * FROM email_intel_investigations"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        results = []
        for r in rows:
            inv_dict = dict(r)
            # Count details
            leaks_c = conn.execute("SELECT COUNT(*) FROM email_intel_leaks WHERE investigation_id = ?", (r["id"],)).fetchone()[0]
            acc_c = conn.execute("SELECT COUNT(*) FROM email_intel_accounts WHERE investigation_id = ? AND status = 'CONFIRMED'", (r["id"],)).fetchone()[0]
            acc_tot = conn.execute("SELECT COUNT(*) FROM email_intel_accounts WHERE investigation_id = ?", (r["id"],)).fetchone()[0]
            pastes_c = conn.execute("SELECT COUNT(*) FROM email_intel_pastes WHERE investigation_id = ?", (r["id"],)).fetchone()[0]
            
            inv_dict["leaks_count"] = leaks_c
            inv_dict["accounts_confirmed"] = acc_c
            inv_dict["accounts_checked"] = acc_tot
            inv_dict["pastes_count"] = pastes_c
            results.append(inv_dict)
        return results
    finally:
        conn.close()


@router.get("/investigations/{inv_id}", response_model=Dict[str, Any])
def get_investigation_details(inv_id: str):
    """Returns complete forensic investigation report including findings and domain posture."""
    conn = get_db()
    try:
        inv_row = conn.execute("SELECT * FROM email_intel_investigations WHERE id = ?", (inv_id,)).fetchone()
        if not inv_row:
            raise HTTPException(status_code=404, detail=f"Investigation '{inv_id}' not found.")

        inv_data = dict(inv_row)

        # Domain analysis
        domain_row = conn.execute("SELECT * FROM email_intel_domain_analysis WHERE investigation_id = ?", (inv_id,)).fetchone()
        if domain_row:
            d_dict = dict(domain_row)
            d_dict["mx_records"] = json.loads(d_dict.get("mx_records_json") or "[]")
            d_dict["weaknesses"] = json.loads(d_dict.get("weaknesses_json") or "[]")
            d_dict["recommendations"] = json.loads(d_dict.get("recommendations_json") or "[]")
            inv_data["domain_analysis"] = d_dict
        else:
            inv_data["domain_analysis"] = None

        # Leaks
        leaks = [dict(r) for r in conn.execute("SELECT * FROM email_intel_leaks WHERE investigation_id = ? ORDER BY id ASC", (inv_id,)).fetchall()]
        for l in leaks:
            l["exposed_data_types"] = json.loads(l.get("exposed_data_types") or "[]")
        inv_data["leaks"] = leaks

        # Accounts
        accounts = [dict(r) for r in conn.execute("SELECT * FROM email_intel_accounts WHERE investigation_id = ? ORDER BY id ASC", (inv_id,)).fetchall()]
        inv_data["accounts"] = accounts

        # Pastes
        pastes = [dict(r) for r in conn.execute("SELECT * FROM email_intel_pastes WHERE investigation_id = ? ORDER BY id ASC", (inv_id,)).fetchall()]
        inv_data["pastes"] = pastes

        # Variants
        variants = [dict(r) for r in conn.execute("SELECT * FROM email_intel_generated_variants WHERE investigation_id = ? ORDER BY id ASC", (inv_id,)).fetchall()]
        inv_data["generated_variants"] = variants

        # Evidences count
        ev_count = conn.execute("SELECT COUNT(*) FROM email_intel_evidence WHERE investigation_id = ?", (inv_id,)).fetchone()[0]
        inv_data["evidences_count"] = ev_count

        return inv_data
    finally:
        conn.close()


@router.post("/investigations/{inv_id}/pause")
def pause_investigation(inv_id: str):
    success = orchestrator.pause_investigation(inv_id)
    return {"success": success, "investigation_id": inv_id, "status": "PAUSED"}


@router.post("/investigations/{inv_id}/cancel")
def cancel_investigation(inv_id: str):
    success = orchestrator.cancel_investigation(inv_id)
    return {"success": success, "investigation_id": inv_id, "status": "CANCELLED"}


@router.delete("/investigations/{inv_id}")
def delete_investigation(inv_id: str):
    conn = get_db()
    try:
        with conn:
            cur = conn.execute("DELETE FROM email_intel_investigations WHERE id = ?", (inv_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail=f"Investigation '{inv_id}' not found.")
        return {"success": True, "deleted_id": inv_id}
    finally:
        conn.close()


@router.get("/investigations/{inv_id}/graph")
def get_investigation_graph(inv_id: str):
    """
    Generates Vis-Network knowledge graph payload:
    Target Email -> Domain -> MX Providers -> Leaks -> Accounts -> Devices.
    """
    conn = get_db()
    try:
        inv_row = conn.execute("SELECT * FROM email_intel_investigations WHERE id = ?", (inv_id,)).fetchone()
        if not inv_row:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        target = inv_row["target_email"]
        domain = target.split("@")[-1]

        nodes = []
        edges = []

        # Central Email Node
        nodes.append({
            "id": "root_email",
            "label": target,
            "group": "email",
            "shape": "box",
            "color": {"background": "#0284c7", "border": "#38bdf8"},
            "font": {"color": "#ffffff", "face": "monospace", "size": 14}
        })

        # Domain Node
        nodes.append({
            "id": f"dom_{domain}",
            "label": f"Domain\n{domain}",
            "group": "domain",
            "shape": "ellipse",
            "color": {"background": "#4338ca", "border": "#818cf8"},
            "font": {"color": "#ffffff", "size": 12}
        })
        edges.append({"from": "root_email", "to": f"dom_{domain}", "label": "DOMAIN_OF", "color": {"color": "#6366f1"}})

        # MX Nodes
        d_row = conn.execute("SELECT mx_records_json, mail_provider FROM email_intel_domain_analysis WHERE investigation_id = ?", (inv_id,)).fetchone()
        if d_row:
            mx_list = json.loads(d_row["mx_records_json"] or "[]")
            for idx, mx in enumerate(mx_list[:3]):
                mx_id = f"mx_{idx}"
                nodes.append({
                    "id": mx_id,
                    "label": f"MX: {mx.get('host')}\n(Pref {mx.get('preference')})",
                    "group": "mx",
                    "shape": "database",
                    "color": {"background": "#0f766e", "border": "#2dd4bf"},
                    "font": {"color": "#ffffff", "size": 11}
                })
                edges.append({"from": f"dom_{domain}", "to": mx_id, "label": "MX_RECORD", "color": {"color": "#14b8a6"}})

        # Leak Nodes
        leaks = conn.execute("SELECT id, source, corporate_services_count, computer_name_preview, operating_system FROM email_intel_leaks WHERE investigation_id = ?", (inv_id,)).fetchall()
        for l in leaks:
            leak_node_id = f"leak_{l['id']}"
            nodes.append({
                "id": leak_node_id,
                "label": f"LEAK: {l['source']}\nCorp: {l['corporate_services_count']}",
                "group": "leak",
                "shape": "diamond",
                "color": {"background": "#be123c", "border": "#fb7185"},
                "font": {"color": "#ffffff", "size": 11}
            })
            edges.append({"from": "root_email", "to": leak_node_id, "label": "COMPROMISED_IN", "color": {"color": "#f43f5e"}})

            if l["computer_name_preview"] or l["operating_system"]:
                dev_id = f"dev_{l['id']}"
                nodes.append({
                    "id": dev_id,
                    "label": f"Device: {l['computer_name_preview'] or 'Host'}\n{l['operating_system'] or ''}",
                    "group": "device",
                    "shape": "dot",
                    "color": {"background": "#854d0e", "border": "#facc15"},
                    "font": {"color": "#ffffff", "size": 10}
                })
                edges.append({"from": leak_node_id, "to": dev_id, "label": "INFECTED_HOST", "color": {"color": "#eab308"}})

        # Confirmed Account Nodes
        accs = conn.execute("SELECT id, platform, username, status FROM email_intel_accounts WHERE investigation_id = ? AND status = 'CONFIRMED'", (inv_id,)).fetchall()
        for a in accs:
            acc_id = f"acc_{a['id']}"
            nodes.append({
                "id": acc_id,
                "label": f"{a['platform']}\n@{a['username'] or target.split('@')[0]}",
                "group": "account",
                "shape": "box",
                "color": {"background": "#065f46", "border": "#34d399"},
                "font": {"color": "#ffffff", "size": 11}
            })
            edges.append({"from": "root_email", "to": acc_id, "label": "REGISTERED_ON", "color": {"color": "#10b981"}})

        return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes), "total_edges": len(edges)}
    finally:
        conn.close()
