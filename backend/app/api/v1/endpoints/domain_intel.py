import csv
import html
import io
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.domain_security import CredentialVault, DomainSecurityError
from app.models.domain_intel import (
    DomainInvestigation,
    DomainReputationHistory,
    ProviderCredential,
)
from app.models.organization import Organization
from app.schemas.domain_intel import (
    DomainHistoryItemOut,
    DomainIndicatorOut,
    DomainInvestigateRequest,
    DomainInvestigationOut,
    ProviderCredentialStatusOut,
    ProviderCredentialUpsert,
    ProviderResultOut,
)
from app.services.domain_intel.service import SUPPORTED_PROVIDERS, DomainIntelligenceService

router = APIRouter()


def _serialize_investigation(inv: DomainInvestigation) -> DomainInvestigationOut:
    summary = json.loads(inv.summary_json) if inv.summary_json else {}
    graph = json.loads(inv.correlation_graph_json) if inv.correlation_graph_json else {"nodes": [], "edges": []}
    limitations = json.loads(inv.limitations_json) if inv.limitations_json else []

    providers_out = [
        ProviderResultOut(
            provider_name=pr.provider_name,
            status=pr.status.value if hasattr(pr.status, "value") else str(pr.status),
            from_cache=bool(pr.from_cache),
            latency_ms=pr.latency_ms,
            queried_at=pr.queried_at,
            error_message=pr.error_message,
            data=json.loads(pr.data_json) if pr.data_json else {},
        )
        for pr in inv.provider_results
    ]

    indicators_out = [
        DomainIndicatorOut(
            id=ind.id,
            indicator_type=ind.indicator_type,
            indicator_value=ind.indicator_value,
            source=ind.source,
            relationship_type=ind.relationship_type.value if hasattr(ind.relationship_type, "value") else str(ind.relationship_type),
            confidence=ind.confidence,
            evidence=ind.evidence,
            first_seen=ind.first_seen,
        )
        for ind in inv.indicators
    ]

    return DomainInvestigationOut(
        id=inv.id,
        organization_id=inv.organization_id,
        asset_id=inv.asset_id,
        target_input=inv.target_input,
        normalized_domain=inv.normalized_domain,
        input_type=inv.input_type.value if hasattr(inv.input_type, "value") else str(inv.input_type),
        trigger_source=inv.trigger_source,
        status=inv.status,
        risk_tier=inv.risk_tier.value if hasattr(inv.risk_tier, "value") else str(inv.risk_tier),
        technical_risk_score=inv.technical_risk_score,
        external_reputation_score=inv.external_reputation_score,
        confidence_score=inv.confidence_score,
        risk_explanation=inv.risk_explanation,
        summary=summary,
        correlation_graph=graph,
        limitations=limitations,
        provider_results=providers_out,
        indicators=indicators_out,
        cache_expires_at=inv.cache_expires_at,
        created_at=inv.created_at,
        completed_at=inv.completed_at,
    )


@router.post("/investigate", response_model=DomainInvestigationOut, summary="Ejecutar investigación Domain Intelligence")
async def investigate_domain(payload: DomainInvestigateRequest, db: Session = Depends(get_db)):
    service = DomainIntelligenceService(db)
    try:
        inv = await service.investigate(
            organization_id=payload.organization_id,
            target=payload.target,
            use_cache=payload.use_cache,
            cache_ttl_seconds=payload.cache_ttl_seconds,
            enabled_providers=payload.enabled_providers,
            enforce_roe_scope=payload.enforce_roe_scope,
            authorized_scope=payload.authorized_scope,
            trigger_source="MANUAL",
        )
        return _serialize_investigation(inv)
    except DomainSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/investigations", response_model=List[DomainHistoryItemOut], summary="Historial de investigaciones")
def list_investigations(
    organization_id: int = Query(..., ge=1),
    domain: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(DomainInvestigation).filter(DomainInvestigation.organization_id == organization_id)
    if domain:
        q = q.filter(DomainInvestigation.normalized_domain.contains(domain.strip().lower()))
    items = q.order_by(DomainInvestigation.created_at.desc()).limit(limit).all()
    return [
        DomainHistoryItemOut(
            id=i.id,
            normalized_domain=i.normalized_domain,
            input_type=i.input_type.value if hasattr(i.input_type, "value") else str(i.input_type),
            trigger_source=i.trigger_source,
            status=i.status,
            risk_tier=i.risk_tier.value if hasattr(i.risk_tier, "value") else str(i.risk_tier),
            technical_risk_score=i.technical_risk_score,
            external_reputation_score=i.external_reputation_score,
            confidence_score=i.confidence_score,
            created_at=i.created_at,
            completed_at=i.completed_at,
        )
        for i in items
    ]


@router.get("/investigations/{investigation_id}", response_model=DomainInvestigationOut, summary="Detalle de investigación")
def get_investigation(investigation_id: int, organization_id: int = Query(..., ge=1), db: Session = Depends(get_db)):
    inv = (
        db.query(DomainInvestigation)
        .filter(DomainInvestigation.id == investigation_id, DomainInvestigation.organization_id == organization_id)
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Expediente de investigación no encontrado para esta organización.")
    return _serialize_investigation(inv)


@router.get("/history/{organization_id}/{domain}", summary="Evolución histórica de reputación")
def get_domain_reputation_history(organization_id: int, domain: str, db: Session = Depends(get_db)):
    rows = (
        db.query(DomainReputationHistory)
        .filter(
            DomainReputationHistory.organization_id == organization_id,
            DomainReputationHistory.normalized_domain == domain.strip().lower(),
        )
        .order_by(DomainReputationHistory.recorded_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "investigation_id": r.investigation_id,
            "risk_tier": r.risk_tier.value if hasattr(r.risk_tier, "value") else str(r.risk_tier),
            "external_reputation_score": r.external_reputation_score,
            "vt_malicious": r.vt_malicious,
            "vt_suspicious": r.vt_suspicious,
            "otx_pulses": r.otx_pulses,
            "recorded_at": r.recorded_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/compare", summary="Comparar dos expedientes de investigación")
def compare_investigations(
    organization_id: int = Query(..., ge=1),
    left_id: int = Query(..., ge=1),
    right_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
):
    left = db.query(DomainInvestigation).filter(DomainInvestigation.id == left_id, DomainInvestigation.organization_id == organization_id).first()
    right = db.query(DomainInvestigation).filter(DomainInvestigation.id == right_id, DomainInvestigation.organization_id == organization_id).first()
    if not left or not right:
        raise HTTPException(status_code=404, detail="Una o ambas investigaciones no existen en la organización.")

    left_inds = {(i.indicator_type, i.indicator_value) for i in left.indicators}
    right_inds = {(i.indicator_type, i.indicator_value) for i in right.indicators}

    return {
        "left": {"id": left.id, "domain": left.normalized_domain, "risk_tier": left.risk_tier.value, "external_reputation_score": left.external_reputation_score, "created_at": left.created_at.isoformat()},
        "right": {"id": right.id, "domain": right.normalized_domain, "risk_tier": right.risk_tier.value, "external_reputation_score": right.external_reputation_score, "created_at": right.created_at.isoformat()},
        "added_indicators": [{"type": t, "value": v} for (t, v) in sorted(right_inds - left_inds)],
        "removed_indicators": [{"type": t, "value": v} for (t, v) in sorted(left_inds - right_inds)],
    }


@router.post("/credentials", response_model=ProviderCredentialStatusOut, summary="Configurar API Key cifrada de proveedor")
def upsert_provider_credential(payload: ProviderCredentialUpsert, db: Session = Depends(get_db)):
    pname = payload.provider_name.strip().lower()
    if pname not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Proveedor no soportado: {pname}")
    org = db.query(Organization).filter(Organization.id == payload.organization_id).first()
    if not org:
        if payload.organization_id == 1:
            org = Organization(id=1, name="OpenRecon Default Organization", description="Auto-initialized default organization")
            db.add(org)
            db.commit()
            db.refresh(org)
        else:
            raise HTTPException(status_code=404, detail="Organización no encontrada.")

    encrypted = CredentialVault.encrypt_key(payload.api_key)
    masked = CredentialVault.mask_key(payload.api_key)

    cred = (
        db.query(ProviderCredential)
        .filter(ProviderCredential.organization_id == payload.organization_id, ProviderCredential.provider_name == pname)
        .first()
    )
    if cred:
        cred.encrypted_api_key = encrypted
        cred.masked_hint = masked
        cred.is_enabled = payload.is_enabled
    else:
        cred = ProviderCredential(
            organization_id=payload.organization_id,
            provider_name=pname,
            encrypted_api_key=encrypted,
            masked_hint=masked,
            is_enabled=payload.is_enabled,
        )
        db.add(cred)

    db.commit()
    db.refresh(cred)
    return ProviderCredentialStatusOut(
        provider_name=cred.provider_name,
        is_configured=True,
        is_enabled=bool(cred.is_enabled),
        masked_hint=cred.masked_hint,
        updated_at=cred.updated_at,
    )


@router.get("/credentials/{organization_id}", response_model=List[ProviderCredentialStatusOut], summary="Estado enmascarado de API Keys")
def list_provider_credentials(organization_id: int, db: Session = Depends(get_db)):
    rows = db.query(ProviderCredential).filter(ProviderCredential.organization_id == organization_id).all()
    by_name = {r.provider_name: r for r in rows}
    result: List[ProviderCredentialStatusOut] = []
    for pname in SUPPORTED_PROVIDERS:
        r = by_name.get(pname)
        result.append(
            ProviderCredentialStatusOut(
                provider_name=pname,
                is_configured=r is not None,
                is_enabled=bool(r.is_enabled) if r else True,
                masked_hint=r.masked_hint if r else None,
                updated_at=r.updated_at if r else None,
            )
        )
    return result


@router.get("/investigations/{investigation_id}/export", summary="Exportar expediente en JSON, CSV o HTML")
def export_investigation(
    investigation_id: int,
    organization_id: int = Query(..., ge=1),
    format: str = Query("json", pattern="^(json|csv|html)$"),
    db: Session = Depends(get_db),
):
    inv = (
        db.query(DomainInvestigation)
        .filter(DomainInvestigation.id == investigation_id, DomainInvestigation.organization_id == organization_id)
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Expediente no encontrado.")

    data = _serialize_investigation(inv).model_dump(mode="json")

    if format == "json":
        return Response(
            content=json.dumps(data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="domain_intel_{inv.normalized_domain}_{inv.id}.json"'},
        )

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["indicator_type", "indicator_value", "source", "relationship_type", "confidence", "evidence"])
        for ind in data["indicators"]:
            writer.writerow([
                ind["indicator_type"],
                ind["indicator_value"],
                ind["source"],
                ind["relationship_type"],
                ind["confidence"],
                ind["evidence"] or "",
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="domain_intel_{inv.normalized_domain}_{inv.id}.csv"'},
        )

    # HTML Report (escapado contra XSS)
    rows_html = "".join(
        f"<tr><td>{html.escape(str(p['provider_name']))}</td><td>{html.escape(str(p['status']))}</td><td>{html.escape(str(p.get('error_message') or 'OK'))}</td></tr>"
        for p in data["provider_results"]
    )
    html_doc = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>OpenRecon Domain Intelligence - {html.escape(inv.normalized_domain)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}table{{width:100%;border-collapse:collapse;margin-top:16px}}th,td{{border:1px solid #334155;padding:8px;text-align:left}}th{{background:#1e293b}}</style>
</head><body>
<h1>OpenRecon — Expediente Domain Intelligence</h1>
<p><strong>Dominio/Objetivo:</strong> {html.escape(inv.normalized_domain)} ({html.escape(data['input_type'])})</p>
<p><strong>Nivel de Riesgo:</strong> {html.escape(data['risk_tier'])} | <strong>Reputación Externa:</strong> {data['external_reputation_score']} | <strong>Confianza:</strong> {data['confidence_score']}</p>
<p><strong>Explicación:</strong> {html.escape(data.get('risk_explanation') or '')}</p>
<h2>Proveedores Consultados</h2>
<table><thead><tr><th>Proveedor</th><th>Estado</th><th>Detalle</th></tr></thead><tbody>{rows_html}</tbody></table>
</body></html>"""
    return Response(
        content=html_doc,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="domain_intel_{inv.normalized_domain}_{inv.id}.html"'},
    )
