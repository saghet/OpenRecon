from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from app.core.database import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetResponse
from app.schemas.exposure import PortServiceResponse, VulnerabilityResponse

router = APIRouter()


@router.get("/", response_model=List[AssetResponse])
def list_assets(
    organization_id: int,
    is_live: Optional[bool] = None,
    cloud_provider: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    if is_live is not None:
        query = query.filter(Asset.is_live == is_live)
    if cloud_provider:
        query = query.filter(Asset.cloud_provider == cloud_provider)
    return query.order_by(Asset.last_seen.desc()).offset(skip).limit(limit).all()


@router.get("/{asset_id}/details")
def get_asset_details(asset_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return {
        "id": asset.id,
        "organization_id": asset.organization_id,
        "asset_type": asset.asset_type,
        "value": asset.value,
        "ip_address": asset.ip_address,
        "asn": asset.asn,
        "cloud_provider": asset.cloud_provider,
        "is_live": asset.is_live,
        "discovery_source": asset.discovery_source,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "ports": [PortServiceResponse.model_validate(p) for p in asset.ports],
        "vulnerabilities": [VulnerabilityResponse.model_validate(v) for v in asset.vulnerabilities]
    }
