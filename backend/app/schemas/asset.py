from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.models.asset import AssetType


class AssetBase(BaseModel):
    asset_type: AssetType = AssetType.SUBDOMAIN
    value: str
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    cloud_provider: Optional[str] = None
    is_live: bool = True
    discovery_source: Optional[str] = None


class AssetCreate(AssetBase):
    organization_id: int
    seed_id: Optional[int] = None


class AssetResponse(AssetBase):
    id: int
    organization_id: int
    seed_id: Optional[int] = None
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)
