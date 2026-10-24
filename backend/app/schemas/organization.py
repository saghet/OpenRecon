from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.models.organization import SeedType


class SeedBase(BaseModel):
    seed_type: SeedType = SeedType.DOMAIN
    value: str
    is_active: int = 1


class SeedCreate(SeedBase):
    pass


class SeedResponse(SeedBase):
    id: int
    organization_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationBase(BaseModel):
    name: str
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationResponse(OrganizationBase):
    id: int
    created_at: datetime
    updated_at: datetime
    seeds: List[SeedResponse] = []

    model_config = ConfigDict(from_attributes=True)
