from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.organization import Organization, Seed
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    SeedCreate,
    SeedResponse
)

router = APIRouter()


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(org_in: OrganizationCreate, db: Session = Depends(get_db)):
    existing = db.query(Organization).filter(Organization.name == org_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Organization with this name already exists")
    
    org = Organization(name=org_in.name, description=org_in.description)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.get("/", response_model=List[OrganizationResponse])
def list_organizations(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Organization).offset(skip).limit(limit).all()


@router.get("/{org_id}", response_model=OrganizationResponse)
def get_organization(org_id: int, db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.post("/{org_id}/seeds", response_model=SeedResponse, status_code=status.HTTP_201_CREATED)
def add_seed(org_id: int, seed_in: SeedCreate, db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    seed = Seed(
        organization_id=org_id,
        seed_type=seed_in.seed_type,
        value=seed_in.value.strip().lower(),
        is_active=seed_in.is_active
    )
    db.add(seed)
    db.commit()
    db.refresh(seed)
    return seed


@router.delete("/{org_id}/seeds/{seed_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_seed(org_id: int, seed_id: int, db: Session = Depends(get_db)):
    seed = db.query(Seed).filter(Seed.id == seed_id, Seed.organization_id == org_id).first()
    if not seed:
        raise HTTPException(status_code=404, detail="Seed not found")
    db.delete(seed)
    db.commit()
    return None
