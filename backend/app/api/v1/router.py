from fastapi import APIRouter
from app.api.v1.endpoints import organizations, assets, scans, exposures

api_router = APIRouter()

api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations & Seeds"])
api_router.include_router(assets.router, prefix="/assets", tags=["Attack Surface Assets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scan Orchestrator"])
api_router.include_router(exposures.router, prefix="/exposures", tags=["Exposures, Vulns & DRP"])
