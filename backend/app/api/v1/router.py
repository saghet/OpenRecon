from fastapi import APIRouter
from app.api.v1.endpoints import (
    organizations,
    assets,
    scans,
    exposures,
    opencti,
    darkweb,
    darkintel,
    cti,
    correlation,
    risk,
    security,
    email_intel
)

api_router = APIRouter()

api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations & Seeds"])
api_router.include_router(assets.router, prefix="/assets", tags=["Attack Surface Assets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scan Orchestrator"])
api_router.include_router(exposures.router, prefix="/exposures", tags=["Exposures, Vulns & DRP"])
api_router.include_router(opencti.router, prefix="/opencti", tags=["OpenCTI & STIX 2.1 Engine"])
api_router.include_router(darkweb.router, prefix="/darkweb", tags=["Dark Web & Ransomware Intelligence"])
api_router.include_router(darkintel.router, prefix="/darkintel", tags=["DARK INTELLIGENCE Enterprise Engine"])
api_router.include_router(email_intel.router, prefix="/email-intel", tags=["EMAIL INTELLIGENCE OSINT Engine"])
api_router.include_router(cti.router, prefix="/cti", tags=["Threat Intelligence Feeds & MISP"])
api_router.include_router(correlation.router, prefix="/correlation", tags=["Multidimensional Graph Correlation"])
api_router.include_router(risk.router, prefix="/risk", tags=["Intelligent Risk & Posture Scoring"])
api_router.include_router(security.router, prefix="/security", tags=["Security Governance & RoE Scope"])
