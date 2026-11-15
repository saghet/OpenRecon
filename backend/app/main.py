import logging
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import Base, engine
from app.core.evidence_sanitizer import SecretRedactingFilter
from app.core.observability import CorrelationIdMiddleware, metrics_registry
from app.api.v1.router import api_router
import app.models  # Ensure all models are registered

# Attach secret redacting filter to root logger
logging.getLogger().addFilter(SecretRedactingFilter())

# Create database tables automatically for SQLite / local setups
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Open Source EASM (External Attack Surface Management), DRP (Digital Risk Protection) and CTI platform.",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Strict CORS configuration (no wildcard with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-OpenRecon-Token", "X-Requested-With"],
)
app.add_middleware(CorrelationIdMiddleware)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics():
    return Response(content=metrics_registry.render_prometheus_text(), media_type="text/plain; version=0.0.4")


@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "safe_mode": settings.SAFE_MODE,
        "docs_url": "/docs",
        "api_v1": settings.API_V1_STR
    }
