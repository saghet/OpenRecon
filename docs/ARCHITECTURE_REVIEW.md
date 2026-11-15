# REVISIÓN DE ARQUITECTURA — OPENRECON 3.0 (FASE 2)

> **Fecha:** 2026-11-14  
> **Estado:** Consolidación de Persistencia, Conectores, Motor Central de Evidencias y Observabilidad.

---

## 1. PERSISTENCIA Y MIGRACIONES VERSIONADAS

- **Motor Principal (`backend/app/core/database.py`):**
  - **PostgreSQL** configurado como motor principal de producción con `pool_size=10`, `max_overflow=20`, `pool_recycle=1800` y `pool_pre_ping=True`.
  - **SQLite** restringido a desarrollo/pruebas aisladas con `PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL` y `PRAGMA busy_timeout=5000`.
  - Gestión explícita de transacciones (`get_db_transaction()`) y aislamiento multi-organización obligatorio (`enforce_org_isolation()`).
- **Migraciones Versionadas (Alembic):**
  - Inicializado `backend/alembic/` con `env.py` conectado a `settings.DATABASE_URL` y `Base.metadata`.
  - Generada y verificada la migración inicial `backend/alembic/versions/ff505bdc538b_initial_openrecon_3_schema.py`.

---

## 2. ARQUITECTURA ESTÁNDAR DE CONECTORES

- Implementados `BaseConnector`, `ConnectorConfig`, `ConnectorStatus`, `NormalizedConnectorResult` y `ConnectorRegistry` en `backend/app/services/connectors/`.
- Cada proveedor dispone de identificador único, versión, rate limiter asíncrono (`rate_limit_rps`), timeout con `asyncio.wait_for`, manejo estructurado de errores (`READY`, `DEGRADED`, `DISABLED`, `ERROR`) y método `normalize()` obligatorio.
- `global_connector_registry` permite registrar nuevos proveedores sin modificar módulos centrales.

---

## 3. MOTOR CENTRAL DE EVIDENCIAS (`EvidenceManager`)

- Modelos `EvidenceRecord` y `EvidenceAuditLog` (`backend/app/models/evidence.py`) con índices compuestos (`ix_evidence_org_asset`, `ix_evidence_org_status`) y claves foráneas con `ON DELETE CASCADE`.
- Servicio `EvidenceManager` (`backend/app/services/evidence/manager.py`):
  - Sanitización automática vía `EvidenceSanitizer` + SHA-256 + firma HMAC-SHA256.
  - Historial inmutable de transiciones (`change_history` + `evidence_audit_logs`).
  - Separación estricta entre coincidencia OSINT (`is_confirmed_vulnerability=False` por defecto) y vulnerabilidad confirmada.
  - Aislamiento estricto por `organization_id` en todas las lecturas y transiciones.

---

## 4. OBSERVABILIDAD Y INFRAESTRUCTURA

- **Logs estructurados & Correlation ID (`backend/app/core/observability.py`):**
  - `CorrelationIdMiddleware` propaga/genera `X-Correlation-ID` por petición usando `contextvars`.
  - `JsonLogFormatter` emite trazas JSON con `timestamp`, `level`, `logger`, `correlation_id` y `message` (protegido por `SecretRedactingFilter`).
- **Métricas Prometheus (`GET /metrics`):**
  - Expone `openrecon_http_requests_total`, `openrecon_http_request_duration_seconds_sum`, `openrecon_provider_errors_total` y `openrecon_task_duration_seconds_sum`.
- **Corrección de `backend/Dockerfile`:**
  - Reemplazado `busybox unzip ... || true` por `unzip` con `set -e` para garantizar que `subfinder`, `httpx`, `naabu` y `nuclei` se instalen correctamente en contenedores.
