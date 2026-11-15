# REPORTE DE ENDURECIMIENTO DE SEGURIDAD (FASE 1 — PRIORIDAD P0)

> **Fecha:** 2026-11-14  
> **Alcance:** TLS/SSL, Protección de Evidencias y Secretos, Gobernanza RoE/Anti-SSRF, Kill-Switch Distribuido, Autenticación API y CORS.

---

## 1. VULNERABILIDADES CORREGIDAS

| ID | Severidad | Hallazgo | Corrección Implementada | Archivo(s) |
|---|---|---|---|---|
| **P0-01** | CRÍTICA | Desactivación masiva de validación TLS (`verify=False`, `CERT_NONE`, `CURLOPT_SSL_VERIFYPEER=false`, `CURLOPT_SSL_VERIFYHOST=false`) en conectores Python y gateway PHP. | Creación de `tls_config.py` con TLS 1.2+ obligatorio, `CERT_REQUIRED`, `check_hostname=True`, soporte de `CUSTOM_CA_BUNDLE` y detección explícita de certificados inválidos/expirados. Eliminadas todas las ocurrencias en Python y >30 en PHP. | `backend/app/core/tls_config.py`, `tor_guard.py`, `http_engine.py`, `ahmia_adapter.py`, `darkweb_collector.py`, `dark_collector_service.py`, `dark_search_engine.py`, `opencti_client.py`, `misp_client.py`, `php2shell_version_scanner.py` (2 copias), `web_dashboard/api.php`, `web_dashboard/vuln_validator_engine.php` |
| **P0-02** | CRÍTICA | Persistencia de respuestas externas sin sanitizar (`raw_text[:500]`) y ausencia de redacción de secretos en logs. | Ampliación de `EvidenceSanitizer` con `redact_secrets_in_text()`, `sanitize_evidence_payload()` y `SecretRedactingFilter` en `logging`. Sanitización obligatoria en `LeakSearcher` y en los 3 métodos de persistencia de `EmailIntelOrchestrator`. | `backend/app/core/evidence_sanitizer.py`, `backend/app/services/email_intel/leak_searcher.py`, `backend/app/services/email_intel/orchestrator.py`, `backend/app/main.py` |
| **P0-03** | ALTA | `SecurityGovernanceGuard` vulnerable a DNS rebinding, redirecciones a IPs internas, IPv6-mapped IPv4 (`::ffff:127.0.0.1`) y CGNAT (`100.64.0.0/10`); `/api/v1/scans/` no validaba RoE. | Unificación de validación Anti-SSRF, DNS rebinding (`resolve_dns=True`), `validate_redirect_url()`, validación de metadatos RoE y bloqueo en `/api/v1/scans/` si el Kill-Switch está activo o faltan semillas válidas. | `backend/app/core/security_guard.py`, `backend/app/api/v1/endpoints/scans.py`, `backend/app/api/v1/endpoints/security.py` |
| **P0-04** | CRÍTICA | Kill-Switch y `ACTIVE_TASKS` exclusivamente en memoria RAM; desconectados entre workers y reinicios. | Kill-Switch distribuido respaldado por **Redis** (`REDIS_URL`) y persistencia durable en tablas SQL (`system_governance_state`, `distributed_active_tasks`) con registro de `triggered_by`, `triggered_at` y `reason`. Integrado en `EmailIntelOrchestrator`. | `backend/app/core/security_guard.py`, `backend/app/services/email_intel/orchestrator.py` |
| **P0-05** | ALTA | CORS `allow_origins=["*"]` con `allow_credentials=True` y rutas de control sin autenticación. | Creación de `require_api_token` (`X-OpenRecon-Token` / `Bearer` con comparación constante) en `/security/kill-switch/*` y `/scans/*`; CORS restringido a `CORS_ALLOWED_ORIGINS` sin credenciales comodín. | `backend/app/core/auth.py`, `backend/app/core/config.py`, `backend/app/main.py`, `.env.example` |

---

## 2. VERIFICACIÓN Y PRUEBAS EJECUTADAS

- **`tests/security/test_p0_security_hardening.py`:** **9/9 pruebas OK** (0.631 s) cubriendo:
  - Contexto TLS estricto y rechazo de `verify_ssl=False` en `OpenCTIClient`/`MISPClient`.
  - Rechazo de certificados MITM/autofirmados en `probe_tls_certificate()`.
  - Verificación estática de **0** bypasses TLS en `backend/app`, `backend/tools` y `web_dashboard`.
  - Redacción de secretos (`sk-`, `ghp_`, `AKIA`, JWT, passwords) y XSS en evidencias y logs.
  - Bloqueo SSRF, DNS Rebinding simulado, redirecciones a `169.254.169.254` y violaciones RoE.
  - Persistencia del Kill-Switch tras borrado de estado en memoria y cancelación de tareas distribuidas.
  - Autenticación por token (`401` sin token / token inválido, `200` con `Bearer` válido) y política CORS.
- **`tests/test_vuln_validator_suite.php`:** Ejecutado tras el endurecimiento TLS en PHP.

---

## 3. RIESGOS RESIDUALES IDENTIFICADOS PARA FASE 2

1. **Autenticación en `web_dashboard/api.php`:** El gateway PHP aún mantiene acciones heredadas que no exigen `$_SESSION` en HTTP; se consolidará en Fase 2/6 al migrar acciones de `api.php` hacia FastAPI.
2. **Sincronización Kill-Switch PHP ↔ FastAPI:** `api.php` todavía escribe en su propia tabla `kill_switch_state` de `web_dashboard/openrecon.sqlite`; en Fase 2 se enrutará directamente a `/api/v1/security/kill-switch/*` al unificar la persistencia en PostgreSQL.
3. **Redis en entorno local Windows:** En desarrollo local sin `redis-server`, el Kill-Switch distribuido opera sobre base de datos SQL compartida; en producción/Docker opera sobre Redis + PostgreSQL.
