# Matriz de Migración Strangler Pattern (`web_dashboard/api.php` -> FastAPI)

Este documento registra el inventario de operaciones en `web_dashboard/api.php` (sobre `web_dashboard/openrecon.sqlite`) y su estrategia de transición progresiva hacia la autoridad central en FastAPI (`backend/app/api/v1/`).

| Dominio | Acciones PHP (`api.php`) | Plano de Destino FastAPI | Estado Actual |
| :--- | :--- | :--- | :--- |
| **Kill-Switch y Gobernanza** | `get_kill_switch`, `trigger_kill_switch`, `reset_kill_switch` | `GET/POST /api/v1/security/kill-switch*` | **MIGRATED (Strangler + Mirror SQLite)** |
| **Control de Escaneos Activos** | `stop_scan` | `POST /api/v1/scans/{scan_id}/stop`, `GET /api/v1/scans/active` | **MIGRATED (FastAPI Autoridad)** |
| **Email Intelligence** | `email_intel_list`, `email_intel_get`, `email_intel_start`, `email_intel_pause`, `email_intel_cancel`, `email_intel_delete`, `email_intel_graph`, `email_intel_export`, `email_intel_correlate_ioc` | `/api/v1/email-intel/*` | **MIGRATED (Proxy FastAPI)** |
| **Domain Intelligence** | `domain_intel_investigate`, `domain_intel_list`, `domain_intel_get`, `domain_intel_credentials_get`, `domain_intel_credentials_set`, `domain_intel_export` | `/api/v1/domain-intel/*` | **MIGRATED (Proxy FastAPI)** |
| **Secretos / Exposiciones** | `get_exposed_secrets` (lectura legacy) | `POST /api/v1/exposures/secrets/scan` | **HYBRID (Nuevo plano FastAPI)** |
| **CTI / Grafo / STIX** | `opencti_status`, `opencti_sync`, `opencti_export_stix`, `get_graph_data` | `/api/v1/opencti/*`, `POST /api/v1/correlation/graph` | **HYBRID (Lectura legacy + FastAPI CTI)** |
| **Seeds, Scope, Assets, Vulns** | `get_seeds`, `add_seed`, `delete_seed`, `get_scope`, `add_scope`, `delete_scope`, `get_assets`, `get_vulnerabilities`, `update_vuln_status`, `run_scan` | `/api/v1/organizations/*`, `/api/v1/assets/*`, `/api/v1/scans/*` | **LEGACY_COMPAT (Siguiente ola CRUD hacia PostgreSQL)** |
| **Autenticación Dashboard** | `login`, `logout`, `check_auth` | `require_api_token` (`X-API-Key` / `Bearer`) en `/api/v1/*` | **HYBRID (Sesión PHP UI + Token FastAPI)** |

## Garantías Activas
- **Detención real de procesos:** `POST /api/v1/scans/{scan_id}/stop` y `POST /api/v1/security/kill-switch/trigger` cancelan tareas `asyncio` activas (`_ACTIVE_SCAN_TASKS`) y terminan subprocesos registrados (`_ACTIVE_SCAN_PROCESSES`).
- **Datos históricos preservados:** `web_dashboard/openrecon.sqlite` permanece intacto para lectura histórica y compatibilidad del dashboard PHP sin pérdida de datos.
