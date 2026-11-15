# AUDITORÍA TÉCNICA INTEGRAL — OPENRECON 3.0 (FASE 0)

> **Fecha de Auditoría:** 2026-11-14  
> **Rama Activa Inspeccionada:** `main` (commit `2a12313`, 21,553 inserciones por delante de `origin/master` `0d6d0b6`)  
> **Versión Declarada:** `2.1.0` en `CHANGELOG.md` / `0.2.0` en `backend/app/core/config.py`  
> **Estado del Working Tree:** `web_dashboard/openrecon.sqlite` con cambios locales sin confirmar (`modified`).

---

## 1. RESUMEN EJECUTIVO DE LÍNEA BASE

OpenRecon presenta una base funcional amplia pero **arquitectónicamente fragmentada en dos planos paralelos**:

1. **Plano PHP Monolítico (`web_dashboard/api.php`, 356 KB / ~7,300+ líneas):** Concentra ~94 acciones que operan directamente sobre `web_dashboard/openrecon.sqlite` o invocan scripts Python locales por `popen`/`shell_exec`. Solo 2 familias de acciones (`domain_intel_*` y `darkintel_ai_analyze`) consumen realmente el microservicio FastAPI (`127.0.0.1:8000`).
2. **Plano FastAPI (`backend/app/`, 60 rutas OpenAPI en 13 routers):** Implementa motores modernos (Domain Intel, Email Intel, DarkIntel, OpenCTI, MISP, Graph Engine, Risk Engine, Security Guard), pero opera contra su propia base SQLite (`./openrecon.db` / `backend/openrecon.db`) desconectada de `web_dashboard/openrecon.sqlite`, sin autenticación en sus endpoints y sin integración real con PostgreSQL/Redis en el entorno local.

### Resultados de Pruebas Observados en Línea Base
- **Python `unittest` (`backend\venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v`):** **79 pruebas ejecutadas, 79 OK (0 fallos, 0 errores)** en 24.393 s. *(Nota: el Python global del sistema `C:\Python314\python.exe` carece de `sqlalchemy`, `httpx` y `pytest`; el entorno real del proyecto es `backend\venv`).*
- **PHP Forense (`C:\xampp\php\php.exe tests/test_vuln_validator_suite.php`):** **10/10 escenarios controlados + 9/9 pruebas Anti-SSRF aprobados** en 14.33 s (0 hallazgos perimetrales activos evaluados en `fdn.com.co`).
- **PHP Email Intel API (`C:\xampp\php\php.exe tests/test_email_intel_api.php`):** Ejecutado con código de salida `0`.

---

## 2. MATRIZ DE MÓDULOS Y ESTADO FUNCIONAL

Estados permitidos: `FUNCIONAL_VERIFICADO`, `PARCIAL`, `DOCUMENTADO_NO_VERIFICADO`, `SIMULADO`, `NO_FUNCIONAL`, `INEXISTENTE`.

| Módulo | Estado | Archivo | Endpoint | Prueba | Problema |
|---|---|---|---|---|---|
| **Core API & Config** | PARCIAL | `backend/app/main.py`, `backend/app/core/config.py` | `/` | `test_stage4_consolidation.py` | CORS `allow_origins=["*"]` con `allow_credentials=True`; versión `0.2.0` desalineada con `2.1.0`; `SECRET_KEY` de desarrollo por defecto; sin Auth/RBAC. |
| **Persistencia & Migraciones** | PARCIAL | `backend/app/core/database.py`, `web_dashboard/api.php` | N/A | `test_domain_intel_phase1.py`, `test_stage4_consolidation.py` | Coexisten 3 archivos SQLite (`./openrecon.db`, `backend/openrecon.db`, `web_dashboard/openrecon.sqlite`). No hay migraciones Alembic activas ni aislamiento multi-tenant. |
| **Gobernanza RoE & Anti-SSRF** | PARCIAL | `backend/app/core/security_guard.py`, `backend/app/core/domain_security.py` | `/api/v1/security/validate-target`, `api.php?action=get_scope` | `test_stage1_security.py`, `test_domain_intel_phase1.py` | `security_guard.py` no resuelve DNS (vulnerable a DNS rebinding) ni valida redirecciones HTTP; `/api/v1/scans/` no invoca `SecurityGovernanceGuard`. `domain_security.py` sí protege contra DNS rebinding pero está aislado en `domain_intel`. |
| **Kill-Switch Global** | PARCIAL | `backend/app/core/security_guard.py`, `backend/app/services/email_intel/orchestrator.py`, `web_dashboard/api.php` | `/api/v1/security/kill-switch*`, `api.php?action=trigger_kill_switch` | `test_stage1_security.py` (parcial) | **Desconectado entre planos:** `api.php` escribe en SQLite `kill_switch_state`; Python usa `_EMERGENCY_KILL_SWITCH` y `ACTIVE_TASKS` solo en memoria RAM de proceso (se pierde al reiniciar y no funciona con múltiples workers). Sin autenticación en `/kill-switch/*`. |
| **Sanitización de Evidencias** | PARCIAL | `backend/app/core/evidence_sanitizer.py`, `backend/app/services/email_intel/leak_searcher.py` | Varios (`email-intel`, `darkintel`) | `test_email_intel_suite.py` | `leak_searcher.py:52` guarda `raw_content_preview: raw_text[:500]` sin pasar por `EvidenceSanitizer.sanitize_raw_content()`. |
| **Domain Intelligence** | FUNCIONAL_VERIFICADO | `backend/app/services/domain_intel/*`, `web_dashboard/domain_intel.php` | `/api/v1/domain-intel/*`, `api.php?action=domain_intel_*` | `test_domain_intel_phase1.py`, `test_domain_intel_suite.py`, `test_domain_intel_webosint.py` | Conectado end-to-end PHP -> FastAPI; cifrado Fernet de API keys; anti-DNS rebinding. Depende de claves externas para WhoisXML; usa `datetime.utcnow()` deprecado. |
| **Email Intelligence (Zehef + XposedOrNot)** | FUNCIONAL_VERIFICADO | `backend/app/services/email_intel/*`, `web_dashboard/email_intel.php` | `/api/v1/email-intel/*`, `api.php?action=email_intel_*` | `test_email_intel_suite.py`, `test_xposedornot_integration.py`, `test_php_gateway_suite.py` | `api.php` ejecuta `run_worker.py` vía SQLite local en lugar de enrutar a FastAPI; `ACTIVE_TASKS` en memoria; `leak_searcher.py` persiste preview crudo; dependencias GPL-3.0 de Zehef requieren revisión continua. |
| **Validador Forense 5 Estados** | FUNCIONAL_VERIFICADO | `web_dashboard/vuln_validator_engine.php` | `api.php?action=validate_vulnerability`, `batch_validate_vulnerabilities` | `test_vuln_validator_suite.php` (10/10 + 9/9 Anti-SSRF) | Deshabilita verificación TLS (`CURLOPT_SSL_VERIFYPEER=false`, `CURLOPT_SSL_VERIFYHOST=false` en líneas 57-58); solo reside en PHP (no disponible como servicio Python). |
| **EASM Core (DNS/Port/HTTP/Nuclei)** | PARCIAL | `backend/app/services/engines/*.py`, `backend/app/services/scanner_orchestrator.py` | `/api/v1/scans/` | `test_stage4_consolidation.py` (import) | `http_engine.py` usa `verify=False` y `ssl.CERT_NONE`; binarios (`subfinder`, `nuclei`, `naabu`, `dnsx`, `httpx`) no están instalados en Windows y en `backend/Dockerfile` fallan silenciosamente (`busybox unzip ... \|\| true`). |
| **Dark Web & Tor Watchdog** | PARCIAL | `backend/app/core/tor_guard.py`, `backend/app/services/cti/dark*.py`, `web_dashboard/darkintel.php` | `/api/v1/darkweb/*`, `/api/v1/darkintel/*` | `test_stage1_security.py` (anti-mock) | `tor_guard.py`, `ahmia_adapter.py`, `darkweb_collector.py`, `dark_collector_service.py` y `dark_search_engine.py` fuerzan `verify=False` en `httpx`. Sin demonio Tor activo en entorno local Windows. |
| **OpenCTI & MISP** | DOCUMENTADO_NO_VERIFICADO | `backend/app/services/cti/opencti_client.py`, `backend/app/services/cti/misp_client.py`, `backend/app/services/cti/stix_exporter.py` | `/api/v1/opencti/*`, `/api/v1/cti/misp/*`, `api.php?action=opencti_*` | Ninguna prueba de integración real en `tests/` | Ambos clientes inicializan `verify_ssl=False` por defecto, usan URLs hardcoded (`localhost:8080`, `misp.local`) sin leer `settings`, y `api.php` no llama al cliente Python sino a SQLite local. |
| **CISA KEV & EPSS** | FUNCIONAL_VERIFICADO | `web_dashboard/api.php`, `backend/app/services/domain_intel/webosint_adapters.py` | `api.php?action=enrich_cve` | `test_stage2_core_modules.py`, `test_domain_intel_webosint.py` | Duplicación entre lógica PHP (`api.php`) y Python (`webosint_adapters.py`). |
| **Correlation Graph Engine** | PARCIAL | `backend/app/services/correlation/graph_engine.py` | `/api/v1/correlation/graph`, `api.php?action=get_graph_data` | `test_domain_intel_suite.py` (parcial) | El grafo en `api.php` consulta SQLite directamente; `graph_engine.py` en Python no persiste aristas ni distingue siempre evidencia confirmada vs inferida. |
| **Risk Scoring Explicable** | FUNCIONAL_VERIFICADO | `backend/app/services/risk/risk_engine.py`, `backend/app/services/email_intel/risk_scorer.py`, `web_dashboard/api.php` | `/api/v1/risk/*`, `api.php?action=get_risk_score_breakdown` | `test_stage2_core_modules.py`, `test_xposedornot_integration.py` | Lógica triplicada entre `risk_engine.py`, `email_intel/risk_scorer.py` y `api.php`. |
| **DeepSeek AI Engine** | PARCIAL | `backend/app/services/ai/deepseek_engine.py` | `/api/v1/darkintel/ai/analyze`, `api.php?action=darkintel_ai_analyze` | `test_stage3_enterprise_modules.py` | Funciona en modo fallback determinístico si falta `DEEPSEEK_API_KEY`; sin suite de pruebas dedicada para anti-hallucination o validación contra Evidence Vault. |
| **DRP & LoginRecon & Facebook AI** | PARCIAL | `backend/app/services/engines/drp_engine.py`, `backend/app/facebook_ai_correlator.py`, `backend/app/face_matcher.py` | `api.php?action=loginrecon_*` | Ninguna prueba automatizada en `tests/` | `web_dashboard/engine/facebook_ai_correlator.py` duplicado en `backend/app/`; dependencias (`opencv-python`, `pillow`) ausentes en `backend/requirements.txt`; `api.php` usa `CURLOPT_SSL_VERIFYPEER=false`. |
| **PHP2Shell Scanner** | PARCIAL | `backend/tools/php2shell_scanner/php2shell_version_scanner.py`, `web_dashboard/backend/tools/php2shell_scanner/` | `api.php?action=php2shell_scan` | Ninguna prueba en `tests/` | Código duplicado en 2 rutas (`backend/tools/` y `web_dashboard/backend/tools/`); desactiva TLS (`ctx.verify_mode = ssl.CERT_NONE`, `ctx.check_hostname = False`). |
| **Strix / AutoPentestX (API PHP)** | DOCUMENTADO_NO_VERIFICADO | `web_dashboard/api.php` | `api.php?action=strix_*`, `autopentestx_*` | Ninguna prueba automatizada | Deshabilita TLS (`CURLOPT_SSL_VERIFYPEER=false`, `CURLOPT_SSL_VERIFYHOST=false`) e inyecta scripts Python inline con `requests` sin verificación TLS. |
| **Autenticación & Control de Acceso** | NO_FUNCIONAL | `web_dashboard/api.php`, `backend/app/main.py` | `api.php?action=login`, `check_auth` | Ninguna prueba de seguridad auth | `api.php` tiene `login`/`check_auth` pero **no exige sesión** en los `case` sensibles (hace fallback a `'analyst_local'`/`'admin'`). FastAPI no tiene ningún middleware de autenticación. |
| **GitHub Secret Intelligence** | INEXISTENTE | N/A | N/A | N/A | No existe integración con Gitleaks, TruffleHog ni GitHub API. |
| **Observabilidad (Prometheus / Logs JSON)** | INEXISTENTE | N/A | N/A | N/A | Solo `logging` básico; sin Correlation ID, métricas Prometheus ni tracing de workers. |

---

## 3. HALLAZGOS CRÍTICOS DE SEGURIDAD (PRIORIDAD P0)

1. **Desactivación Masiva de Validación TLS (MITM Vulnerable):**
   - **Python:** `tor_guard.py:286`, `ahmia_adapter.py:77`, `darkweb_collector.py:52,75`, `dark_collector_service.py:344`, `dark_search_engine.py:262`, `http_engine.py:40,78-79`, `opencti_client.py:27`, `misp_client.py:25`, `php2shell_version_scanner.py:384-385,647-648`.
   - **PHP:** `web_dashboard/api.php` contiene **>30 ocurrencias** de `CURLOPT_SSL_VERIFYPEER => false` / `CURLOPT_SSL_VERIFYHOST => false` (incluyendo scripts Python inline); `web_dashboard/vuln_validator_engine.php:57-58` desactiva verificación TLS en todas las sondas.
2. **Ausencia Total de Control de Acceso (Auth Bypass):**
   - `web_dashboard/api.php` no valida `$_SESSION` antes de ejecutar mutaciones críticas (`trigger_kill_switch`, `add_seed`, `run_scan`, `domain_intel_credentials_set`, etc.).
   - FastAPI (`60` rutas) carece de autenticación por token/API-key/JWT; cualquier cliente local o en red puede disparar/resetear el Kill-Switch o lanzar escaneos.
3. **Kill-Switch No Distribuido y Desconectado:**
   - `SecurityGovernanceGuard._EMERGENCY_KILL_SWITCH` y `email_intel.orchestrator.ACTIVE_TASKS` viven únicamente en memoria del proceso Python.
   - El botón del dashboard (`index.php` -> `api.php`) solo actualiza la tabla SQLite `kill_switch_state`, sin detener workers Python ni bloquear rutas FastAPI.
4. **SSRF & DNS Rebinding Parciales:**
   - `SecurityGovernanceGuard.validate_target_safety()` no resuelve DNS ni valida redirecciones HTTP; además `/api/v1/scans/` no invoca la validación RoE antes de crear el `ScanJob`.
5. **Exposición de Evidencia Cruda sin Sanitizar:**
   - `leak_searcher.py:52` almacena `raw_text[:500]` directamente en `raw_content_preview` sin sanitización centralizada ni redacción de secretos.
6. **CORS Permisivo en FastAPI:**
   - `backend/app/main.py:21-27` configura `allow_origins=["*"]` combinado con `allow_credentials=True`.

---

## 4. DUPLICACIONES DETECTADAS (NO REIMPLEMENTAR)

- **Motor SSRF/Validación:** `domain_security.py` (completo con anti-DNS rebinding y Fernet) vs `security_guard.py` (incompleto). **Acción:** Unificar en un único núcleo de seguridad.
- **Scanners/Tools duplicados en árbol:** `backend/tools/php2shell_scanner` y `web_dashboard/backend/tools/php2shell_scanner`; `backend/app/facebook_ai_correlator.py` y `web_dashboard/engine/facebook_ai_correlator.py`.
- **Lógica de Risk Scoring y EPSS/KEV:** Implementada por separado en `api.php`, `risk_engine.py`, `email_intel/risk_scorer.py` y `domain_intel/risk_and_correlation.py`.
- **Base de datos fragmentada:** `openrecon.db`, `backend/openrecon.db` y `web_dashboard/openrecon.sqlite`.
- **Tests referenciados en CHANGELOG que no existen en `tests/`:** `test_stage5_opencti_and_darkweb.py`, `test_stage6_correlation_and_risk.py`, `test_stage7_security_and_governance.py`.

---

## 5. REFERENCIAS DE ARCHIVOS AUDITADOS

- Backend Entry: `backend/app/main.py`, `backend/app/api/v1/router.py`, `backend/app/core/config.py`
- Seguridad: `backend/app/core/security_guard.py`, `backend/app/core/domain_security.py`, `backend/app/core/evidence_sanitizer.py`, `backend/app/core/tor_guard.py`
- Servicios: `backend/app/services/domain_intel/*`, `backend/app/services/email_intel/*`, `backend/app/services/cti/*`, `backend/app/services/engines/*`, `backend/app/services/ai/deepseek_engine.py`
- Frontend/Gateway: `web_dashboard/api.php`, `web_dashboard/index.php`, `web_dashboard/vuln_validator_engine.php`, `web_dashboard/domain_intel.php`, `web_dashboard/email_intel.php`, `web_dashboard/darkintel.php`
- Infraestructura: `docker-compose.yml`, `backend/Dockerfile`, `backend/requirements.txt`
