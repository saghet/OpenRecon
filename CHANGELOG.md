# CHANGELOG — REGISTRO DE CAMBIOS Y EVOLUCIÓN DE OPENRECON

Todas las modificaciones notables realizadas en el proyecto OpenRecon se documentan en este archivo.
El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y se adhiere a [Semantic Versioning](https://semver.org/).

---

## [3.0.0-alpha] — 2026-11-14
### 🛡️ Hardening P0, Consolidación Arquitectónica, GitHub/Web Intel, STIX/TAXII y Motor Anti-FP

#### Añadido (Added)
- **Seguridad Crítica P0:**
  - `backend/app/core/tls_config.py`: Verificación TLS 1.2+ obligatoria, gestión de CA bundle (`CUSTOM_CA_BUNDLE`) y detección de certificados inválidos/expirados.
  - `backend/app/core/auth.py`: Autenticación por token (`X-OpenRecon-Token` / `Bearer`) en rutas críticas (`/api/v1/security/kill-switch/*`, `/api/v1/scans/*`).
  - `SecretRedactingFilter` y `sanitize_evidence_payload()` en `backend/app/core/evidence_sanitizer.py` para redacción automática de secretos en evidencias y logs.
  - Kill-Switch distribuido en `backend/app/core/security_guard.py` (Redis + persistencia SQL) con control de tareas distribuidas y protección Anti-DNS-Rebinding / redirecciones.
- **Arquitectura & Observabilidad:**
  - Migraciones versionadas con Alembic (`backend/alembic/`) y endurecimiento de `database.py` (PostgreSQL pooling + SQLite WAL/FK + `enforce_org_isolation()`).
  - Arquitectura estándar de conectores (`backend/app/services/connectors/`) y motor central de evidencias (`backend/app/services/evidence/manager.py`).
  - Observabilidad (`backend/app/core/observability.py`): `CorrelationIdMiddleware`, `JsonLogFormatter` y endpoint Prometheus `GET /metrics`.
- **Inteligencia, CTI y Anti-Falsos Positivos:**
  - `EmailVerificationClassifier`, `GitHubIntelConnector`, `WebSecurityAnalyzer`, `STIX21TaxiiService`, `VulnIntelEnrichmentService` y `AntiFalsePositiveEngine` (8 etapas con guardrail estricto sobre IA).
  - Acceso directo en `web_dashboard/domain_intel.php` para configurar la API Key cifrada de **VirusTotal** ante `KEY_NOT_CONFIGURED`, con feedback visual, invalidación automática de caché de investigaciones previas al guardar credenciales en `POST /api/v1/domain-intel/credentials` y re-consulta automática del objetivo activo.
- **Documentación y Suites de Pruebas:**
  - `docs/AUDIT_OPENRECON_3.md`, `docs/SECURITY_HARDENING_REPORT.md`, `docs/ARCHITECTURE_REVIEW.md`, `docs/EMAIL_INTELLIGENCE_REVIEW.md`, `docs/CTI_AND_CORRELATION_REVIEW.md`, `docs/ANTI_FALSE_POSITIVE_STRATEGY.md`, `docs/OPENRECON_QA_STRATEGY.md`, `docs/THIRD_PARTY_LICENSE_AUDIT.md`, `docs/OPENRECON_3_ROADMAP.md`.
  - Nuevas suites: `tests/security/test_p0_security_hardening.py`, `tests/integration/test_phase2_architecture.py`, `tests/integration/test_phase3_intelligence.py`, `tests/integration/test_phase4_cti_and_afp.py`, `tests/e2e/test_e2e_workflows_and_performance.py`.

#### Corregido (Fixed)
- Eliminados todos los bypasses TLS (`verify=False`, `CERT_NONE`, `CURLOPT_SSL_VERIFYPEER=false`) en backend Python y gateway PHP.
- Corregido CORS comodín con credenciales en `backend/app/main.py` y corregida instalación de binarios ProjectDiscovery en `backend/Dockerfile`.

---

## [2.1.0] — 2026-11-14
### 🔍 Expansión OSINT: Domain Intelligence, Email Intelligence, LoginRecon AI & PHP2Shell

#### Añadido (Added)
- **Módulo Domain Intelligence (`backend/app/services/domain_intel/`, `web_dashboard/domain_intel.php`):**
  - Pipeline OSINT & CTI bajo alcance estricto de semillas autorizadas (RoE), con vista filtrada por semilla individual o consolidada.
  - Integración de adaptadores **WebOSINT**, **WhoisXML API** (con reglas de riesgo específicas), **HackerTarget Reverse IP** (con protección *shared-hosting guard*), verificación de seguridad DNS, **EPSS / CISA KEV** y correlación con **Email Intelligence**.
  - Configuración de claves API desde UI y modal de grafo de correlación CTI interactivo a pantalla completa con filtros e inspector de nodos.
- **Módulo Email Intelligence (`backend/app/services/email_intel/`, `web_dashboard/email_intel.php`):**
  - Motor OSINT basado en **Zehef**, worker con polling en tiempo real y persistencia forense.
  - Integración oficial de la API **XposedOrNot v1** en `LeakSearcher`, `RiskScorer` y UI, con caché TTL, endpoint `domain-breaches` y detección de diferencias históricas (*historical diff*).
  - Grafo relacional interactivo con modo paneo manual (*hand pan*), zoom, expansión a pantalla completa, filtros e inspector.
- **LoginRecon & Correlación Visual IA:**
  - Expansión de superficie de reconocimiento a **100 plataformas** (incluyendo redes sociales, creadores, citas y canales de huella digital).
  - Motor de correlación cruzada **Facebook AI** mediante visión por computadora (**pHash** y **SIFT**).
- **Escáner PHP2Shell (`CVE-2026-109618` / `CVE-2026-109619`):**
  - Integración del verificador PHP2Shell en la consola web junto a LoginRecon.
- **Hardening Dark Web & DRP:**
  - Herencia de dominio apex en DRP y Dark Web Watchdog, junto con el **Generador de Avisos de Incidente CSIRT**.
- **Operación Transparente XAMPP/Apache (`web_dashboard/backend_autostart.php`):**
  - Auto-arranque transparente del microservicio FastAPI desde el dashboard PHP.
- **Nuevas Suites de Pruebas:**
  - `tests/test_domain_intel_phase1.py`, `tests/test_domain_intel_suite.py`, `tests/test_domain_intel_webosint.py`, `tests/test_email_intel_suite.py`, `tests/test_xposedornot_integration.py`, `tests/test_email_intel_api.php`.

#### Modificado (Changed)
- **`README.md`:** Actualización integral de la documentación principal del proyecto en GitHub reflejando todas las capacidades implementadas (EASM, Validación Forense 5 Estados, Domain/Email Intelligence, DRP/LoginRecon, Dark Web/CTI, Grafo 8 Niveles, Risk Engine, RoE/Kill-Switch y Consola SOC).

---

## [2.0.0] — 2026-11-11
### 🛡️ Evolución a Plataforma Integral de Ciberinteligencia (EASM + DRP + CTI)

#### Añadido (Added)
- **Cliente e Integración Desacoplada OpenCTI (`backend/app/services/cti/opencti_client.py`):**
  - Soporte de comunicación con API GraphQL de OpenCTI.
  - Sincronización de indicadores STIX 2.1, perfiles de actores de amenazas y campañas.
  - Conversor nativo a bundles `STIX 2.1 Bundle` conteniendo objetos `Identity`, `Indicator` y `Vulnerability`.
  - Tolerancia a fallos: conmutación transparente a modo local `DEGRADED_LOCAL` sin interrupción de escaneos si OpenCTI está desconectado.
- **Colector Defensivo Dark Web & Ransomware (`backend/app/services/cti/darkweb_collector.py`):**
  - Ingesta y seguimiento de sitios de divulgación de ransomware (DLS) en tiempo real.
  - Correlación algorítmica de víctimas anunciadas contra semillas corporativas de la organización.
  - Generación de hashes criptográficos SHA-256 para trazabilidad inmutable de evidencias.
  - Protocolo de seguridad estricto: transporte seguro vía proxy Tor SOCKS5, prohibición de descarga de dumps y preservación de k-anonimato en credenciales.
- **Conector MISP (`backend/app/services/cti/misp_client.py`):**
  - Consulta de atributos e indicadores de compromiso mediante endpoint REST de búsqueda con respeto estricto de warninglists.
- **Adaptadores Unificados de Feeds CTI (`backend/app/services/cti/feed_adapters.py`):**
  - Conectores para AbuseIPDB, URLhaus y ThreatFox con enriquecimiento multiconector de dominios e IPs.
- **Motor de Correlación Multidimensional de Grafos (`backend/app/services/correlation/graph_engine.py`):**
  - Modelado de grafo dirigido de 8 niveles: `Organización -> Dominio -> Subdominio -> IP -> Puerto -> Servicio -> Tecnología -> CVE -> IoC -> Amenaza -> Actor`.
  - Ponderación de confianza de aristas (0-100%) y algoritmo BFS de trazado de rutas de ataque (Attack Path Tracing).
- **Motor Inteligente de Riesgo Explicable (`backend/app/services/risk/risk_engine.py`):**
  - Fórmula matemática multicriterio que combina CVSS v3.1, percentil EPSS, presencia en CISA KEV, nivel de exposición perimetral y amenazas de ransomware.
  - Multiplicadores dinámicos según el estado de validación forense y garantía de 0 puntos para falsos positivos comprobados.
- **Gobernanza RoE, Anti-SSRF y Parada de Emergencia (`backend/app/core/security_guard.py`):**
  - Escudo contra SSRF bloqueando loopback, RFC 1918, link-local y metadatos de nubes (169.254.169.254).
  - Verificador de pertenencia a lista blanca `authorized_scope`.
  - Interruptor global de parada de emergencia (Kill-Switch) en memoria y base de datos con bitácora en `audit_logs`.
- **Nuevos Endpoints en Microservicio FastAPI (`backend/app/api/v1/router.py`):**
  - `/api/v1/opencti` (health, indicators, threat-actors, correlate, export-stix).
  - `/api/v1/darkweb` (leaks, groups, correlate-seeds, mask-credential).
  - `/api/v1/cti` (enrich IP/domain, misp health/iocs).
  - `/api/v1/correlation` (graph, attack-paths).
  - `/api/v1/risk` (calculate, organization-posture).
  - `/api/v1/security` (kill-switch check/trigger/reset, validate-target).
  - Total de rutas OpenAPI incrementadas de 12 a **32 rutas documentadas**.
- **Nuevas Acciones en API Gateway PHP (`web_dashboard/api.php`):**
  - `opencti_status`, `opencti_sync`, `opencti_export_stix`.
  - `darkweb_get_leaks`, `darkweb_correlate`.
  - `get_kill_switch`, `trigger_kill_switch`, `reset_kill_switch`.
  - `get_mitre_matrix`, `get_campaigns`.
- **Evolución del SOC Dashboard a 15 Módulos Especializados (`web_dashboard/index.php`):**
  - Botón interactivo de Parada de Emergencia en la barra superior (`RO-GUARD: NORMAL` / `KILL-SWITCH: ACTIVO`).
  - Módulo 8: Matriz MITRE ATT&CK Enterprise Navigator interactiva.
  - Módulo 9: Centro de Gestión de IoCs con búsqueda, filtrado y exportación STIX 2.1.
  - Módulo 10: Telemetría de Ransomware y Grupos de Extorsión.
  - Módulo 11: Desglose Explicable de Riesgo y Ponderación de Criterios.
  - Módulo 13: Centro de Generación de Reportes y Descarga de Bundles STIX.
- **Ampliación de la Suite de Pruebas Automatizadas:**
  - `tests/test_stage5_opencti_and_darkweb.py` (5 pruebas).
  - `tests/test_stage6_correlation_and_risk.py` (5 pruebas).
  - `tests/test_stage7_security_and_governance.py` (3 pruebas).
  - Cobertura total de **40 pruebas en Python** y suite forense PHP con 100% de éxito.
- **Entregables de Documentación Maestra:**
  - `AUDITORIA_TECNICA_OPENRECON.md`
  - `ARQUITECTURA_OPENRECON.md`
  - `ROADMAP_OPENRECON.md`
  - `MATRIZ_DE_FUNCIONALIDADES.md`
  - `INTEGRACIONES_CTI.md`
  - `MODELO_DE_SEGURIDAD.md`
  - `PLAN_DE_PRUEBAS.md`

#### Modificado (Changed)
- **Normalización de Semillas en Colector Dark Web:** Mejora del algoritmo de coincidencia de víctimas para soportar nombres corporativos compuestos con espacios y guiones.
- **`web_dashboard/index.php`:** Actualización de `switchTab` y `FORTI_MODULE_META` para gestionar los 15 módulos con scroll automático al tope del viewport.

#### Corregido (Fixed)
- Erradicación de excepciones no controladas cuando servicios externos de CTI se encuentran fuera de línea.
- Garantía de no persistencia de contraseñas en claro durante la ingesta de credenciales expuestas.

---

## [1.5.0] — 2026-11-10
### 🔬 Motor de Validación Forense Perimetral & Anti-Falsos Positivos
- Implementación de `vuln_validator_engine.php` con 5 estados de validación: `VALIDADA`, `PROBABLE`, `POTENCIAL`, `INFO_INSUFICIENTE` y `FALSO_POSITIVO`.
- Detección de bloqueos nativos 403 en balanceadores de Azure App Service y Cloudflare.
- Validación de redirección forzada a HTTPS en puerto 80 y reglas de no explotabilidad de CORS W3C.
- Incorporación del catálogo local de 1,779 vulnerabilidades activamente explotadas de CISA KEV y percentiles EPSS.
- Purga completa de datos simulados y mocks en `openrecon.sqlite`.
- Creación de 11 índices de rendimiento optimizados en base de datos SQLite.

---

## [1.0.0] — 2026-10-24
### 🚀 Lanzamiento Inicial de OpenRecon
- Arquitectura base con microservicio FastAPI y dashboard PHP.
- Descubrimiento pasivo de subdominios (`crt.sh`) y sondeo de puertos perimetrales.
- Módulo de typosquatting y homóglifos DRP.
- Despliegue con Docker Compose (FastAPI, PostgreSQL 16, Redis 7).
