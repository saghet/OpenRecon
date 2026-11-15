# OpenRecon 3.0 🛡️

> **Plataforma Open Source Integral de Gestión de Superficie de Ataque Externa (EASM), Protección Digital de Marca (DRP), OSINT y Ciberinteligencia de Amenazas (CTI)**  
> *Alternativa abierta y auto-hospedable inspirada en Fortinet FortiRecon, Recorded Future, Palo Alto Cortex Xpanse y CrowdStrike Falcon Exposure Management.*

---

## 🌟 Características Implementadas (v3.0.0-alpha)

OpenRecon unifica en una arquitectura modular (**FastAPI + PostgreSQL/SQLite + Redis + Consola SOC PHP**) las capacidades clave de ciberseguridad defensiva perimetral, validación forense anti-falsos positivos e inteligencia de amenazas:

### 1. 🌐 EASM (External Attack Surface Management)
* **Descubrimiento de Activos y Subdominios (`DNSEngine`):** Ejecución asíncrona no bloqueante, enumeración pasiva y activa (`subfinder -json`, `amass -passive`, `crt.sh`), detección y eliminación automática de **Wildcard DNS** y preservación de procedencia (`dnspython`, `dnsx`).
* **Mapeo Perimetral y Fingerprinting (`HTTPEngine`, `PortEngine`):** Sondeo TCP no destructivo (`naabu -s c`, sockets asíncronos), fingerprinting HTTP/TLS/tecnologías (`httpx` JSONL), detección de servicios críticos expuestos (MySQL, Redis, PostgreSQL, MongoDB, RDP, FTP) y estado de certificados SSL/TLS.
* **Validación de Vulnerabilidades (`NucleiEngine`):** Integración con **Nuclei v3** (`-jsonl`) con exclusión automática de tags destructivos (`-etags dos,fuzz,intrusive,bruteforce`), captura de evidencia HTTP sanitizada y escáner específico **PHP2Shell** (`CVE-2026-109618` / `CVE-2026-109619`).

### 2. 🔬 Contrato Único de Hallazgos, Validación Forense & Anti-Falsos Positivos
* **Contrato Único y Deduplicación (`finding_contract.py`):** Esquema `NormalizedFinding` y `GlobalFindingDeduplicator` con `fingerprint` **SHA-256 determinista** que conserva evidencias independientes de múltiples fuentes, integrado en `AntiFalsePositiveEngine` y `ScannerOrchestrator`.
* **`AntiFalsePositiveEngine` (`backend/app/services/validation/`):** Pipeline determinista de 8 etapas (evidencia técnica, contexto HTTP/WAF, validación de versiones, correlación de infraestructura, deduplicación, *guardrail* estricto sobre IA para evitar alucinaciones y degradación de confianza sin confirmación).
* **`vuln_validator_engine.php`:** Clasifica hallazgos en 5 estados verificables (`VALIDADA`, `PROBABLE`, `POTENCIAL`, `INFO_INSUFICIENTE`, `FALSO_POSITIVO`), con detección nativa de bloqueos WAF/balanceadores (Azure App Service, Cloudflare) y reglas CORS W3C.
* **Priorización con Inteligencia Real (`VulnIntelEnrichmentService`):** Catálogo **CISA KEV** (CVEs activamente explotados), percentiles **EPSS** en vivo, enriquecimiento **CISA Vulnrichment** (**SSVC** / CWE / CVSS) y trazabilidad de `missing_signals` y `data_completeness` en `IntelligentRiskEngine`.

### 3. 🔍 Domain Intelligence, GitHub Intel & Web Security
* **Módulo Especializado (`domain_intel.php` / `/api/v1/domain-intel`):** Análisis OSINT y CTI restringido estrictamente a semillas autorizadas (RoE) con **configuración directa de API Keys cifradas (Fernet)** — incluyendo acceso rápido desde el panel de **VirusTotal** e invalidación automática de caché al actualizar credenciales.
* **Adaptadores y Conectores:** Integración con **VirusTotal**, **AlienVault OTX**, **WebOSINT**, **WhoisXML API**, **HackerTarget Reverse IP** (con protección *shared-hosting guard*), **Cert Spotter**, seguridad DNS, **EPSS / CISA KEV** y correlación cruzada con **Email Intelligence**.
* **GitHub, Secretos & Web Security Intel:** `GitHubIntelConnector` y endpoint protegido `POST /api/v1/exposures/secrets/scan` con **Gitleaks** en sandbox (protección contra *path traversal*), además de `WebSecurityAnalyzer` (cabeceras CSP, HSTS, X-Frame-Options, cookies y postura TLS).
* **Visualización Interactiva:** Modal de grafo de correlación CTI a pantalla completa con paleta SOC, filtros dinámicos e inspector de nodos.

### 4. 📧 Email Intelligence (OSINT & Brechas)
* **Módulo Especializado (`email_intel.php` / `/api/v1/email-intel`):** Descubrimiento y análisis de exposición de identidades corporativas basado en **Zehef OSINT**, sanitización obligatoria en `PasteSearcher` y worker con polling en tiempo real.
* **Integración Oficial XposedOrNot v1:** Búsqueda de brechas por correo y dominio con caché TTL, detección de diferencias históricas (*historical diff*) y puntuación de riesgo automatizada.
* **Grafo Relacional Interactivo:** Modo paneo manual (*hand pan*), zoom, expansión a pantalla completa, filtros e inspector forense.

### 5. 🛡️ DRP (Digital Risk Protection) & LoginRecon
* **Detección de Typosquatting y Homóglifos (`DRPEngine`):** Integración con **dnstwist** + **IDN punycode**, herencia de dominio apex y evaluación multi-señal en tiempo real (registros DNS, MX y heurísticas anti-phishing).
* **LoginRecon & Visión por Computadora:** Cobertura de **100 plataformas** (redes sociales, creadores, citas y canales de huella digital) con motor de correlación cruzada **Facebook AI** usando verificación visual (**pHash** y **SIFT**).

### 6. 🕶️ CTI, Dark Web & Ransomware Intelligence
* **Dark Web Watchdog (`darkintel.php` / `/api/v1/darkweb`, `/api/v1/darkintel`):** Ingesta defensiva vía proxy **Tor SOCKS5** (Ahmia, catálogos DeepDark, sitios de divulgación de ransomware DLS), correlación con dominios apex/semillas corporativas, trazabilidad con hashes **SHA-256**, manejo seguro de credenciales (*k-anonimato*, sin almacenamiento en claro) y **Generador de Avisos de Incidente CSIRT**.
* **Conectores OpenCTI, MISP & MISP Galaxy:** Sincronización GraphQL con **OpenCTI** (con degradación transparente a modo local `DEGRADED_LOCAL`), exportación nativa de bundles **STIX 2.1**, conector **MISP**, servicio **`MISPGalaxyService`** con índice local versionado y aristas con evidencia en `CorrelationGraphEngine`, y feeds **AbuseIPDB**, **URLhaus** y **ThreatFox**.

### 7. 🧠 Grafo Multidimensional, Risk Scoring Explicable & IA
* **Motor de Correlación de Grafos (`graph_engine.py`):** Grafo dirigido de 8 niveles (`Organización -> Dominio -> Subdominio -> IP -> Puerto -> Servicio -> Tecnología -> CVE -> IoC -> Amenaza -> Actor`) con ponderación de confianza y trazado de rutas de ataque (*Attack Path Tracing* vía BFS).
* **Risk Engine Explicable (`risk_engine.py`):** Fórmula multicriterio transparente (CVSS v3.1 + EPSS + CISA KEV + CISA Vulnrichment SSVC + exposición perimetral + ransomware) con trazabilidad de `missing_signals` / `data_completeness` y **riesgo 0 garantizado** para falsos positivos confirmados.
* **Soporte IA (`deepseek_engine.py`):** Asistencia de análisis y correlación CTI.

### 8. 🔒 Hardening P0/P1/P2, Resiliencia, Strangler Pattern & Docker Hardened
* **Seguridad Crítica y Autenticación Global:** Validación TLS 1.2+ obligatoria sin bypasses (`tls_config.py`), autenticación global `Depends(require_api_token)` aplicada a los **13 routers** bajo `/api/v1/*`, sanitización automática de secretos (`evidence_sanitizer.py` + `SecretRedactingFilter`), escudo **Anti-SSRF / Anti-DNS-Rebinding** y **Kill-Switch distribuido** (Redis + SQL) con detención real de tareas `asyncio` y subprocesos.
* **Resiliencia & Observabilidad:** Migraciones versionadas con **Alembic**, `BaseConnector` y `DomainIntelligenceService` con **reintentos, backoff exponencial, Circuit Breaker y métricas Prometheus** (`GET /metrics`), `EvidenceManager` centralizado, `CorrelationIdMiddleware` y logs JSON estructurados.
* **Docker Hardened & Binarios Fijados (`backend/Dockerfile`):** Usuario no-root `openrecon`, `HEALTHCHECK`, `no-new-privileges:true`, red aislada `tor-sandbox-net` y binarios con verificación criptográfica **SHA-256** (`subfinder`, `dnsx`, `httpx`, `naabu`, `nuclei`, `gitleaks`, `dnstwist`).
* **Consola SOC Web (`web_dashboard/index.php`) & Strangler Pattern:** 15+ módulos integrados con **auto-arranque transparente de FastAPI** (`backend_autostart.php`) y migración progresiva en `web_dashboard/api.php` (Kill-Switch, Scan Stop, Domain/Email Intel enrutados a FastAPI).

---

## 🏗️ Arquitectura del Sistema

```text
OpenRecon/
├── backend/
│   ├── alembic/                    # Migraciones versionadas de base de datos (PostgreSQL / SQLite)
│   ├── app/
│   │   ├── api/v1/endpoints/       # 13+ routers REST (EASM, DRP, CTI, OpenCTI, DarkWeb, DomainIntel, EmailIntel, Risk, Security)
│   │   ├── core/                   # config, database, tls_config, auth, evidence_sanitizer, observability, security_guard
│   │   ├── models/                 # Modelos relacionales (Orgs, Assets, Ports, Vulns, DRP, Evidence, Scans, Audit)
│   │   ├── schemas/                # Esquemas Pydantic v2
│   │   ├── services/
│   │   │   ├── ai/                 # DeepSeek CTI correlation engine (con guardrail anti-alucinación)
│   │   │   ├── connectors/         # Arquitectura estándar BaseConnector y registro de proveedores
│   │   │   ├── correlation/        # Grafo multidimensional de 8 niveles y Attack Path Tracing
│   │   │   ├── cti/                # OpenCTI, MISP, DarkWeb/Tor, STIX 2.1 / TAXII, KEV/EPSS, AbuseIPDB, URLhaus, ThreatFox
│   │   │   ├── domain_intel/       # VirusTotal, OTX, WebOSINT, WhoisXML, HackerTarget, CertSpotter, EmailIntel/KEV/EPSS
│   │   │   ├── email_intel/        # Zehef OSINT, XposedOrNot v1, clasificador de confianza, paste/account searchers
│   │   │   ├── engines/            # Motores base (DNS, HTTP, Port, DRP Typosquatting, Nuclei)
│   │   │   ├── evidence/           # EvidenceManager centralizado con auditoría y sanitización
│   │   │   ├── github_intel/       # Detección de exposición de secretos en GitHub
│   │   │   ├── risk/               # Motor de scoring explicable multicriterio
│   │   │   ├── validation/         # AntiFalsePositiveEngine (8 etapas)
│   │   │   ├── web_security/       # Analizador de cabeceras de seguridad, cookies y TLS
│   │   │   └── scanner_orchestrator.py
│   │   └── main.py                 # FastAPI + OpenAPI + Prometheus /metrics
│   ├── requirements.txt
│   └── Dockerfile
├── docs/                           # Auditoría OpenRecon 3.0, reportes P0, arquitectura, QA y roadmap
├── web_dashboard/                  # Consola SOC PHP + API Gateway + Auto-start FastAPI
│   ├── index.php                   # Dashboard SOC unificado (15+ módulos)
│   ├── domain_intel.php            # UI Domain Intelligence, gestor de API Keys cifradas y grafo CTI
│   ├── email_intel.php             # UI Email Intelligence & grafo relacional
│   ├── darkintel.php               # UI Dark Web & Ransomware Watchdog
│   ├── vuln_validator_engine.php   # Motor forense anti-falsos positivos (5 estados)
│   ├── api.php                     # Gateway PHP hacia SQLite y microservicio FastAPI
│   ├── backend_autostart.php       # Arranque transparente de FastAPI con XAMPP/Apache
│   └── report.php                  # Generador de reportes ejecutivos y fichas CSIRT/Takedown
├── tests/                          # Suites security/, integration/, e2e/, Domain/Email Intel y PHP
├── docker-compose.yml              # Orquestación con PostgreSQL 16 y Redis 7
├── run_dev.py                      # Lanzador de desarrollo local
└── CHANGELOG.md / ROADMAP_OPENRECON.md / MATRIZ_DE_FUNCIONALIDADES.md
```

---

## 🚀 Despliegue Rápido

### Opción 1: Desarrollo Local (Python + Consola SOC PHP)
1. Crear y activar entorno virtual e instalar dependencias:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/Mac:
   source venv/bin/activate

   pip install -r backend/requirements.txt
   ```
2. Configurar variables de entorno copiando `.env.example` a `.env` (claves opcionales: WhoisXML, XposedOrNot, OpenCTI, MISP, AbuseIPDB, etc.).
3. Iniciar el backend FastAPI:
   ```bash
   python run_dev.py
   ```
   * Documentación interactiva Swagger/OpenAPI: `http://localhost:8000/docs`
4. Si utilizas **XAMPP/Apache**, abre `web_dashboard/index.php` en el navegador: `backend_autostart.php` gestionará el arranque transparente del backend FastAPI si no está activo.

### Opción 2: Contenedores con Docker Compose
```bash
docker compose up -d --build
```
Levanta automáticamente **PostgreSQL 16**, **Redis 7** y el contenedor de la API con binarios de escaneo (`subfinder`, `httpx`, `naabu`, `nuclei`).

---

## 🧪 Pruebas Automatizadas

El repositorio incluye pruebas unitarias, de seguridad, integración, E2E, benchmarks y validación forense en `tests/`:
* **Seguridad P0, Arquitectura, Inteligencia, CTI y E2E (OpenRecon 3.0):** `tests/security/test_p0_security_hardening.py`, `tests/integration/test_phase2_architecture.py`, `tests/integration/test_phase3_intelligence.py`, `tests/integration/test_phase4_cti_and_afp.py`, `tests/e2e/test_e2e_workflows_and_performance.py`
* **Cierre de Deuda P1/P2, Contrato Único y Benchmark Fase 5:** `tests/integration/test_master_improvement_program.py`, `tests/integration/test_p1_p2_debt_closure.py`, `tests/integration/test_phase5_metrics_benchmark.py`
* **Seguridad, Core, Enterprise y Consolidación:** `test_stage1_security.py` a `test_stage4_consolidation.py`
* **Domain Intelligence:** `test_domain_intel_phase1.py`, `test_domain_intel_suite.py`, `test_domain_intel_webosint.py`
* **Email Intelligence & XposedOrNot:** `test_email_intel_suite.py`, `test_xposedornot_integration.py`, `test_email_intel_api.php`
* **Gateway y Validación Forense PHP:** `test_php_gateway_suite.py`, `test_vuln_validator_suite.php`

```bash
python -m unittest tests/security/test_p0_security_hardening.py tests/integration/test_phase2_architecture.py tests/integration/test_phase3_intelligence.py tests/integration/test_phase4_cti_and_afp.py tests/integration/test_master_improvement_program.py tests/integration/test_p1_p2_debt_closure.py tests/integration/test_phase5_metrics_benchmark.py tests/e2e/test_e2e_workflows_and_performance.py -v
```

---

## 📚 Documentación Técnica Adicional

* [CHANGELOG.md](CHANGELOG.md) — Historial detallado de versiones y cambios.
* [PLAN_DE_TRABAJO_OPENRECON.md](PLAN_DE_TRABAJO_OPENRECON.md) — Plan de trabajo maestro, hitos completados y próximos pasos hacia 3.0.0 GA.
* [docs/OPENRECON_3_ROADMAP.md](docs/OPENRECON_3_ROADMAP.md) & [docs/OPENRECON_QA_STRATEGY.md](docs/OPENRECON_QA_STRATEGY.md) — Hoja de ruta y estrategia de QA.
* [docs/STRANGLER_MIGRATION_MATRIX.md](docs/STRANGLER_MIGRATION_MATRIX.md) — Matriz de migración Strangler Pattern (`web_dashboard/api.php` → FastAPI).
* [docs/BINARIES_AND_DOCKER.md](docs/BINARIES_AND_DOCKER.md) — Binarios fijados con SHA-256, hardening Docker y política de actualización.
* [docs/AUDIT_OPENRECON_3.md](docs/AUDIT_OPENRECON_3.md) — Auditoría técnica completa de OpenRecon 3.0.
* [docs/SECURITY_HARDENING_REPORT.md](docs/SECURITY_HARDENING_REPORT.md) — Reporte de endurecimiento P0 (TLS, secretos, RoE/SSRF, Kill-Switch).
* [docs/ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md) — Consolidación de persistencia, conectores, evidencias y observabilidad.
* [ARQUITECTURA_OPENRECON.md](ARQUITECTURA_OPENRECON.md) — Diseño técnico y flujo de datos.
* [MATRIZ_DE_FUNCIONALIDADES.md](MATRIZ_DE_FUNCIONALIDADES.md) — Comparativa frente a soluciones comerciales (FortiRecon, Recorded Future, Cortex Xpanse, etc.).
* [INTEGRACIONES_CTI.md](INTEGRACIONES_CTI.md) — Guía de conectores OSINT/CTI y STIX 2.1.
* [MODELO_DE_SEGURIDAD.md](MODELO_DE_SEGURIDAD.md) — Gobernanza RoE, Anti-SSRF y manejo seguro de credenciales.

---

## ⚖️ Seguridad y Ética

OpenRecon está diseñado bajo la premisa de **escaneo no intrusivo, autorizado y defensivo**:
* Control estricto de alcance mediante lista blanca de semillas (`authorized_scope` / RoE) y protección Anti-SSRF.
* Parada de emergencia global (*Kill-Switch*) con auditoría persistente.
* Manejo de credenciales expuestas bajo principios de **k-anonimato** y hashes criptográficos (sin persistencia de contraseñas en claro).
