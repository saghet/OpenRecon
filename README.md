# OpenRecon 3.0 🛡️

> **Plataforma Open Source Integral de Gestión de Superficie de Ataque Externa (EASM), Protección Digital de Marca (DRP), OSINT y Ciberinteligencia de Amenazas (CTI)**  
> *Alternativa abierta y auto-hospedable inspirada en Fortinet FortiRecon, Recorded Future, Palo Alto Cortex Xpanse y CrowdStrike Falcon Exposure Management.*

---

## 🌟 Características Implementadas (v3.0.0-alpha)

OpenRecon unifica en una arquitectura modular (**FastAPI + PostgreSQL/SQLite + Redis + Consola SOC PHP**) las capacidades clave de ciberseguridad defensiva perimetral, validación forense anti-falsos positivos e inteligencia de amenazas:

### 1. 🌐 EASM (External Attack Surface Management)
* **Descubrimiento de Activos y Subdominios:** Enumeración pasiva y activa (`subfinder`, `crt.sh`, logs de transparencia de certificados) y resolución DNS (`dnspython`, `dnsx`).
* **Mapeo Perimetral y Fingerprinting:** Sondeo no destructivo de puertos (`naabu`, sockets asíncronos), detección de servicios críticos expuestos (MySQL, Redis, PostgreSQL, MongoDB, RDP, FTP), tecnologías web y estado de certificados SSL/TLS.
* **Validación de Vulnerabilidades:** Integración con `Nuclei` y escáner específico **PHP2Shell** (`CVE-2026-109618` / `CVE-2026-109619`).

### 2. 🔬 Motor de Validación Forense & Anti-Falsos Positivos (8 Etapas)
* **`AntiFalsePositiveEngine` (`backend/app/services/validation/`):** Pipeline determinista de 8 etapas (evidencia técnica, contexto HTTP/WAF, validación de versiones, correlación de infraestructura, deduplicación, *guardrail* estricto sobre IA para evitar alucinaciones y degradación de confianza sin confirmación).
* **`vuln_validator_engine.php`:** Clasifica hallazgos en 5 estados verificables (`VALIDADA`, `PROBABLE`, `POTENCIAL`, `INFO_INSUFICIENTE`, `FALSO_POSITIVO`), con detección nativa de bloqueos WAF/balanceadores (Azure App Service, Cloudflare) y reglas CORS W3C.
* **Priorización con Inteligencia Real (`VulnIntelEnrichmentService`):** Catálogo **CISA KEV** (CVEs activamente explotados), percentiles **EPSS** en vivo y enriquecimiento CVSS/CPE.

### 3. 🔍 Domain Intelligence, GitHub Intel & Web Security
* **Módulo Especializado (`domain_intel.php` / `/api/v1/domain-intel`):** Análisis OSINT y CTI restringido estrictamente a semillas autorizadas (RoE) con **configuración directa de API Keys cifradas (Fernet)** — incluyendo acceso rápido desde el panel de **VirusTotal** e invalidación automática de caché al actualizar credenciales.
* **Adaptadores y Conectores:** Integración con **VirusTotal**, **AlienVault OTX**, **WebOSINT**, **WhoisXML API**, **HackerTarget Reverse IP** (con protección *shared-hosting guard*), **Cert Spotter**, seguridad DNS, **EPSS / CISA KEV** y correlación cruzada con **Email Intelligence**.
* **GitHub & Web Security Intel:** `GitHubIntelConnector` (detección pasiva de secretos potenciales/revocados sin uso de credenciales) y `WebSecurityAnalyzer` (evaluación de cabeceras CSP, HSTS, X-Frame-Options, cookies y postura TLS).
* **Visualización Interactiva:** Modal de grafo de correlación CTI a pantalla completa con paleta SOC, filtros dinámicos e inspector de nodos.

### 4. 📧 Email Intelligence (OSINT & Brechas)
* **Módulo Especializado (`email_intel.php` / `/api/v1/email-intel`):** Descubrimiento y análisis de exposición de identidades corporativas basado en **Zehef OSINT** y worker con polling en tiempo real.
* **Integración Oficial XposedOrNot v1:** Búsqueda de brechas por correo y dominio con caché TTL, detección de diferencias históricas (*historical diff*) y puntuación de riesgo automatizada.
* **Grafo Relacional Interactivo:** Modo paneo manual (*hand pan*), zoom, expansión a pantalla completa, filtros e inspector forense.

### 5. 🛡️ DRP (Digital Risk Protection) & LoginRecon
* **Detección de Typosquatting y Homóglifos:** Generación de permutaciones sospechosas, herencia de dominio apex y verificación en tiempo real de registros DNS y MX para detectar phishing activo.
* **LoginRecon & Visión por Computadora:** Cobertura de **100 plataformas** (redes sociales, creadores, citas y canales de huella digital) con motor de correlación cruzada **Facebook AI** usando verificación visual (**pHash** y **SIFT**).

### 6. 🕶️ CTI, Dark Web & Ransomware Intelligence
* **Dark Web Watchdog (`darkintel.php` / `/api/v1/darkweb`, `/api/v1/darkintel`):** Ingesta defensiva vía proxy **Tor SOCKS5** (Ahmia, catálogos DeepDark, sitios de divulgación de ransomware DLS), correlación con dominios apex/semillas corporativas, trazabilidad con hashes **SHA-256**, manejo seguro de credenciales (*k-anonimato*, sin almacenamiento en claro) y **Generador de Avisos de Incidente CSIRT**.
* **Conectores OpenCTI & MISP:** Sincronización GraphQL con **OpenCTI** (con degradación transparente a modo local `DEGRADED_LOCAL`), exportación nativa de bundles **STIX 2.1**, conector **MISP** y feeds **AbuseIPDB**, **URLhaus** y **ThreatFox**.

### 7. 🧠 Grafo Multidimensional, Risk Scoring Explicable & IA
* **Motor de Correlación de Grafos (`graph_engine.py`):** Grafo dirigido de 8 niveles (`Organización -> Dominio -> Subdominio -> IP -> Puerto -> Servicio -> Tecnología -> CVE -> IoC -> Amenaza -> Actor`) con ponderación de confianza y trazado de rutas de ataque (*Attack Path Tracing* vía BFS).
* **Risk Engine Explicable (`risk_engine.py`):** Fórmula multicriterio transparente (CVSS v3.1 + EPSS + CISA KEV + exposición perimetral + ransomware) con **riesgo 0 garantizado** para falsos positivos confirmados.
* **Soporte IA (`deepseek_engine.py`):** Asistencia de análisis y correlación CTI.

### 8. 🔒 Hardening P0, Gobernanza RoE, Observabilidad & Consola SOC Unificada
* **Seguridad Crítica P0:** Validación TLS 1.2+ obligatoria sin bypasses (`tls_config.py`), autenticación por token (`auth.py` con `X-OpenRecon-Token` / `Bearer`), sanitización y redacción automática de secretos (`evidence_sanitizer.py` + `SecretRedactingFilter`), escudo **Anti-SSRF / Anti-DNS-Rebinding** y **Kill-Switch distribuido** (Redis + persistencia SQL) con bitácora en `audit_logs`.
* **Arquitectura Estándar & Observabilidad:** Migraciones versionadas con **Alembic**, framework uniforme de conectores (`BaseConnector`), `EvidenceManager` centralizado con historial de cambios, `CorrelationIdMiddleware`, logs JSON estructurados y métricas **Prometheus** (`GET /metrics`).
* **Consola SOC Web (`web_dashboard/index.php`):** 15+ módulos integrados con **auto-arranque transparente de FastAPI** bajo XAMPP/Apache (`backend_autostart.php`).

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

El repositorio incluye pruebas unitarias, de seguridad, integración, E2E y validación forense en `tests/`:
* **Seguridad P0, Arquitectura, Inteligencia, CTI y E2E (OpenRecon 3.0):** `tests/security/test_p0_security_hardening.py`, `tests/integration/test_phase2_architecture.py`, `tests/integration/test_phase3_intelligence.py`, `tests/integration/test_phase4_cti_and_afp.py`, `tests/e2e/test_e2e_workflows_and_performance.py`
* **Seguridad, Core, Enterprise y Consolidación:** `test_stage1_security.py` a `test_stage4_consolidation.py`
* **Domain Intelligence:** `test_domain_intel_phase1.py`, `test_domain_intel_suite.py`, `test_domain_intel_webosint.py`
* **Email Intelligence & XposedOrNot:** `test_email_intel_suite.py`, `test_xposedornot_integration.py`, `test_email_intel_api.php`
* **Gateway y Validación Forense PHP:** `test_php_gateway_suite.py`, `test_vuln_validator_suite.php`

```bash
python -m unittest tests/security/test_p0_security_hardening.py tests/integration/test_phase2_architecture.py tests/integration/test_phase3_intelligence.py tests/integration/test_phase4_cti_and_afp.py tests/e2e/test_e2e_workflows_and_performance.py -v
```

---

## 📚 Documentación Técnica Adicional

* [CHANGELOG.md](CHANGELOG.md) — Historial detallado de versiones y cambios.
* [docs/AUDIT_OPENRECON_3.md](docs/AUDIT_OPENRECON_3.md) — Auditoría técnica completa de OpenRecon 3.0.
* [docs/SECURITY_HARDENING_REPORT.md](docs/SECURITY_HARDENING_REPORT.md) — Reporte de endurecimiento P0 (TLS, secretos, RoE/SSRF, Kill-Switch).
* [docs/ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md) — Consolidación de persistencia, conectores, evidencias y observabilidad.
* [docs/OPENRECON_3_ROADMAP.md](docs/OPENRECON_3_ROADMAP.md) & [docs/OPENRECON_QA_STRATEGY.md](docs/OPENRECON_QA_STRATEGY.md) — Hoja de ruta y estrategia de QA.
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
