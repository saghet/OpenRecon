# Integración Selectiva de WebCopilot en OpenRecon 3.0

## 1. Auditoría Previa de OpenRecon y WebCopilot

### Estado real verificado en OpenRecon (`main`)
- **Backend FastAPI & Orquestación:** `backend/app/main.py`, `backend/app/api/v1/router.py`, `backend/app/services/scanner_orchestrator.py`.
- **Motores existentes:**
  - `DNSEngine` (`backend/app/services/engines/dns_engine.py`): Subfinder JSON, Amass passive, `crt.sh`, eliminación de Wildcard DNS, `dnsx`/`dnspython`.
  - `PortEngine` (`backend/app/services/engines/port_engine.py`): `naabu -s c` (sin privilegios root) + fallback `asyncio`.
  - `HTTPEngine` (`backend/app/services/engines/http_engine.py`): ProjectDiscovery `httpx` JSONL + fallback Python `httpx` con TLS estricto y `WebSecurityAnalyzer`.
  - `NucleiEngine` (`backend/app/services/engines/nuclei_engine.py`): Nuclei v3 JSONL con `EXCLUDED_DANGEROUS_TAGS = "dos,fuzz,intrusive,bruteforce"`.
- **Gobernanza, Evidencia, Anti-FP y Riesgo:**
  - `SecurityGovernanceGuard` (`backend/app/core/security_guard.py`): RoE, Anti-SSRF (RFC 1918, loopback, link-local, CGNAT, metadata), Anti-DNS-Rebinding y Kill-Switch distribuido (Redis + SQL).
  - `AntiFalsePositiveEngine` (`backend/app/services/validation/anti_false_positive.py`) y `GlobalFindingDeduplicator` (`finding_contract.py`).
  - `EvidenceManager` (`backend/app/services/evidence/manager.py`) con SHA-256, firma de custodia y `EvidenceSanitizer`.
  - `IntelligentRiskEngine` (`backend/app/services/risk/risk_engine.py`).
- **Infraestructura:** Docker no-root (`USER openrecon` en `backend/Dockerfile`), PostgreSQL 16, Redis 7, sandbox Tor aislado.

### Auditoría del repositorio `h4r5h1t/webcopilot`
- **Licencia:** MIT License (Copyright 2021 Harshit Raj Singh).
- **Implementación:** Script monolítico Bash (`webcopilot`, 480 líneas) + `install.sh`.
- **Problemas críticos detectados en el código original:**
  - Exige ejecución como `root` (`id -u != 0`).
  - Múltiples vectores de *command injection* (`xargs ... bash -c "curl -s -L '%'..."` sin sanitización).
  - Uso de `--insecure` en `curl` (deshabilita validación TLS).
  - Errores en el propio script (`tem/lfi.txt`, `patterns/openredirect`, `domains/patterns/ssrf.txt`, llamada a función inexistente `sensitive`).
  - Ejecución automática agresiva de `sqlmap --risk 3 --level 5` y SSRF hacia `169.254.169.254` sin control de alcance ni Kill-Switch.

---

## 2. Matriz de Duplicaciones y Oportunidades

| Capacidad / Herramienta | Estado en OpenRecon | Decisión | Justificación |
| :--- | :--- | :--- | :--- |
| Subfinder, Amass, crt.sh, dnsx, httpx | **Implementado nativamente** | **Descartar de WebCopilot** | Evita duplicación; `WebCopilotAdapter` consume activos vivos de OpenRecon. |
| Assetfinder, Sublist3rV2, Findomain, Gobuster DNS | **Redundante / Obsoleto** | **No incorporar** | Redundantes frente a `DNSEngine` y con mayor tasa de falsos positivos. |
| Aquatone | **Obsoleto** | **No incorporar** | Dependencia pesada de Chromium sin integración con evidencia estructurada. |
| **GAU, WaybackURLs, Waymore** | **No implementado** | **Incorporar selectivamente** | Descubrimiento de endpoints históricos y parámetros ocultos (+ fallback CDX). |
| **GF Patterns, urldedupe/uro** | **No implementado** | **Implementar en Python (`url_normalizer.py`)** | Normalización determinista, deduplicación canónica y clasificación sin binarios inseguros. |
| **KXSS, Dalfox, OpenRedireX** | **No implementado** | **Incorporar vía `WebCopilotAdapter`** | Refuerzan detección de XSS reflejado/verificado y Open Redirect con validación Anti-FP. |
| **Nuclei** | **Implementado (`NucleiEngine`)** | **Reutilizar y enriquecer** | `NucleiEngine.scan_targets()` recibe URLs con parámetros descubiertas; `dos,fuzz,intrusive,bruteforce` excluidos por defecto. |
| **Interactsh (OOB / Blind XSS)** | **No implementado** | **Opcional (`False` por defecto)** | Política por organización (`WebOrgPolicy`), token protegido, requiere autorización explícita. |
| **SQLMap** | **No implementado** | **Opcional controlado (`False` por defecto)** | Solo bajo autorización de org + scan, flags no destructivos (`--level=1 --risk=1`), límites de tiempo y Kill-Switch. |

---

## 3. Revisión de los 8 Especialistas y Decisiones de Seguridad

1. **Arquitecto EASM:** Desacoplamiento en `WebCopilotAdapter` alimentado por `Asset` vivos; sin re-enumeración DNS.
2. **Especialista OWASP:** Mapeo CWE/OWASP 2021 (`CWE-79`, `CWE-89`, `CWE-601`, `CWE-918`, `CWE-22`, `CWE-78`, `CWE-93`).
3. **Pentester Senior:** `kxss` clasificado como `PROBABLE`; solo PoCs verificados (`dalfox` verificado, `openredirex_safe` con redirección `30x` a canario) pasan a `CONFIRMADO`.
4. **Ingeniero Python/FastAPI:** Ejecución asíncrona con `asyncio.create_subprocess_exec` (sin `shell=True`), semáforos de concurrencia y timeouts por herramienta.
5. **DevSecOps & Contenedores:** Sin privilegios `root`, sin `shell=True`, límites de concurrencia y aislamiento de fallos por herramienta en `WebScanExecution`.
6. **Normalización y Evidencia:** Ingesta unificada en `CandidateFinding` -> `AntiFalsePositiveEngine` -> `NormalizedFinding` -> `GlobalFindingDeduplicator` -> `EvidenceManager` -> `Vulnerability` -> `IntelligentRiskEngine`.
7. **Cadena de Suministro y Licencias:** Dependencias Python existentes (MIT/BSD/PSF); herramientas externas opcionales (`gau`, `waybackurls`, `waymore`, `kxss`, `dalfox` — todas MIT; `sqlmap` — GPLv2, opcional y deshabilitado por defecto).
8. **Reducción de Falsos Positivos:** Override de seguridad **Safe-by-Default**: ni plantillas intrusivas de Nuclei, ni Interactsh, ni SQLMap se ejecutan automáticamente sin autorización explícita en `WebOrgPolicy` y en la petición de escaneo; SQLMap bloquea técnicas destructivas o de modificación de datos.

---

## 4. Archivos Creados o Modificados

- **Creados:**
  - `backend/app/models/web_recon.py` (`DiscoveredEndpoint`, `WebScanExecution`, `WebOrgPolicy`)
  - `backend/alembic/versions/a1b2c3d4e5f6_add_web_recon_models.py`
  - `backend/app/services/web_security/url_normalizer.py`
  - `backend/app/services/web_security/webcopilot_adapter.py`
  - `backend/app/api/v1/endpoints/web_recon.py`
  - `tests/integration/test_webcopilot_integration.py`
- **Modificados:**
  - `backend/app/models/scan.py` (`ScanType.WEB_RECON`)
  - `backend/app/models/__init__.py`
  - `backend/app/services/engines/nuclei_engine.py` (`scan_targets` enriquecido y `allow_intrusive` gobernado por `SAFE_MODE`)
  - `backend/app/services/scanner_orchestrator.py` (invocación aislada de `WebCopilotAdapter`)
  - `backend/app/api/v1/router.py` (ruta `/api/v1/web-recon`)
  - `web_dashboard/index.php` (panel integrado en la vista de Exposición/Vulnerabilidades)
  - `ROADMAP_OPENRECON.md`

---

## 5. Pruebas Ejecutadas y Resultados Reales

- `tests/integration/test_webcopilot_integration.py`: **6/6 tests OK**.
- Suite completa `tests/security` (**9/9 OK**) + `tests/integration` (**36/36 OK**), ejecutada tras la última edición.
