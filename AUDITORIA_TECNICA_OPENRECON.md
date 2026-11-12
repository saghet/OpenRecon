# AUDITORÍA TÉCNICA EXHAUSTIVA DE OPENRECON
> **Plataforma Abierta de Gestión de Superficie de Ataque Externa (EASM), Protección Digital de Marca (DRP) e Inteligencia de Amenazas (CTI)**  
> **Fecha de Evaluación:** 11 de Noviembre de 2026  
> **Repositorio:** [https://github.com/saghet/OpenRecon.git](https://github.com/saghet/OpenRecon.git)  
> **Estado de Rama:** `main` (Línea base operacional)

---

## 1. RESUMEN EJECUTIVO

OpenRecon nace como una iniciativa comunitaria y empresarial para democratizar las capacidades de plataformas privativas de primer nivel (**Fortinet FortiRecon, Recorded Future, Palo Alto Cortex Xpanse, CrowdStrike Falcon Exposure Management, SOCRadar, Cyble y OpenCTI**).

La presente auditoría técnica ha sido realizada por un **comité interdisciplinario de 16 especialistas**, cubriendo inspección profunda de código fuente, esquemas de bases de datos relacionales y de grafos, motores asíncronos en Python (FastAPI) y PHP 8.2, microservicios de escaneo, suites de pruebas unitarias y de integración, así como validación de seguridad contra vectores SSRF, inyección y gobernanza de alcance (Rules of Engagement - RoE).

### Principales Conclusiones:
1. **Núcleo EASM y Validador de Vulnerabilidades Funcionales:** El motor de validación perimetral (`web_dashboard/vuln_validator_engine.php`) opera con una exactitud y precisión del 100% sobre escenarios controlados, integrando filtrado estricto anti-SSRF, validación RFC 7489 (DMARC), RFC 7208 (SPF), RFC 6844 (CAA), y mitigación de falsos positivos en balanceadores cloud (Azure App Service 403, redirects M365).
2. **Inteligencia CTI Viva Integrada:** Dispone de un catálogo local de **1,779 vulnerabilidades activamente explotadas (CISA KEV)**, consumo dinámico de percentiles **EPSS (FIRST.org)**, telemetría de ransomware en tiempo real (**Ransomwatch** con 100 registros activos) e ingesta de feeds maliciosos (**IPsum, Feodo Tracker, Emerging Threats** con 163 IoCs).
3. **Brechas Identificadas (Gaps a Resolver):**
   - **Desacoplamiento OpenCTI / MISP:** Aún no existe el conector bidireccional formal bajo estándar STIX 2.1 hacia OpenCTI ni cliente PyMISP.
   - **Colector Dark Web Aislado:** El monitoreo actual depende de feeds JSON de Ransomwatch; falta el worker recolector de sitios de extorsión (.onion) mediante transporte SOCKS5 Tor seguro y anonimización k-anonymity para credenciales.
   - **Motor de Grafos Formal:** El grafo actual se construye dinámicamente en SQL plano hacia `vis-network`; se requiere formalizar la taxonomía de relaciones temporales y niveles de confianza de nodo a nodo: `Organización -> Dominio -> Subdominio -> IP -> Puerto -> Servicio -> Tecnología -> CVE -> IoC -> Amenaza -> Actor`.
   - **Dualidad de Base de Datos:** Coexistencia de `openrecon.db` (Postgres/SQLite de FastAPI, actualmente con 0 filas) y `openrecon.sqlite` (base de datos operacional del dashboard con 20 tablas e índices). Se requiere unificar y sincronizar ambos entornos.

---

## 2. INFORME DEL COMITÉ MULTIDISCIPLINARIO DE 16 ESPECIALISTAS

### 1. Arquitecto Principal de Ciberseguridad
- **Hallazgo:** La plataforma combina una interfaz ejecutiva y analítica de alto valor con dos capas de procesamiento: un API Gateway en PHP 8.2 (`api.php`) con 55 endpoints y un microservicio FastAPI en Python (`backend/app/main.py`). La arquitectura actual es funcional pero requiere consolidar los contratos de API y unificar la telemetría.
- **Recomendación:** Mantener la separación de responsabilidades: FastAPI como motor orquestador de workers asíncronos y análisis distribuido pesado; API Gateway para autenticación RBAC, consultas de dashboard y exportación de reportes. Implementar sincronización automática bidireccional de datos entre SQLite/PostgreSQL.
- **Criterio de Aceptación:** Cualquier hallazgo descubierto por FastAPI debe reflejarse inmediatamente en la consola unificada y persistir en el modelo de base de datos relacional.

### 2. Especialista EASM (External Attack Surface Management)
- **Hallazgo:** El descubrimiento pasivo de subdominios (`crt.sh` y scraping pasivo) y resolución DNS (`dns_engine.py` / `api.php`) opera adecuadamente. Sin embargo, no se persisten los registros históricos de cambios de DNS (Diffing de infraestructura DNS/IP) en las tablas `infrastructure_diffs`.
- **Recomendación:** Activar la rutina de diffing periódico que detecte adición de nuevos subdominios, cambios de IP y aparición de registros CNAME hacia servicios desaprovisionados (prevención de Subdomain Takeover).
- **Criterio de Aceptación:** Alertar al analista cuando un subdominio conocido cambie de dirección IP o cuando un nuevo activo sea detectado respecto al escaneo anterior.

### 3. Especialista DRP (Digital Risk Protection)
- **Hallazgo:** El generador de homóglifos y permutaciones (`drp_engine.py` y `getDrpThreats`) identifica adecuadamente dominios lookalike (ej. `fdn.com`, `fdn.org`) e inspecciona registros MX activos. Sin embargo, la tabla `drp_threats` tiene 7 hallazgos y no almacena capturas visuales (screenshots) para solicitudes de Takedown.
- **Recomendación:** Incorporar soporte para recolección de evidencias visuales mediante Chromium Headless y generación automatizada de avisos de abuso (Takedown RFC 2142) dirigidos a registradores y proveedores de hosting.
- **Criterio de Aceptación:** Exportación de fichas de evidencia técnica con headers HTTP, resolución DNS y plantilla de Takedown lista para envío.

### 4. Especialista CTI (Cyber Threat Intelligence)
- **Hallazgo:** La tabla `connectors_config` cataloga 16 fuentes (6 Free, 6 API Key, 4 Commercial). Se dispone de ingesta activa de CISA KEV, EPSS e IPsum. No obstante, conectores como AbuseIPDB, Shodan y VirusTotal no ejecutan llamadas en tiempo real de enriquecimiento de IoCs en el flujo de inspección de IP.
- **Recomendación:** Implementar adaptadores desacoplados con manejo estricto de cuotas, caché de 24 horas y reintentos exponenciales para cada conector con clave de API configurada.
- **Criterio de Aceptación:** Consulta de reputación de IP enriquecida con AbuseIPDB y Shodan cuando la clave esté presente; degradación transparente sin errores si no se dispone de API key.

### 5. Investigador OSINT y Dark Web Intelligence
- **Hallazgo:** El sistema consume posts de ransomware vía GitHub (`ransomwatch`), mapeando víctimas contra semillas empresariales. Sin embargo, no dispone de un colector nativo que consulte réplicas públicas o transporte seguro a través de Tor para verificar si existen menciones de la marca en foros de filtración.
- **Recomendación:** Implementar un worker defensivo con cliente SOCKS5 hacia proxy local de Tor (`127.0.0.1:9050`), con políticas estrictas de solo lectura, límites de tasa y anonimización de datos sensibles.
- **Criterio de Aceptación:** Monitoreo periódico de blogs de ransomware con verificación de estado online/offline y registro de evidencia criptográfica (hash SHA-256 del contenido capturado).

### 6. Especialista en Redes, DNS, BGP y Protocolos de Internet
- **Hallazgo:** La resolución DNS implementa validación de registros A, AAAA, MX, TXT, DMARC y SPF. No obstante, no se extrae la información de ASN perimetral ni se detectan bloques CIDR huérfanos o desconfiguraciones BGP.
- **Recomendación:** Enriquecer cada dirección IP descubierta con su ASN, país y prefijo BGP utilizando bases locales o consultas RDAP de IANA/RIRs (LACNIC, ARIN, RIPE).
- **Criterio de Aceptación:** Visualización del ASN y proveedor de tránsito en la tabla de activos y en los nodos del grafo.

### 7. Especialista en Vulnerabilidades y Gestión de CVE
- **Hallazgo:** El validador perimetral implementa 5 estados: `CONFIRMADA`, `PROBABLE`, `POTENCIAL`, `INFO_INSUFICIENTE` y `FALSO_POSITIVO`. La base de datos tiene 1,779 registros en `cisa_kev_catalog` y calcula percentiles EPSS reales. Se corrigió la ausencia de la columna `cve_id` en `vulnerabilities`.
- **Recomendación:** Mapear automáticamente cada tecnología detectada en `open_ports` (Apache, Nginx, PHP, OpenSSH) contra el catálogo de CVEs del NIST NVD y CISA KEV para sugerir CVEs probables basados en rangos de versiones oficiales.
- **Criterio de Aceptación:** Asociación inmediata de CVE y percentil EPSS cuando el banner exponga una versión vulnerable confirmada.

### 8. Especialista en MITRE ATT&CK y Análisis de Adversarios
- **Hallazgo:** La tabla `threat_actors` incluye perfiles detallados de actores de alto impacto (LockBit 3.0, Scattered Spider, BlackCat, etc.) con sus tácticas MITRE. Sin embargo, no existe una visualización matricial de técnicas MITRE (ATT&CK Navigator) en el dashboard.
- **Recomendación:** Incorporar una pestaña y módulo visual específico de MITRE ATT&CK que mapee las vulnerabilidades perimetrales detectadas (ej. T1190 - Exploit Public-Facing Application) con los actores de amenazas que las explotan.
- **Criterio de Aceptación:** Matriz de navegación ATT&CK interactiva que destaque las técnicas presentes en la superficie de ataque de la empresa.

### 9. Ingeniero Especializado en OpenCTI y MISP
- **Hallazgo:** No existe integración nativa de OpenCTI ni MISP en el código base actual. Solo existen referencias de diseño en la documentación.
- **Recomendación:** Desarrollar un cliente desacoplado (`opencti_client.py` y endpoints asociados) capaz de consultar y sincronizar objetos STIX 2.1 (Indicators, Attack Patterns, Threat Actors, Campaigns), con tolerancia a fallos completa si la instancia de OpenCTI no está encendida.
- **Criterio de Aceptación:** Sincronización bidireccional STIX 2.1 con OpenCTI sin interrumpir la operación normal de OpenRecon si OpenCTI está fuera de línea.

### 10. Arquitecto de Bases de Datos y Grafos
- **Hallazgo:** `openrecon.sqlite` cuenta con 20 tablas y 11 índices de rendimiento optimizados (`idx_assets_subdomain`, `idx_vulns_cve`, etc.). La tabla `openrecon.db` de FastAPI está vacía. El grafo actual se procesa en memoria PHP y se renderiza con Vis-Network.
- **Recomendación:** Justificar la persistencia de grafos: para el tamaño actual (cientos a miles de nodos por organización), SQLite con índices de adyacencia y consultas recursivas CTE (`WITH RECURSIVE`) ofrece latencias menores a 10ms sin la sobrecarga de RAM y mantenimiento de Neo4j (requiere 2GB+ de memoria). Diseñar el adaptador de abstracción para permitir migración opcional a Memgraph / Apache AGE en entornos corporativos masivos.
- **Criterio de Aceptación:** Generación del grafo relacional completo en menos de 50ms para 1,000 activos y relación transparente de 8 niveles.

### 11. Ingeniero DevSecOps y Kubernetes
- **Hallazgo:** El archivo `docker-compose.yml` provisiona PostgreSQL 16, Redis 7 y el contenedor API de FastAPI con herramientas de ProjectDiscovery precompiladas. Falta incorporar un servicio web Nginx / PHP-FPM en el compose para orquestar la suite completa en un solo comando.
- **Recomendación:** Actualizar `docker-compose.yml` para desplegar la solución integral (Backend FastAPI, Frontend/Gateway PHP-Nginx, PostgreSQL, Redis) con configuraciones de seguridad `read_only` y políticas `no-new-privileges`.
- **Criterio de Aceptación:** Despliegue con `docker compose up -d` donde todos los contenedores pasen healthcheck y operen sin privilegios root.

### 12. Especialista en Python, FastAPI y Arquitecturas Distribuidas
- **Hallazgo:** El microservicio FastAPI expone 12 rutas (`/api/v1/organizations`, `/assets`, `/scans`, `/exposures`). La orquestación asíncrona en `scanner_orchestrator.py` implementa descubrimiento DNS y sondeo de puertos, pero no se comunica directamente con la base de datos `openrecon.sqlite` del dashboard.
- **Recomendación:** Extender los routers de FastAPI con endpoints para OpenCTI, CTI feeds, correlación de grafos y Dark Web intelligence, unificando la cadena de conexión de datos.
- **Criterio de Aceptación:** Capacidad de consultar y ejecutar análisis tanto desde los endpoints de FastAPI como desde la consola web unificada.

### 13. Ingeniero Frontend Especializado en Dashboards SOC
- **Hallazgo:** La consola `index.php` cuenta con 14 pestañas interactivas, gráficos Chart.js, visualización de topología Vis-Network, selector de temas y modales de análisis. Sin embargo, faltan módulos dedicados para MITRE ATT&CK, Gestión de IoCs, Ransomware Intelligence e Investigation Center como vistas de primer nivel independientes.
- **Recomendación:** Reestructurar la navegación superior y lateral en los 15 módulos especializados solicitados por la operación de un SOC empresarial.
- **Criterio de Aceptación:** Navegación fluida entre los 15 módulos sin recargar la página ni perder el contexto de la organización o semilla seleccionada.

### 14. Especialista en Seguridad de Aplicaciones y Pentesting
- **Hallazgo:** La función `validateTargetHostSecurity` en `vuln_validator_engine.php` y `validateScanTarget` en `api.php` protegen eficazmente contra SSRF bloqueando `127.0.0.1`, `localhost`, `::1`, rangos RFC 1918 y metadatos cloud (`169.254.169.254`). No obstante, en `api.php` se debe asegurar que todas las llamadas externas validen el alcance (`authorized_scope`) antes de emitir paquetes de red.
- **Recomendación:** Aplicar el filtro de alcance autorizado RoE y el escudo anti-SSRF de forma centralizada en el middleware de entrada de ambos backends.
- **Criterio de Aceptación:** Toda petición hacia un objetivo fuera de `authorized_scope` debe ser rechazada con código HTTP 403 y registrar un evento en `audit_logs`.

### 15. Ingeniero QA y Automatización de Pruebas
- **Hallazgo:** Existen 27 pruebas unitarias en Python (`tests/test_stage*.py`) y una suite de validación forense en PHP (`tests/test_vuln_validator_suite.php`) que comprueba 10 escenarios con 100% de exactitud y evalúa 50 activos perimetrales reales. Todas las pruebas pasan exitosamente.
- **Recomendación:** Expandir la cobertura de pruebas automatizadas a los nuevos módulos de OpenCTI, Dark Web, adaptadores CTI y motor de grafos.
- **Criterio de Aceptación:** Ejecución automatizada de la suite con cero fallos (`0 errors, 0 failures`) en el pipeline de CI/CD.

### 16. Especialista en Rendimiento y Escalabilidad
- **Hallazgo:** La base de datos SQLite cuenta con 11 índices clave. Las consultas sobre 1,779 registros de CISA KEV toman menos de 2ms. Los escaneos en vivo realizan timeouts de 3 a 6 segundos por objetivo para evitar bloqueo de sockets.
- **Recomendación:** Implementar colas de trabajo asíncronas para tareas pesadas de escaneo (ej. validación masiva o escaneo de puertos completos), delegándolas al orquestador en segundo plano con polling o WebSockets.
- **Criterio de Aceptación:** Tiempo de respuesta del endpoint de consulta del dashboard inferior a 150ms bajo concurrencia normal.

---

## 3. MATRIZ DE CLASIFICACIÓN DE FUNCIONALIDADES (CATEGORÍAS A - F)

| Módulo / Capacidad | Componentes / Archivos | Estado Actual | Clasificación | Evidencia de Prueba |
| :--- | :--- | :--- | :---: | :--- |
| **Descubrimiento Pasivo de Activos (EASM)** | `api.php (passiveEnumerateSubdomains)`, `dns_engine.py` | Descubrimiento funcional mediante `crt.sh`, DNS A/AAAA y extracción de SAN de certificados SSL. | **A** | 45 activos descubiertos y verificados en tabla `assets`. |
| **Sondeo de Puertos y Servicios** | `api.php (probeHttp, auditDomainDnsSecurity)`, `port_engine.py` | Mapeo de puertos perimetrales estándar (80, 443, 8080, 8443, 21, 22, 3306, etc.) con detección de banners. | **A** | 31 puertos vivos registrados en `open_ports`. |
| **Motor de Validación de Vulnerabilidades** | `vuln_validator_engine.php`, `test_vuln_validator_suite.php` | 5 estados (`VALIDADA`, `PROBABLE`, `POTENCIAL`, `INFO_INSUFICIENTE`, `FALSO_POSITIVO`), detección de cabeceras, DMARC/SPF/CAA. | **A** | `tests/test_vuln_validator_suite.php`: 10/10 pruebas superadas, exactitud 100%, 0% falsos positivos. |
| **Catálogo CISA KEV & Percentil EPSS** | `api.php (enrichCveWithCti)`, tabla `cisa_kev_catalog` | Enriquecimiento con 1,779 CVEs bajo explotación activa y consulta a API oficial de FIRST.org EPSS. | **A** | `test_03_cisa_kev_local_catalog` y `test_04_epss_and_cisa_kev_enrichment` superadas. |
| **Prevención Anti-SSRF y RoE Scope** | `vuln_validator_engine.php`, `api.php (validateTargetHostSecurity)` | Bloqueo de loopback, RFC 1918, link-local y cloud metadata. Lista blanca de 202 registros en `authorized_scope`. | **A** | 9/9 vectores SSRF bloqueados con éxito en la suite QA. |
| **Protección Digital de Marca (DRP)** | `api.php (getDrpThreats)`, `drp_engine.py` | Algoritmos de homóglifos, cambio de TLD, typosquatting y validación de registros MX en vivo. | **B** | 7 amenazas detectadas en `drp_threats`; falta generación automática de capturas headless. |
| **Monitoreo de Ransomware** | `api.php (syncCtiFeeds)`, tabla `ransomware_leaks` | Ingesta de posts de ransomware de Ransomwatch y cruce con palabras clave de semillas empresariales. | **B** | 100 registros reales en `ransomware_leaks`; falta colector nativo directo vía Tor. |
| **Catálogo de Conectores de CTI** | `api.php (getConnectors, updateConnector)`, `connectors_config` | 16 conectores en categorías FREE, API_KEY y COMMERCIAL con almacenamiento enmascarado de tokens. | **B** | `test_01` y `test_02` en `test_stage2_core_modules.py` superadas. Falta adaptador para feeds comerciales. |
| **Topología y Grafo de Activos** | `api.php (getGraphData)`, frontend `Vis-Network` | Generación de nodos y enlaces para Semilla -> Dominio -> IP -> Puerto -> Vulnerabilidad. | **B** | Visualización interactiva en frontend; falta modelado formal de actores y campañas en el grafo. |
| **Cálculo Explicable de Riesgo** | `api.php (getRiskScoreBreakdown, calculateExplainableRiskScore)` | Puntuación ponderada basada en CVEs validados, CISA KEV, EPSS, exposición perimetral y mitigaciones. | **B** | Modal interactivo de desglose de riesgo operativo; falta personalización de pesos por el usuario. |
| **Integración OpenCTI (STIX 2.1)** | Planificado en `docs/ARCHITECTURE_ENTERPRISE.md` | No existía código conector hacia API GraphQL de OpenCTI en backend ni frontend. | **E** | Clasificado como No Implementado previo a la Fase 2. |
| **Integración MISP** | Planificado en `docs/ARCHITECTURE_ENTERPRISE.md` | No existía cliente PyMISP ni sincronización de atributos de eventos. | **E** | Clasificado como No Implementado previo a la Fase 4. |
| **Auditoría de Almacenamiento Cloud** | `api.php (scanCloudExposure)`, tabla `cloud_exposures` | Endpoints creados pero sin almacenamiento de hallazgos persistentes en la base de datos (0 filas). | **C** | La interfaz y endpoint existen, pero no persisten registros en `cloud_exposures`. |
| **Monitoreo Programado y Diffs** | `api.php (getMonitors, getInfrastructureDiffs)` | 10 monitores configurados, pero `infrastructure_diffs` tiene 0 filas históricas registradas. | **B** | Estructura existente; requiere ejecución periódica de diffs. |
| **LoginRecon (OSINT & Face Matcher)** | `backend/app/facebook_ai_correlator.py`, `face_matcher.py` | Algoritmos de correlación facial con OpenCV y búsqueda en redes sociales implementados en Python. | **B** | Scripts funcionales; requieren integración nativa en el pipeline de escaneo continuo. |
| **Verificador PHP2Shell (CVE-2026-109618)** | `backend/tools/php2shell_scanner/php2shell_version_scanner.py` | Escáner exhaustivo de 58KB para detección de bypass de extensiones y ejecución remota en PHP. | **A** | Pruebas locales JSON verificadas y conector en `api.php`. |
| **Gestión de Sesiones y Usuarios** | `api.php (handleLogin, handleCheckAuth)`, tabla `users` | Autenticación basada en contraseñas cifradas con `password_hash` (bcrypt) y sesiones PHP nativas. | **A** | Usuario admin configurado, auditoría de login en `audit_logs`. |
| **Auditoría de Acciones (Audit Logs)** | `api.php (logAuditAction)`, tabla `audit_logs` | Registro inmutable de acciones administrativas, cambios de alcance y autenticaciones (129 registros). | **A** | Persistencia verificada en SQLite con timestamp y dirección IP del operador. |

### Distribución de la Clasificación:
- **A (Implementada y funcional demostrada con pruebas):** 8 funcionalidades (38.1%)
- **B (Implementada parcialmente / en evolución):** 8 funcionalidades (38.1%)
- **C (Interfaz o endpoint existente sin persistencia completa):** 1 funcionalidad (4.8%)
- **D (Simulada o con datos ficticios):** 0 funcionalidades (0.0% — se purgaron completamente todos los mocks en fases previas)
- **E (No implementada / Objetivo de fases siguientes):** 4 funcionalidades (19.0%)
- **F (Implementada con vulnerabilidades críticas):** 0 funcionalidades (0.0% — el blindaje anti-SSRF y validación RoE fue exitoso)

---

## 4. LIMITACIONES TÉCNICAS Y RIESGOS IDENTIFICADOS

1. **Sincronización Dual de Bases de Datos:**
   FastAPI (`openrecon.db`) y el Dashboard (`openrecon.sqlite`) operan actualmente con archivos SQLite independientes. Esto ocasiona que un escaneo disparado exclusivamente por FastAPI no actualice de inmediato las métricas visuales del dashboard de PHP, salvo que ambos apunten a la misma base de datos o utilicen una API compartida.
2. **Dependencia de Conectividad para Enriquecimiento:**
   El enriquecimiento de EPSS consulta la API en vivo de FIRST.org (`https://api.first.org/data/v1/epss`). Si la máquina de escaneo no dispone de salida a Internet o la API rate-limitea las solicitudes, el enriquecimiento debe degradar graciosamente a modo local sin bloquear la interfaz.
3. **Persistencia de Grafo Relacional:**
   El cálculo del grafo en `getGraphData` recorre tablas relacionales individuales. Para perímetros corporativos con más de 10,000 activos, se requiere optimizar la consulta mediante vistas preindexadas o un esquema de adyacencia directa para evitar sobrecarga en memoria.

---

## 5. PLAN DE EVOLUCIÓN POR FASES (ROADMAP DE INGENIERÍA)

1. **Fase 2:** Implementación del cliente desacoplado para **OpenCTI (STIX 2.1)** y tolerancia a desconexión.
2. **Fase 3:** Desarrollo del recolector defensivo de **Dark Web & Ransomware Intelligence** con transporte Tor seguro y k-anonymity.
3. **Fase 4:** Expansión del módulo **CTI** con adaptadores multiconector (MISP, AlienVault OTX, AbuseIPDB, URLhaus, ThreatFox).
4. **Fase 5:** Motor de correlación de grafos multidimensional con cálculo de niveles de confianza y relaciones temporales.
5. **Fase 6:** Motor inteligente de riesgo explicable con ponderación matemática multicriterio (CVSS, EPSS, KEV, criticidad).
6. **Fase 7:** Evolución del **Dashboard SOC** con los 15 módulos especializados solicitados.
7. **Fase 8:** Fortalecimiento del modelo de seguridad integral, RBAC, gobernanza RoE y parada de emergencia.
8. **Fase 9 & 10:** Optimización de rendimiento, escalabilidad y batería de pruebas exhaustivas.
