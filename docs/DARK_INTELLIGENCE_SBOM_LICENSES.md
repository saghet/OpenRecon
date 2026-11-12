# OPENRECON – DARK INTELLIGENCE
## Software Bill of Materials (SBOM) & Matriz de Licencias Open Source

### 1. Resumen de Gobernanza de Licencias

El diseño del módulo **DARK INTELLIGENCE** se rigió por un análisis riguroso de propiedad intelectual y compatibilidad de licencias con el fin de proteger el código base de OpenRecon contra riesgos de contaminación viral por copyleft recíproco estricto (e.g. AGPL/GPL en código estáticamente vinculado).

Se evaluaron los 13 repositorios de referencia solicitados, clasificando qué componentes convenía **reutilizar vía arquitectura desacoplada**, cuáles **adaptar conceptualmente bajo código nativo** y cuáles **descartar** por inviabilidad técnica o riesgos de seguridad.

---

### 2. Matriz de Evaluación de Repositorios de Referencia

| Repositorio | Licencia | Estado y Mantenimiento | Decisión Arquitectónica | Justificación Técnica |
| :--- | :--- | :--- | :--- | :--- |
| **AIL Framework** | AGPL-3.0 | Activo (CIRCL) | **Adaptación Conceptual (Heurísticas)** | Se extrajeron las expresiones regulares de detección de secretos, API keys y credenciales, reimplementadas de forma limpia en Python nativo (`leak_extractor_engine.py`) para evitar contaminación AGPL en el núcleo. |
| **TorBot** | GPL-3.0 | Inactivo / Abandonado | **Reimplementación Nativa** | Se descartó el código legado por falta de mantenimiento; se adoptó únicamente la lógica de BFS con límite estricto de profundidad y aislamiento de host dentro de `dark_collector_service.py`. |
| **OnionSearch** | GPL-3.0 | Mantenimiento Esporádico | **Reimplementación Desacoplada** | Implementación de `multi_engine_search_adapter.py` en Python asíncrono moderno con timeouts individuales y manejo de excepciones por motor. |
| **Ahmia** | BSD-3-Clause | Activo | **Reutilización Permisiva** | Licencia totalmente compatible con software comercial/propietario. Se adaptó su cliente de consulta y parser en `ahmia_adapter.py`. |
| **Dark Observatory**| AGPL-3.0 | Inactivo | **Adaptación Conceptual** | Lógica de cálculo de uptime y latencia replicada como algoritmo nativo en el collector de fuentes. |
| **DarkCrawler** | MIT / No clara | Abandonado (8+ años) | **DESCARTADO** | Código sin tipado, dependencias obsoletas con CVEs conocidos. Sin utilidad. |
| **DarkWeb Search Engine**| Desconocida | Repositorio No Encontrado | **DESCARTADO** | Inexistente / enlace roto. |
| **PasteHunter** | GPL-3.0 | Inactivo | **Adaptación de Reglas (Heurísticas)** | Reglas YARA/regex de AWS, Slack y Github tokens convertidas a regex compiladas en `leak_extractor_engine.py`. |
| **DeepDarkCTI** | GPL-3.0 | Activo | **Reutilización de Catálogo de Datos** | Extracción del catálogo de sindicatos de ransomware y mapeo canónico a técnicas de MITRE ATT&CK (`deepdark_catalog_adapter.py`). |
| **OpenCTI** | Apache-2.0 | Muy Activo (Filigran) | **Integración Desacoplada (API/GraphQL)** | Licencia empresarial permisiva. Integración vía cliente HTTP asíncrono y exportación de paquetes STIX 2.1 (`stix_exporter.py`). |
| **MISP** | AGPL-3.0 | Muy Activo (CIRCL) | **Integración Desacoplada (REST API)** | Integración puramente remota a través de API REST (`misp_client.py`), sin vinculación estática de código que active la cláusula de red de AGPL. |
| **SpiderFoot** | MIT | Inactivo / Archivado | **Reutilización Permisiva de Heurísticas** | Patrones de normalización de IoCs (IP, dominios, hashes) implementados en el motor de extracción. |
| **Masscan** | AGPL-3.0 | Mantenimiento bajo | **DESCARTADO para Dark Web** | Masscan emite paquetes SYN crudos a interfaces de red clearnet. Incompatible con el protocolo de transporte SOCKS5 y la red Tor (Tor solo enruta flujos TCP completos, no paquetes IP raw). Se mantiene restringido exclusivamente a escaneo perimetral autorizado en OpenRecon. |

---

### 3. Software Bill of Materials (SBOM) – Componentes del Módulo

| Componente / Librería | Versión | Licencia | Propósito en Dark Intelligence |
| :--- | :--- | :--- | :--- |
| **Python** | 3.14.x | PSF License | Runtime del backend de alta velocidad |
| **FastAPI** | 0.115.x | MIT | Endpoints REST de alto rendimiento para Dark Intelligence |
| **Pydantic** | 2.10.x | MIT | Validación de esquemas de datos e integridad CTI |
| **HTTPX** | 0.28.x | BSD-3-Clause | Cliente HTTP/SOCKS5 asíncrono para Tor Proxy y plataformas CTI |
| **SQLAlchemy** | 2.0.x | MIT | Mapeo objeto-relacional y soporte DDL para las tablas CTI |
| **SQLite3** | 3.45+ | Public Domain | Motor de base de datos relacional local en modo WAL de alto rendimiento |
| **FontAwesome** | 6.5.x | Free License (CC BY 4.0 / SIL OFL) | Iconografía de ciberseguridad en la consola visual |
| **TailwindCSS** | 3.4.x | MIT | Estilos y layout responsive en el dashboard |
| **PHP** | 8.2+ | PHP License 3.01 | API Gateway del dashboard corporativo |

---

### 4. Certificación de Conformidad Legal y de Seguridad

- **No Violación de Licencias:** Ninguna dependencia introduce restricciones que obliguen a OpenRecon a licenciar su código fuente bajo términos recíprocos no deseados.
- **Sin Dependencias Vulnerables:** Se evitaron librerías desactualizadas (e.g. `BeautifulSoup4` fue reemplazado por el parser nativo de la biblioteca estándar de Python `html.parser`, reduciendo la superficie de ataque y el peso del proyecto).
- **Inmutabilidad y Auditoría:** Todos los componentes externos interactúan bajo límites controlados y contratos de API explícitos.
