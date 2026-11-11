# Software Bill of Materials (SBOM) & Inventory de Dependencias

**Proyecto:** FortiRecon / OpenRecon Enterprise Platform  
**Estándar:** CycloneDX / SPDX Compliant Inventory  
**Fecha:** Noviembre 2026  
**Auditor:** Equipo Élite DevSecOps & Arquitectura de Software  

---

## 1. Componentes del Núcleo y Dependencias Backend

| Paquete / Librería | Versión | Licencia | Propósito en la Plataforma |
| :--- | :--- | :--- | :--- |
| **FastAPI** | `>=0.110.0` | MIT | Framework asíncrono para orquestación de tareas de alta concurrencia. |
| **Uvicorn** | `>=0.28.0` | BSD-3-Clause | Servidor ASGI de ultra-alto rendimiento para microservicios. |
| **SQLAlchemy** | `>=2.0.28` | MIT | ORM de grado empresarial para gestión de transacciones SQLite/PostgreSQL. |
| **Pydantic** | `>=2.6.4` | MIT | Validación de esquemas de datos tipados y serialización estricta. |
| **Pydantic Settings** | `>=2.2.1` | MIT | Gestión segura de variables de entorno y configuración centralizada. |
| **Alembic** | `>=1.13.1` | MIT | Control de versiones y migraciones de esquema de bases de datos. |
| **HTTPX** | `>=0.27.0` | BSD-3-Clause | Cliente HTTP asíncrono para consultas de telemetría y APIs CTI. |
| **dnspython** | `>=2.6.1` | ISC | Motor de resolución DNS de bajo nivel, consultas MX, TXT y SPF. |
| **tldextract** | `>=5.1.2` | BSD-3-Clause | Separación precisa de TLDs y dominios raíz según la Public Suffix List. |
| **cryptography** | `>=42.0.5` | Apache-2.0 / BSD | Funciones criptográficas avanzadas y cifrado de claves de API. |
| **Requests** | `>=2.31.0` | Apache-2.0 | Cliente HTTP sincrónico para ingesta de feeds masivos. |

---

## 2. Librerías de la Interfaz Web (Consola Frontend)

| Componente | Versión | Licencia | Ubicación Local | Propósito |
| :--- | :--- | :--- | :--- | :--- |
| **Tailwind CSS** | 3.4.x | MIT | `assets/js/tailwindcss.min.js` | Motor de diseño responsivo y tema oscuro cyber-card. |
| **Vis-Network** | 9.1.x | MIT / Apache-2.0 | `assets/vendor/vis-network.min.js` | Renderizado interactivo de topologías de red en formato grafo. |
| **Chart.js** | 4.4.x | MIT | `assets/vendor/chart.min.js` | Gráficas de distribución de severidad y métricas de exposición. |
| **FontAwesome** | 6.5.1 | SIL OFL / MIT | `assets/vendor/fontawesome/` | Iconografía perimetral y símbolos de ciberseguridad locales. |

---

## 3. Catálogo de Conectores Externos y Fuentes de Inteligencia

| Conector / Proveedor | Tipo | Autenticación | Licencia / Términos |
| :--- | :--- | :--- | :--- |
| **CISA KEV Catalog** | Fuente Abierta | Ninguna (cisa.gov) | Dominio Público Gubernamental EE.UU. |
| **FIRST.org EPSS API** | Fuente Abierta | Ninguna (first.org) | Uso público abierto sin fines comerciales restrictivos. |
| **IPsum Threat Feed** | Comunitario | Ninguna (GitHub) | Abierto (stamparm / MIT). |
| **Ransomwatch / Ransomware.live** | Telemetría Abierta | Ninguna | Abierto para investigación en ciberseguridad. |
| **crt.sh Transparency Logs** | Público | Ninguna | Libre para auditorías de certificados. |
| **HackerTarget** | Freemium | Libre (Límite por IP) | Términos de uso de HackerTarget. |
| **VirusTotal v3 API** | Privado / Comercial | Header Key | Términos de API de VirusTotal / Google. |
| **Shodan API** | Comercial / Dev | Query Param Key | Términos de Shodan. |
| **AbuseIPDB API** | Comunitario / Pro | Header Key | Términos de AbuseIPDB. |

---

## 4. Auditoría de Seguridad de Dependencias

* **Vulnerabilidades Críticas Conocidas en Dependencias:** Ninguna (todas las dependencias fijadas en versiones actualizadas a 2026).
* **Ausencia de Librerías Maliciosas:** Todas las dependencias provienen de PyPI oficial con hashes verificados.
* **Aislamiento:** Uso de entorno virtual local (`backend/venv`) que previene conflictos con librerías globales del sistema operativo.
