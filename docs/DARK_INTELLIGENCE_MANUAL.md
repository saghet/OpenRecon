# OPENRECON – DARK INTELLIGENCE
## Manual de Arquitectura, Operación y Seguridad para Analistas CTI

### 1. Visión General del Módulo

**DARK INTELLIGENCE** es el módulo integral de Cyber Threat Intelligence (CTI) y reconocimiento pasivo/defensivo en la Dark Web (.onion) de **OpenRecon**. Su objetivo es dotar al equipo de ciberseguridad, analistas de SOC y directores de seguridad de una plataforma profesional, segura, auditable y modular capaz de investigar fuentes no indexadas, monitorizar la exposición de marcas corporativas, registrar víctimas de extorsión ransomware, neutralizar fugas de credenciales (bajo estricto K-Anonimato) y exportar inteligencia estructurada bajo el estándar **OASIS STIX 2.1**.

---

### 2. Principios de Diseño y Restricciones Operativas

1. **Cero Ruptura de Funcionalidades:** El módulo opera de forma completamente desacoplada y aditiva, preservando intactos los 32 endpoints REST y las 66 acciones base del API Gateway de OpenRecon.
2. **Cero Simulación:** Todos los componentes visuales (15 sub-secciones en `darkintel.php`) consumen endpoints verificados con datos estructurados reales, evitando placeholders o botones sin implementación.
3. **Privacidad y K-Anonimato (Zero-Plaintext):**
   - Las credenciales nunca se muestran ni se almacenan en texto claro.
   - Las identidades se enmascaran automáticamente (`ad****n@empresa.com`).
   - Las contraseñas se almacenan exclusivamente como hashes **SHA-256**.
4. **Blindaje de Red y Aislamiento Tor (Defensive Tor Sandbox):**
   - Enrutamiento obligatorio por proxy `socks5h://` para resolución remota de DNS en nodos de salida Tor (prevención de DNS Leakage).
   - Verificación **Anti-SSRF** estricta: Se rechaza cualquier petición dirigida a RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), metadata cloud (`169.254.169.254`, `metadata.google.internal`) o nombres de contenedor Docker.
   - Límite de carga útil de 2 MB y rechazo de binarios ejecutables (`.exe`, `.zip`, `.elf`, `.msi`).
   - **Emergency Kill-Switch:** Bloqueo en seco inmediato ante cualquier detección de hostilidad.
5. **Cadena de Custodia Criptográfica (Evidence Vault):**
   - Identificadores de evidencia inmutables calculados como el hash SHA-256 del contenido crudo.
   - Firma criptográfica **HMAC-SHA256** para validar que la evidencia no ha sufrido alteraciones post-recolección.
   - Saneamiento de contenido mediante parser HTML nativo sin ejecución de scripts ni iframes.
6. **Inteligencia Artificial con Blindaje Anti-Inyección (DeepSeek CTI):**
   - Encapsulamiento del contenido investigado en jaulas XML `<untrusted_darkweb_content>`.
   - Neutralización previa de patrones de evasión (jailbreaks, directivas de reinicio de rol, tokens de chat adversarios).
   - Mapeo objetivo de técnicas **MITRE ATT&CK** (T1486, T1190, T1078, etc.) y citaciones obligatorias al Evidence Vault.
   - Fallback determinista local sin interrupción de servicio en caso de fallo o ausencia de API key.

---

### 3. Arquitectura del Sistema

```
+-----------------------------------------------------------------------------------+
|                           OPENRECON WEB DASHBOARD                                 |
|      FortiOS Navigation: Threat Intelligence & DRP -> Dark Intelligence (PRO)      |
|               (15 Sub-secciones interactivas en darkintel.php)                     |
+-----------------------------------------+-----------------------------------------+
                                          |
                      (JSON REST / AJAX calls)
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        PHP 8.2 API GATEWAY (api.php)                             |
| Acciones: darkintel_search, darkintel_get_sources, darkintel_get_ransomware,      |
| darkintel_get_leaks, darkintel_get_actors, darkintel_get_iocs,                     |
| darkintel_investigate, darkintel_get_evidence, darkintel_export_stix,              |
| darkintel_integrations_status, darkintel_ai_analyze                               |
+--------------------+------------------------------------+-------------------------+
                     |                                    |
                     v                                    v
+-----------------------------------------+  +--------------------------------------+
|          FASTAPI BACKEND (/darkintel)   |  |      SQLITE PERSISTENCE ENGINE       |
|  - TorSecurityGuard (Anti-SSRF/SOCKS5h) |  |   (openrecon.sqlite en modo WAL)     |
|  - EvidenceSanitizer & Vault Custody    |  |  - darkintel_evidence_vault          |
|  - DarkCollectorService (BFS Crawler)   |  |  - darkintel_sources                 |
|  - DarkSearchEngine (Multi-source)      |  |  - darkintel_leaks                   |
|  - LeakExtractorEngine (AIL Heuristics) |  |  - darkintel_ransomware_posts        |
|  - DeepDarkCatalogAdapter (MITRE ATT&CK)|  |  - darkintel_threat_actors           |
|  - StixExporter (STIX 2.1 JSON Bundles) |  |  - darkintel_iocs                    |
|  - DeepSeekCTIEngine (Anti-Injection)   |  |  - darkintel_search_queries          |
|  - OpenCTI & MISP Decoupled Connectors  |  |  - darkintel_investigations          |
+--------------------+--------------------+  +--------------------------------------+
                     |
                     v
+-----------------------------------------------------------------------------------+
|                         TOR SANDBOX & DEFENSIVE EGRESS                            |
|             Contenedor tor-proxy aislado (socks5h://127.0.0.1:9050)                |
|           Solo acceso saliente a la red Tor. Prohibido acceso a DB o Redis.        |
+-----------------------------------------------------------------------------------+
```

---

### 4. Guía de Uso para Analistas de Ciberseguridad

#### 4.1. Búsqueda Federada en la Dark Web
1. Dirígete al menú lateral **Threat Intelligence & DRP > Dark Intelligence**.
2. Selecciona la pestaña **2. Dark Web Search**.
3. Introduce el término deseado: un dominio corporativo (ej. `miempresa.com`), una IP, un hash de malware, un CVE o el nombre de un sindicato de ransomware (ej. `LockBit`, `cl0p`).
4. Haz clic en **Investigar**. El sistema consultará concurrentemente la bóveda local de evidencias, el catálogo de DLS de ransomware, el directorio de fuentes activas y los motores de indexación Onion.
5. Revisa la **Declaración de Transparencia de Cobertura**, la cual detalla exactamente cuántas fuentes fueron auditadas para evitar falsas asunciones de cobertura total.

#### 4.2. Evaluación de Exposición Organizacional (Exposure Score)
1. Selecciona la pestaña **9. Org Exposure**.
2. Introduce el dominio corporativo autorizado para auditoría.
3. El motor correlacionará:
   - Presencia en blogs de extorsión (DLS).
   - Credenciales filtradas asociadas al dominio.
   - Vulnerabilidades perimetrales y IoCs vinculados.
4. Se generará un **Exposure Score** objetivo entre 0 y 100, acompañado de un resumen ejecutivo y recomendaciones de mitigación inmediata.

#### 4.3. Bóveda de Evidencias y Cadena de Custodia
1. En cualquier hallazgo, haz clic en **Ver Bóveda** o dirígete a **11. Evidence Vault**.
2. El visor muestra:
   - Identificador SHA-256 de la evidencia.
   - Firma HMAC de custodia.
   - URL de origen y tipo de fuente.
   - Previsualización limpia y saneada, garantizando que ningún script, macro o payload activo pueda ejecutarse en el navegador del analista.

#### 4.4. Asistencia Analítica DeepSeek CTI
1. Accede a **12. DeepSeek CTI**.
2. Pega el extracto de un comunicado de extorsión, paste o documento sospechoso.
3. El motor:
   - Evalúa y neutraliza posibles técnicas de prompt injection contenidas en el texto.
   - Extrae el vector de ataque y las técnicas de **MITRE ATT&CK**.
   - Asigna un nivel de severidad técnico (CRITICAL / HIGH / MEDIUM / LOW).
   - Genera recomendaciones de contención para el equipo SOC.

#### 4.5. Exportación e Integración STIX 2.1 / CTI
1. Para descargar el paquete de inteligencia en formato JSON estándar, haz clic en el botón superior **Exportar STIX 2.1** o visita la pestaña **14. Reportes**.
2. El archivo generado contiene todos los SDOs (`threat-actor`, `incident`, `indicator`, `note`) e identidades autoritativas listas para importación en **OpenCTI**, **MISP** o plataformas SIEM.
3. Si tienes una instancia OpenCTI o MISP en red, las opciones en **15. Integraciones** permiten activar la sincronización directa.

---

### 5. Configuración de Variables de Entorno

En el archivo `.env` del backend se configuran los parámetros del módulo:

```env
# Configuración Tor Sandbox
TOR_PROXY_URL=socks5h://127.0.0.1:9050
TOR_REQUEST_TIMEOUT=15.0
TOR_MAX_REDIRECTS=3
TOR_MAX_CONTENT_BYTES=2097152
TOR_VERIFY_SSL=False

# Motor DeepSeek AI
DEEPSEEK_API_KEY=sk-your-deepseek-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_MODEL=deepseek-chat

# Integraciones CTI Desacopladas
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=your-opencti-token
MISP_URL=https://misp:8443
MISP_KEY=your-misp-api-key
```
