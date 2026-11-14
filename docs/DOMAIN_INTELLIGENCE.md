# Domain Intelligence — OpenRecon

## 1. Descripción General
Módulo nativo de investigación OSINT y Threat Intelligence integrado en OpenRecon (`FastAPI + SQLAlchemy + web_dashboard`). Permite investigar dominios, subdominios, IPv4, IPv6 y URLs consultando múltiples fuentes en paralelo con caché configurable, correlación CTI y evaluación de riesgo explicable.

## 2. Fuentes de Inteligencia Implementadas
| Proveedor | Protocolo / API | Requisito de Clave | Comportamiento |
| :--- | :--- | :--- | :--- |
| `rdap_whois` | RDAP (`rdap.org`) + fallback WHOIS TCP :43 | No | Prioriza RDAP; extrae fechas, registrador, org, país, NS, estados y contactos de abuso |
| `virustotal` | VirusTotal API v3 (`GET /domains/{id}`, `/ip_addresses/{id}`) | Sí | Solo lectura pasiva; nunca envía dominios/URLs a escaneo público |
| `otx` | AlienVault OTX API v1 (`general`) | Sí | Extrae Pulses, tags, familias de malware y adversarios documentados |
| `dns` | `dnspython` (`1.1.1.1`, `8.8.8.8`) | No | Consulta `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR` |
| `crt_sh` | Certificate Transparency (`crt.sh`) | No | Extrae certificados asociados, emisores, vigencia y subdominios |
| `urlhaus` | abuse.ch URLhaus (reutiliza `URLhausAdapter`) | Opcional | Consulta distribución de malware |
| `threatfox` | abuse.ch ThreatFox (reutiliza `ThreatFoxAdapter`) | Opcional | Búsqueda de IoCs activos |
| `abuseipdb` | AbuseIPDB v2 (reutiliza `AbuseIPDBAdapter`) | Sí | Consulta reputación de IP directa o IP `A` resuelta |

## 3. Seguridad Implementada (`backend/app/core/domain_security.py`)
- **Validación estricta de entrada**: detección automática de `DOMAIN`, `SUBDOMAIN`, `IPV4`, `IPV6`, `URL`; rechazo de caracteres de control, path traversal (`../`), credenciales embebidas (`user:pass@`) y esquemas distintos a `http`/`https`.
- **Anti-SSRF y Anti-DNS Rebinding**: integración con `SecurityGovernanceGuard` y verificación post-resolución DNS (`socket.getaddrinfo`) bloqueando RFC 1918, loopback, link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast y reservados.
- **Control de redirecciones**: `safe_http_get()` desactiva redirecciones automáticas y valida cada salto con `validate_outbound_url()`.
- **Protección de credenciales**: las API Keys se cifran con `Fernet` derivado de `SECRET_KEY` en `domain_provider_credentials` y nunca se devuelven en texto plano al frontend.
- **Aislamiento multi-organización**: todas las consultas, historial, comparaciones y exportaciones exigen `organization_id`.

## 4. Integraciones con OpenRecon
- **EASM** (`ScannerOrchestrator`): enriquece subdominios activos recién catalogados respetando caché (`trigger_source="EASM"`).
- **DRP** (`ScannerOrchestrator`): enriquece hallazgos de typosquatting sin auto-clasificar phishing únicamente por similitud de marca (`trigger_source="DRP"`).
- **Correlación y Riesgo**: reutiliza `CorrelationGraphEngine` y separa `technical_risk_score`, `external_reputation_score` y `confidence_score`.

## 5. Limitaciones Conocidas
1. **Conectores opcionales Shodan / Censys / Cisco Talos**: no incluidos en esta versión inicial; la arquitectura modular de `DomainIntelligenceService` permite añadirlos sin alterar la API.
2. **Caché**: implementada sobre SQLAlchemy (`cache_expires_at`) para compatibilidad directa con SQLite y PostgreSQL sin requerir Redis obligatorio en entornos locales.
3. **Exportación PDF**: se provee exportación nativa en **JSON, CSV y HTML**; la impresión a PDF se realiza desde el navegador sobre el informe HTML generado.
4. **RDAP / WHOIS**: algunos TLDs con privacidad GDPR redactan `registrant_org` y `country`, reportándose explícitamente como `REDACTED_OR_NOT_DISCLOSED` o `NOT_DISCLOSED`.
