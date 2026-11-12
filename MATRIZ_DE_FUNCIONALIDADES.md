# MATRIZ DE EQUIVALENCIA Y COMPARATIVA DE MERCADO — OPENRECON 2.0
> **Análisis Comparativo Frente a Soluciones Privativas y Open Source Líderes de la Industria**  
> **Fecha de Publicación:** 11 de Noviembre de 2026

---

## 1. RESUMEN COMPARATIVO GLOBAL

OpenRecon unifica en una sola plataforma abierta las tres disciplinas críticas de la ciberseguridad perimetral moderna:
1. **External Attack Surface Management (EASM):** Descubrimiento y mapeo continuo de activos perimetrales expuestos.
2. **Digital Risk Protection (DRP):** Detección de suplantación de marca, typosquatting, phishing y credenciales comprometidas.
3. **Cyber Threat Intelligence (CTI):** Monitoreo de amenazas, actores, campañas, Dark Web y correlación bajo el estándar STIX 2.1.

A continuación se presenta la matriz detallada de capacidades frente a las plataformas de referencia de la industria:
- **Fortinet FortiRecon**
- **Recorded Future Intelligence Cloud**
- **Palo Alto Cortex Xpanse**
- **CrowdStrike Falcon Exposure Management (FEM)**
- **SOCRadar Extended Threat Intelligence**
- **Cyble Vision**
- **OpenCTI Platform**

---

## 2. MATRIZ DE COMPARACIÓN FUNCIONAL

| Capacidad / Módulo de Ciberseguridad | OpenRecon 2.0 | Fortinet FortiRecon | Recorded Future | Palo Alto Cortex Xpanse | CrowdStrike Falcon Exp. | SOCRadar | Cyble Vision | OpenCTI Platform |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Modelo de Licenciamiento** | **Open Source (Libre)** | Privativo SaaS | Privativo SaaS | Privativo SaaS | Privativo SaaS | Privativo SaaS | Privativo SaaS | **Open Source (Apache 2.0)** |
| **Soberanía y Despliegue On-Prem / VPC** | **SÍ (Total)** | No (Cloud única) | No (Cloud única) | No (Cloud única) | No (Cloud única) | No (Cloud única) | No (Cloud única) | **SÍ (Total)** |
| **Descubrimiento Pasivo de Subdominios (CT Logs / DNS)** | **SÍ** | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ | No (Solo CTI) |
| **Sondeo Perimetral Activo no Destructivo** | **SÍ** | SÍ | Parcial | SÍ | SÍ | SÍ | Parcial | No |
| **Validación Forense en 5 Estados (Eliminación FP)** | **SÍ (100% Precisión)** | Parcial | No | Parcial | Parcial | No | No | No |
| **Mitigación de Falsos Positivos Cloud (403 / Redirects)** | **SÍ (Nativo)** | Parcial | No | SÍ | Parcial | No | No | No |
| **Integración con CISA KEV (Explotación Activa)** | **SÍ (1,779 CVEs)** | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ (Vía Conector) |
| **Integración con FIRST.org EPSS (Percentiles Reales)** | **SÍ (API en Vivo)** | Parcial | SÍ | SÍ | SÍ | Parcial | SÍ | SÍ (Vía Conector) |
| **Monitoreo de Typosquatting y Homóglifos (DRP)** | **SÍ** | SÍ | SÍ | No | No | SÍ | SÍ | No |
| **Verificación en Vivo de Registros MX de Clones** | **SÍ** | SÍ | SÍ | No | No | SÍ | SÍ | No |
| **Generador de Fichas de Takedown (RFC 2142)** | **SÍ** | SÍ | SÍ | No | No | SÍ | SÍ | No |
| **Telemetría de Ransomware y Víctimas DLS** | **SÍ (Ransomwatch)** | SÍ | SÍ | No | No | SÍ | SÍ | SÍ |
| **Colector Dark Web con Transporte Tor SOCKS5** | **SÍ (Defensivo)** | SÍ | SÍ | No | No | SÍ | SÍ | Parcial |
| **Manejo Seguro de Credenciales (k-Anonimato / Hashes)** | **SÍ (Estricto)** | SÍ | SÍ | No | No | SÍ | SÍ | No |
| **Soporte Nativo de Estándar STIX 2.1 / TAXII** | **SÍ (Bundle Export)** | Parcial | SÍ | No | No | Parcial | Parcial | **SÍ (Nativo)** |
| **Conector Desacoplado OpenCTI (GraphQL)** | **SÍ** | No | No | No | No | No | No | **Plataforma Core** |
| **Conector Desacoplado MISP (Eventos / Atributos)** | **SÍ** | No | Parcial | No | No | Parcial | No | SÍ |
| **Grafo Multidimensional de Correlación (8 Niveles)** | **SÍ** | Parcial | SÍ | SÍ | Parcial | Parcial | Parcial | **SÍ** |
| **Trazado de Rutas de Ataque (Attack Path Tracing)** | **SÍ** | No | SÍ | SÍ | SÍ | No | No | SÍ |
| **Scoring Explicable de Riesgo con Ponderación Transparente** | **SÍ** | No (Opaco) | No (Opaco) | No (Opaco) | No (Opaco) | No (Opaco) | No (Opaco) | No (Opaco) |
| **Gobernanza de Alcance (RoE) y Escudo Anti-SSRF** | **SÍ (Estricto)** | No expuesto | No expuesto | No expuesto | No expuesto | No expuesto | No expuesto | No expuesto |
| **Parada de Emergencia (Emergency Kill-Switch)** | **SÍ (1-Click)** | No | No | No | No | No | No | No |
| **Centro de Reportes Ejecutivos (HTML, PDF, STIX)** | **SÍ** | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ |
| **Consola SOC Unificada con 15 Módulos** | **SÍ** | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ | SÍ |

---

## 3. ANÁLISIS DE VENTAJAS DIFERENCIALES DE OPENRECON

### 1. Soberanía Absoluta de la Información
Las regulaciones internacionales (GDPR, HIPAA, ENS, ISO 27001) exigen en sectores críticos (defensa, banca, salud, gobierno) que la relación de activos, vulnerabilidades perimetrales y contraseñas expuestas **no sea transmitida a nubes privadas externas**. OpenRecon permite el despliegue dentro del perímetro del cliente, manteniendo el 100% de los datos bajo su custodia exclusiva.

### 2. Transparencia y Explicabilidad Forense
A diferencia de los "Exposure Scores" de herramientas comerciales (que calculan números opacos donde un falso positivo puede inflar arbitrariamente la puntuación de riesgo), OpenRecon ofrece:
- Desglose matemático claro: componentes CVSS, EPSS, KEV, exposición perimetral y ransomware.
- **Riesgo 0 garantizado para falsos positivos comprobados**.
- Registro de evidencia verificable: código de respuesta HTTP, cabeceras del servidor, registros DNS y hashes SHA-256 inmutables.

### 3. Precisión Forense Anti-Falsos Positivos
Muchas soluciones de escaneo masivo marcan como vulnerables endpoints que devuelven bloqueos HTTP 403 de balanceadores de carga en la nube (ej. Azure App Service o Cloudflare) o servidores con redirección obligatoria a HTTPS. El motor de validación perimetral de OpenRecon inspecciona técnicamente el protocolo y la infraestructura, evitando alertar innecesariamente al equipo de seguridad.

### 4. Coexistencia Armónica con OpenCTI y MISP
OpenRecon no pretende reemplazar a OpenCTI o MISP en lo que ya hacen con excelencia (gestión taxonómica profunda de amenazas, correlación de inteligencia de fuentes abiertas masivas). Por el contrario, se integra de forma desacoplada: OpenRecon actúa como el **sensor de superficie de ataque y el validador perimetral**, alimentando a OpenCTI con indicadores STIX 2.1 y consumiendo de éste los perfiles de actores y campañas activas.
