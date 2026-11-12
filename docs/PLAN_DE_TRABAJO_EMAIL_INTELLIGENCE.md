# PLAN DE TRABAJO INTEGRAL: MÓDULO EMAIL INTELLIGENCE (ZEHEF OSINT)
## Plataforma Abierta de Ciberseguridad Defensiva y Exposición Perimetral: OpenRecon

**Fecha de Actualización:** 12 de Noviembre de 2026  
**Versión:** 2.2.1-Enterprise-GA  
**Comité Evaluador:** Equipo Multidisciplinario de 13 Especialistas  

---

## 1. OBJETIVO DEL PLAN DE TRABAJO

Consolidar, integrar, asegurar y verificar el módulo profesional **EMAIL INTELLIGENCE** dentro de la suite OpenRecon, basándose en la investigación pasiva de fuentes abiertas, mitigación de Info-Stealers, presencia en plataformas digitales, postura de seguridad DNS (SPF/DMARC/MX), generación heurística de variantes y bóveda criptográfica de evidencias forenses, garantizando una ejecución desacoplada, observable y reactiva en tiempo real.

---

## 2. ETAPAS DEL PLAN DE TRABAJO Y ESTADO DE EJECUCIÓN

| Etapa | Descripción y Entregables | Responsable(s) | Estado |
| :--- | :--- | :--- | :--- |
| **Etapa 1: Auditoría y Cumplimiento** | Análisis de dependencias, auditoría de licencia GPL-3.0 (Zehef v2.2.1), inspección de arquitectura SQLite + FastAPI + PHP/Apache. | Auditor de Licencias, Arquitecto de Software | **COMPLETADO (100%)** |
| **Etapa 2: Motor Central Python** | Implementación del adaptador modular `backend/app/services/email_intel/` (ZehefAdapter, LeakSearcher, AccountSearcher, PasteSearcher, DomainIntelEngine, EmailGenerator, RiskScorer, Orchestrator). | Ingeniero Python, Especialista OSINT | **COMPLETADO (100%)** |
| **Etapa 3: Pasarela API y Persistencia** | Rutas OpenAPI FastAPI (`/api/v1/email-intel/`), endpoints de pasarela PHP (`api.php`), y creación de 7 tablas SQLite con claves foráneas. | Ingeniero de BD, Arquitecto de Software | **COMPLETADO (100%)** |
| **Etapa 4: Interfaz de Usuario y SOC UX** | Panel interactivo `web_dashboard/email_intel.php` con 9 subsecciones, métricas de impacto forense, visualizador de grafos Vis.js y modal de caso. | Especialista UX/UI para SOC | **COMPLETADO (100%)** |
| **Etapa 5: Diagnóstico y Resolución RCA** | Corrección de spawning en segundo plano en Apache/XAMPP, junctions NTFS para sincronización de código y entorno virtual Python. | DevSecOps, Especialista AppSec | **COMPLETADO (100%)** |
| **Etapa 6: Sincronización en Tiempo Real** | Implementación de sondeo reactivo (Polling `0% -> 100%`) en frontend, badge dinámico de estado y renderizado de Bóveda Forense. | Especialista UX/UI, Arquitecto de Software | **COMPLETADO (100%)** |
| **Etapa 7: Control Forense y DFIR** | Almacenamiento inmutable de evidencias con cálculo SHA-256 de contenido crudo y sellado de tiempo UTC. | Especialista DFIR, Ingeniero de BD | **COMPLETADO (100%)** |
| **Etapa 8: Pruebas Automatizadas** | Batería de 22 pruebas unitarias y de integración pasando al 100% (validación RFC 5322, anti-SSRF, scraping ético, gateway PHP). | QA Automated Engineer | **COMPLETADO (100%)** |
| **Etapa 9: Documentación y Versionado** | Manuales técnicos, auditoría de seguridad, informe de limitaciones conocidas y sincronización con repositorio GitHub. | DevSecOps, Especialista Privacidad | **COMPLETADO (100%)** |

---

## 3. APORTES ESPECÍFICOS DEL COMITÉ DE 13 ESPECIALISTAS

1. **Arquitecto de Software Senior:**
   - Diseñó el ciclo de vida reactivo con polling asíncrono para desacoplar las peticiones HTTP del tiempo de ejecución de la recolección OSINT.
2. **Ingeniero Senior de Python:**
   - Construyó el orquestador asíncrono con control de concurrencia y ejecución desacoplada por proceso mediante `run_worker.py`.
3. **Especialista en Integración OSINT:**
   - Adaptó los módulos de Zehef 2.2.1 para consultas no intrusivas sin violación de términos de servicio.
4. **Investigador de Inteligencia de Fuentes Abiertas:**
   - Estandarizó la clasificación de presencia en cuentas en: *Confirmado, Probable, No encontrado, Inconcluso y Error*.
5. **Analista de Threat Intelligence:**
   - Integró correlación bidireccional de correos y dominios hacia los contenedores de IoCs tácticos (OpenCTI / DarkIntel).
6. **Especialista en DFIR:**
   - Implementó la Bóveda de Evidencias Criptográfica (`email_intel_evidence`) con trazabilidad de custodia y hashes SHA-256 inmutables.
7. **Ingeniero de Bases de Datos:**
   - Modeló 7 tablas normalizadas en SQLite con integridad referencial en cascada e índices optimizados para alta concurrencia de lectura.
8. **Especialista UX/UI para SOC:**
   - Desarrolló los componentes visuales: dial explicable de riesgo (0-100), barra de progreso dinámica, tarjetas métricas y renderizado de grafo relacional en Vis.js.
9. **Ingeniero DevSecOps:**
   - Resolvió los bloqueos de ejecución en entornos Windows Apache/XAMPP utilizando junctions NTFS y redirección de logs de diagnóstico.
10. **Especialista en Seguridad de Aplicaciones (AppSec):**
    - Estableció controles anti-SSRF bloqueando dominios internos/privados (RFC 1918) y saneamiento estricto de parámetros contra inyección de comandos.
11. **Auditor de Licencias de Software Libre:**
    - Documentó el cumplimiento estricto de la licencia GPL-3.0 de Zehef en `docs/ZEHEF_LICENSE_COMPLIANCE.md`.
12. **QA Engineer Especializado en Pruebas Automatizadas:**
    - Desarrolló y verificó la suite de pruebas automatizadas con 22 pruebas superadas con éxito.
13. **Especialista en Privacidad y Protección de Datos:**
    - Aseguró el principio de *K-Anonymity*, enmascaramiento de direcciones IP/hostnames y prohibición total de almacenamiento de contraseñas en texto claro.

---

## 4. INVENTARIO DE ARCHIVOS PRINCIPALES

- **Motor Backend:**
  - `backend/app/services/email_intel/zehef_adapter.py`
  - `backend/app/services/email_intel/leak_searcher.py`
  - `backend/app/services/email_intel/account_searcher.py`
  - `backend/app/services/email_intel/domain_intel_engine.py`
  - `backend/app/services/email_intel/paste_searcher.py`
  - `backend/app/services/email_intel/email_generator.py`
  - `backend/app/services/email_intel/risk_scorer.py`
  - `backend/app/services/email_intel/orchestrator.py`
  - `backend/app/services/email_intel/run_worker.py`
  - `backend/app/services/email_intel/schemas.py`
- **Pasarela y Rutas:**
  - `backend/app/api/v1/endpoints/email_intel.py`
  - `web_dashboard/api.php`
- **Interfaz Gráfica:**
  - `web_dashboard/email_intel.php`
  - `web_dashboard/index.php`
- **Documentación:**
  - `docs/PLAN_DE_TRABAJO_EMAIL_INTELLIGENCE.md`
  - `docs/ARQUITECTURA_EMAIL_INTELLIGENCE.md`
  - `docs/AUDITORIA_INTEGRACION_ZEHEF_EMAIL_INTEL.md`
  - `docs/EMAIL_INTEL_SECURITY_AUDIT.md`
  - `docs/ZEHEF_LICENSE_COMPLIANCE.md`
  - `docs/EMAIL_INTEL_KNOWN_LIMITATIONS.md`
  - `docs/EMAIL_INTEL_INSTALL_GUIDE.md`
  - `docs/ENTREGABLE_FINAL_EMAIL_INTELLIGENCE.md`
- **Batería de Pruebas:**
  - `tests/test_email_intel_suite.py` (15 pruebas unitarias de motor)
  - `tests/test_php_gateway_suite.py` (7 pruebas de pasarela API y evidencias)
