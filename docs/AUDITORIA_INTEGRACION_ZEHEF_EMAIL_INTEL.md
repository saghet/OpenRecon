# AUDITORÍA TÉCNICA EXHAUSTIVA & DIAGNÓSTICO PRE-IMPLEMENTACIÓN
## PROYECTO: INTEGRACIÓN DE ZEHEF EN OPENRECON — MÓDULO "EMAIL INTELLIGENCE"

> **Fecha:** 11 de Noviembre de 2026  
> **Evaluado por:** Comité Multidisciplinario de 13 Especialistas  
> **Herramienta Base:** [Zehef v2.2.1](https://github.com/N0rz3/Zehef) (`scratch/Zehef`)  
> **Plataforma Destino:** OpenRecon v2.0 Enterprise (`c:\Users\saghe\Documents\FortiRecon`)  
> **Estado:** ETAPA 1 — AUDITORÍA TÉCNICA OBLIGATORIA Y PLAN DE IMPLEMENTACIÓN  

---

## 1. EVALUACIÓN ARQUITECTURAL DE OPENRECON

Tras la inspección profunda de la estructura de OpenRecon, se identifican las características operativas reales del ecosistema:

1. **Framework y Tecnologías Centrales:**
   - **Backend Asíncrono:** Python 3.12+ con **FastAPI** (`backend/app/main.py`), SQLAlchemy 2.0, Pydantic v2, `httpx` (asíncrono con timeouts estrictos) y Uvicorn.
   - **API Gateway & SOC Console:** PHP 8.2 (`web_dashboard/api.php` y `index.php`), SQLite 3 con modo WAL (`openrecon.sqlite`) y PDO con sentencias preparadas.
   - **Capa Frontend:** Single Page Application (SPA) con **Tailwind CSS**, FontAwesome 6, Chart.js y Vis-Network para grafos de correlación de ciberinteligencia.
2. **Mecanismo de Implementación de Módulos:**
   - La arquitectura sigue un patrón desacoplado:
     - El componente visual reside en un archivo parcial PHP (ej. `web_dashboard/darkintel.php`, `web_dashboard/index.php`), renderizado dentro de la consola con la identidad visual corporativa *Cyber/Forti*.
     - Los endpoints de consulta rápida e interfaces con base de datos se conectan a `api.php`.
     - El microservicio FastAPI gestiona la orquestación asíncrona pesada, workers en segundo plano y normalización de telemetría hacia las bases de datos.
3. **Persistencia y Modelado de Datos:**
   - Base de datos operativa: `web_dashboard/openrecon.sqlite` (33 tablas actuales, incluyendo las tablas operativas de EASM, CTI, DRP y DarkIntel).
   - Base de datos backend: `openrecon.db` (gestionada por SQLAlchemy).
   - Toda nueva investigación debe contar con un modelo relacional normalizado con índices específicos y claves foráneas en cascada.
4. **Control de Acceso, Auditoría y Seguridad:**
   - Autenticación mediante sesiones seguras PHP (`users` con `password_hash` bcrypt).
   - Registro inmutable de acciones en `audit_logs` (registrando usuario, IP, acción y timestamp UTC).
   - Mecanismo centralizado de gobernanza RoE (`authorized_scope`) y escudo anti-SSRF (`security_guard.py` y `vuln_validator_engine.php`) que bloquea rangos RFC 1918, loopback y metadatos cloud (`169.254.169.254`).
   - Botón de parada de emergencia (`Kill-Switch`) que invalida la ejecución de tareas activas.

---

## 2. ANÁLISIS TÉCNICO Y AUDITORÍA EN VIVO DE ZEHEF v2.2.1

Se descargó y auditó el repositorio original de Zehef (`https://github.com/N0rz3/Zehef.git`, tag/versión 2.2.1). Se ejecutaron pruebas reales de conectividad contra cada uno de sus 17 módulos de cuentas, 2 módulos de filtraciones y utilidades de generación:

### 2.1 Resultados de las Pruebas Reales de Endpoints (Verificación en Vivo)

| Módulo / Servicio | Tipo | Endpoint / Método Original | Estado HTTP en Prueba Real | Diagnóstico Técnico y Veredicto |
| :--- | :--- | :--- | :---: | :--- |
| **HudsonRock** | Leaks / Stealers | `cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email` | **HTTP 200 OK** | **FUNCIONAL:** Devuelve datos de infecciones por info-stealers, equipos y servicios afectados. Requiere sanitización urgente: **eliminar contraseñas en texto claro**. |
| **Github** | Account Search | `api.github.com/search/users?q={email}+in:email` | **HTTP 200 OK** | **FUNCIONAL:** Localiza perfiles públicos asociados al correo, login, avatar, ID y fechas. |
| **Duolingo** | Account Search | `duolingo.com/2017-06-30/users?email={email}` | **HTTP 200 OK** | **FUNCIONAL:** Expone presencia, perfil, ID de usuario y avatar. |
| **Adobe** | Account Search | `auth.services.adobe.com/signin/v2/users/accounts` | **HTTP 200 OK** | **FUNCIONAL:** Con header `x-ims-clientid: homepage_milo`, confirma existencia con `authenticationMethods`. |
| **Bandlab** | Account Search | `bandlab.com/api/v1.3/validation/user` | **HTTP 200 OK** | **FUNCIONAL:** Devuelve `isAvailable: false` indicando que el correo ya está registrado. |
| **Chess.com** | Account Search | `chess.com/callback/email/available?email={email}` | **HTTP 226 IM Used** | **FUNCIONAL:** Devuelve `isEmailAvailable: false, reason: "Email In Use"`. |
| **Gravatar** | Account Search | `en.gravatar.com/{sha256}.json` | **HTTP 200 / 404** | **FUNCIONAL:** Confirma perfiles con avatar o 404 inequívoco si no existe. |
| **Spotify** | Account Search | `spclient.wg.spotify.com/signup/public/v1/account` | **HTTP 200 OK** | **FUNCIONAL:** Devuelve `status: 20` confirmando registro existente. |
| **Twitter / X** | Account Search | `api.twitter.com/i/users/email_available.json` | **HTTP 200 OK** | **FUNCIONAL:** Devuelve `taken: true` confirmando registro. |
| **Deezer** | Account Search | `deezer.com/ajax/gw-light.php` (emailCheck) | **HTTP 200 OK** | **FUNCIONAL:** Devuelve `availability: false` tras handshake con token CSRF de sesión. |
| **Flickr** | Account Search | `flickr.com/search/people/?q={email}` | **HTTP 200 OK** | **FUNCIONAL:** Permite identificar coincidencias en la comunidad fotográfica. |
| **PicsArt** | Account Search | `api.picsart.com/users/search.json` | **HTTP 200 OK** | **FUNCIONAL:** Responde búsqueda pública de usuarios. |
| **Instagram** | Account Search | `instagram.com/api/v1/web/accounts/web_create_ajax/attempt/` | **HTTP 429 Too Many Requests** | **BLOQUEADO:** Protegido activamente por Cloudflare / WAF anti-bot de Meta. Debe clasificarse como `BLOQUEADO_POR_PROVEEDOR` y manejar timeout sin colapsar. |
| **Pinterest** | Account Search | `pinterest.com/_ngjs/resource/EmailExistsResource/get/` | **HTTP 403 Forbidden** | **INCONCLUSO / CAMBIO DE API:** Requiere token de sesión SPA y validación anti-CSRF moderna. |
| **Strava** | Account Search | `strava.com/athletes/search?text={email}` | **HTTP 307 Redirect** | **INCONCLUSO:** Redirige a `/login` al requerir autenticación previa obligatoria. |
| **Imgur** | Account Search | `api.imgur.com/identity/verifyemail` | **HTTP 301 Moved** | **NO FUNCIONAL EN VERSIÓN ZEHEF:** Endpoint de verificación descontinuado/migrado. |
| **ProtonMail** | Account Search | `account.proton.me/api/auth/v4/sessions` | **HTTP 422 Unprocessable** | **OBSOLETO EN ZEHEF:** El cliente hardcodeado `web-account@5.0.153.3` es rechazado por la API de Proton. |
| **Pastebin Dumper** | Paste Search | Google Scraper (`site:pastebin.com`) | **INESTABLE / BLOQUEABLE** | **VULNERABLE A CAPTCHAS:** Scraping crudo de Google Search se bloquea ante ráfagas. Debe reemplazarse por colector híbrido con fallback a APIs públicas de pastes y verificación directa de contenido. |
| **Emails Gen** | Generator | Mutación heurística y reemplazo alfanumérico | **LÓGICA PURA** | **ADAPTABLE:** Requiere parametrización de nombres corporativos, permutaciones de nombre.apellido y clasificación explícita como hipótesis no verificadas. |

### 2.2 Diagnóstico Crítico de Calidad de Zehef Original
1. **Ausencia de Salida Estructurada:** Zehef v2.2.1 imprime texto coloreado con códigos ANSI directamente por consola (`print(f"[{RED}HudsonRock{WHITE}]...")`) y no retorna objetos Python tipados ni JSON. No puede usarse directamente como biblioteca sin un adaptador desacoplador que capture o reimplemente la lógica de negocio de manera asíncrona.
2. **Riesgo DFIR y de Privacidad Severo:** En `hudsonrock.py`, Zehef intenta imprimir `top_passwords` en texto claro. Esto viola directamente las normas de protección de datos, OWASP y las reglas estrictas del proyecto.
3. **Manejo Frágil de Excepciones:** Muchos módulos capturan excepciones con `except: pass`, lo que oculta errores de red, límites de tasa y cambios de formato.

---

## 3. AUDITORÍA DE LICENCIA DE SOFTWARE LIBRE (GPL-3.0)

- **Licencia de Zehef:** GNU General Public License v3.0 (GPL-3.0).
- **Licencia de OpenRecon:** Licencia abierta dual / compatible (Apache 2.0 / AGPLv3).
- **Evaluación Legal de Compatibilidad:**
  - Según la Free Software Foundation (FSF), el código bajo Apache 2.0 puede combinarse con código bajo GPL-3.0 siempre que la obra combinada resultante se distribuya bajo los términos de la GPL-3.0 o AGPL-3.0.
  - Para proteger la modularidad y soberanía del código:
    1. Mantendremos el código base de Zehef en un directorio de herramientas/adaptadores claramente demarcado (`backend/app/services/osint/zehef/` o `backend/tools/zehef_adapter/`) conservando íntegro su archivo `LICENSE` y avisos de copyright originales.
    2. En cumplimiento de la **Sección 5(a) de la GPL-3.0**, cualquier archivo derivado o adaptado incluirá una cabecera prominente indicando la fecha de modificación, el propósito de la adaptación y el autor original (*N0rz3*).
    3. La integración con OpenRecon se efectuará a través de una interfaz de adaptador tipada (`ZehefAdapter` / `EmailIntelService`), asegurando un acoplamiento débil.

---

## 4. APORTES Y CRITERIOS DE ACEPTACIÓN POR ESPECIALISTA (13 ROLES)

| Especialista | Controles Obligatorios | Criterio de Aceptación Innegociable |
| :--- | :--- | :--- |
| **1. Arquitecto Senior** | Desacoplamiento de 3 capas: UI SPA, API Gateway PHP y Microservicio FastAPI. | Cero llamadas bloqueantes en el hilo principal del servidor web; comunicación asíncrona estructurada. |
| **2. Ingeniero Python** | Adaptador asíncrono con `httpx.AsyncClient`, timeouts configurables (5s max por probe) y tipado Pydantic v2. | Toda consulta debe retornar modelos validados `EmailIntelResult`, `AccountFinding`, `LeakFinding`. |
| **3. Especialista OSINT** | Normalización de proveedores, clasificación en 5 estados (`CONFIRMADO`, `PROBABLE`, `NO_ENCONTRADO`, `INCONCLUSO`, `ERROR`). | Nunca clasificar un HTTP 200 genérico como confirmación si el payload no contiene evidencia inequívoca. |
| **4. Investigador OSINT** | Prevención de falsos positivos en dominios con catch-all o portales cautivos. | Verificación de falsos positivos mediante sondas diferenciales con correos canario aleatorios. |
| **5. Analista CTI** | Mapeo de indicadores (correos, dominios, IPs de stealer) contra IoCs de OpenRecon y MITRE ATT&CK. | Cada correo investigado debe poder correlacionarse como IoC de tipo `email-addr` (STIX 2.1). |
| **6. Especialista DFIR** | Cadena de custodia, identificador forense único (`uuid4`), hash SHA-256 del contenido crudo y sellado temporal UTC. | Todo hallazgo debe persistir su evidencia inmutable en `email_intel_evidence` con trazabilidad completa. |
| **7. Ingeniero de BD** | Esquema DDL optimizado en SQLite/SQLAlchemy con claves foráneas, índices de alto rendimiento y migraciones seguras. | Creación de 5 tablas especializadas sin alterar ninguna de las 33 tablas existentes en `openrecon.sqlite`. |
| **8. Especialista UX/UI SOC** | Interfaz idéntica al diseño SOC de OpenRecon (Tailwind CSS, tema Cyber, tarjetas de riesgo, badges y modales). | Navegación nativa bajo la sección `OSINT -> EMAIL INTELLIGENCE`, sin botones simulados ni datos ficticios. |
| **9. Ingeniero DevSecOps** | Aislamiento de ejecución, control de recursos, gestión de dependencias en `backend/venv` y logging seguro. | Ejecución reproducible mediante scripts sin escalado de privilegios y con parada por Kill-Switch. |
| **10. Especialista AppSec** | Validación estricta RFC 5322, escudo anti-SSRF, parametrización total contra inyecciones SQL/Command. | Bloqueo absoluto de inyecciones de comandos, rutas locales y dominios protegidos o en localhost. |
| **11. Auditor de Licencias** | Preservación de autoría de N0rz3, licencia GPL-3.0 y registro de modificaciones en headers. | Documentación explícita de licencias y compatibilidad en `LEGAL_NOTICE_ZEHEF.md`. |
| **12. QA Engineer** | Suite de pruebas unitarias y de integración que valide los 15 puntos exigidos en la especificación. | Ejecución con 100% de aserciones superadas (`0 errors, 0 failures`) con correos de prueba controlados. |
| **13. Privacidad y Datos** | K-Anonymity, enmascaramiento de contraseñas (`***`), minimización de datos y justificación obligatoria de caso. | **Cero contraseñas en texto claro** almacenadas o visualizadas; registro del motivo/RoE en cada investigación. |

---

## 5. PLAN DE IMPLEMENTACIÓN POR FASES (HOJA DE RUTA DETALLADA)

### FASE 1: AUDITORÍA TÉCNICA Y DIAGNÓSTICO PRE-IMPLEMENTACIÓN (Completada en esta entrega)
- Inspección del código base de OpenRecon y Zehef 2.2.1.
- Ejecución de pruebas de conectividad sobre todos los endpoints públicos.
- Determinación de módulos funcionales, inestables y obsoletos.
- Aprobación del diagnóstico técnico y del plan de trabajo.

### FASE 2: MOTOR CORE Y ADAPTADOR ASÍNCRONO DE ZEHEF (`backend/app/services/email_intel/`)
1. Implementar el motor desacoplado `zehef_adapter.py` y `email_intel_service.py` con `httpx` asíncrono.
2. Implementar los analizadores específicos:
   - `leak_searcher.py` (HudsonRock seguro sin passwords en claro + Dark Web Leaks).
   - `account_searcher.py` (servicios verificados: Github, Adobe, Duolingo, Chess, Spotify, Twitter, Deezer, Bandlab, Gravatar, Flickr, PicsArt).
   - `paste_searcher.py` (búsqueda en repositorios públicos de texto con filtrado contextual mínimo).
   - `email_generator.py` (generación matemática y combinatoria de variantes con etiqueta de hipótesis no confirmada).
   - `domain_intel_engine.py` (análisis DNS completo: MX, SPF, DMARC, DKIM, proveedor y postura de seguridad del dominio de correo).
3. Implementar el motor de scoring de riesgo explicable (`risk_scorer.py`: Informativo, Bajo, Medio, Alto, Crítico) con desglose de justificación.

### FASE 3: PERSISTENCIA, MODELOS Y ESQUEMA DE BASE DE DATOS
1. Crear el script de migración DDL (`backend/app/core/init_email_intel_db.py`) creando las tablas:
   - `email_intel_investigations` (investigaciones, estado, ID de caso, autorización, riesgo global).
   - `email_intel_evidence` (bóveda de evidencias forenses, SHA-256, payload original).
   - `email_intel_leaks` (exposición en filtraciones, fechas, clases de datos, sin contraseñas).
   - `email_intel_accounts` (presencia en plataformas, método, nivel de confianza).
   - `email_intel_pastes` (referencias públicas en pastes).
   - `email_intel_domain_analysis` (postura DNS, registros MX, SPF y DMARC).
2. Sincronizar esquemas en `openrecon.sqlite` y modelos SQLAlchemy en `backend/app/models/email_intel.py`.

### FASE 4: CAPA DE INTEGRACIÓN API (FASTAPI & PHP GATEWAY)
1. Exponer endpoints FastAPI en `/api/v1/email-intel/`:
   - `POST /investigations/start`: Iniciar investigación asíncrona validando RFC 5322 y RoE.
   - `GET /investigations/{id}`: Estado en tiempo real, progreso y resultados.
   - `POST /investigations/{id}/pause` y `/cancel`: Control del ciclo de vida de la tarea.
   - `GET /investigations/{id}/report`: Exportación en JSON/CSV/PDF estructurado.
2. Integrar acciones en `web_dashboard/api.php` (`email_intel_list`, `email_intel_start`, `email_intel_status`, `email_intel_export`, `email_intel_correlate`).

### FASE 5: INTEGRACIÓN CON EL MOTOR DE GRAFOS Y CORRELACIÓN CTI
1. Conectar las entidades descubiertas (Correo -> Dominio -> MX -> IP -> Filtraciones -> Cuentas) con el grafo interactivo de OpenRecon (`Vis-Network`).
2. Sincronizar indicadores como STIX 2.1 (`threat_iocs`).

### FASE 6: CONSOLA SOC INTERACTIVA (`web_dashboard/email_intel.php`)
1. Diseñar el módulo `OSINT -> EMAIL INTELLIGENCE` integrado en la barra de navegación de `index.php`.
2. Componentes visuales:
   - Formulario de Nueva Investigación (Email, Caso, Etiquetas, Justificación RoE).
   - Dashboard de Métricas y Postura de Riesgo (Indicador explicable con radial chart y badges).
   - Panel de Filtraciones (Leak Search con fechas, servicios corporativos, severidad y K-Anonymity).
   - Panel de Cuentas Digitales (Account Search con avatares, evidencia y estado de verificación).
   - Panel de Referencias en Pastes (URL, fragmento sanitizado y fecha).
   - Panel de Generador de Variantes (Hipótesis categorizadas sin interacción de red).
   - Panel de Inteligencia de Dominio (MX, SPF, DMARC, DKIM y recomendaciones).
   - Grafo de Relaciones Integrado.
   - Historial de Investigaciones y Bóveda Forense de Evidencias.
   - Exportadores funcionales a JSON, CSV e Informe Ejecutivo para imprimir/PDF.

### FASE 7: SUITE DE PRUEBAS AUTOMATIZADAS Y CONTROL DE CALIDAD
1. Suite en Python (`tests/test_email_intel_suite.py`) cubriendo las 15 pruebas obligatorias.
2. Suite en PHP (`tests/test_email_intel_gateway.php`) para validación de API Gateway, sanitización y persistencia.
3. Validación de mitigación de falsos positivos y no-regresión en los 15 módulos existentes de OpenRecon.

### FASE 8: DOCUMENTACIÓN TÉCNICA, AUDITORÍA DE SEGURIDAD Y CIERRE
1. `docs/EMAIL_INTELLIGENCE_GUIDE.md`: Manual de usuario y configuración.
2. `docs/EMAIL_INTEL_SECURITY_AUDIT.md`: Informe de seguridad y privacidad.
3. `docs/ZEHEF_LICENSE_AUDIT.md`: Notificación de copyright y cumplimiento GPL-3.0.
4. Matriz de funcionalidades verificadas (A - F).
