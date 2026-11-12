# GUÍA DE INSTALACIÓN, CONFIGURACIÓN Y OPERACIÓN
## MÓDULO EMAIL INTELLIGENCE — OPENRECON ENTERPRISE

> **Versión:** 1.0 Enterprise  
> **Fecha:** 11 de Noviembre de 2026  

---

## 1. REQUISITOS PREVIOS

- **Python:** Versión 3.10 o superior (disponible en `backend/venv`).
- **PHP:** Versión 8.1 o superior con extensiones `pdo_sqlite`, `curl` y `json` (ej. `C:\xampp\php`).
- **Base de Datos:** SQLite 3 (`web_dashboard/openrecon.sqlite`).
- **Navegador Web:** Chrome, Edge, Firefox o Safari con soporte moderno de JavaScript y CSS Grid.

---

## 2. INICIALIZACIÓN DE LA BASE DE DATOS

Para aplicar las migraciones y crear las 7 tablas especializadas con sus índices de rendimiento:

```powershell
# En Windows PowerShell
$env:PYTHONPATH="backend"
& backend\venv\Scripts\python.exe backend\app\core\init_email_intel_db.py
```

Salida esperada:
```
INFO:email_intel.init_db:Connecting to operational SQLite DB: ...\web_dashboard\openrecon.sqlite
INFO:email_intel.init_db:Email Intelligence SQLite tables and indexes successfully created or updated.
INFO:email_intel.init_db:Email Intelligence SQLAlchemy tables initialized successfully.
```

---

## 3. EJECUCIÓN DE PRUEBAS DE ACEPTACIÓN

Para verificar el correcto funcionamiento de los 15 controles obligatorios y el API Gateway:

```powershell
$env:PYTHONPATH="backend"
& backend\venv\Scripts\python.exe -m unittest tests/test_email_intel_suite.py tests/test_php_gateway_suite.py
```

Resultado esperado:
```
Ran 21 tests in ~7.0s - OK
```

---

## 4. CÓMO USAR EL MÓDULO EN LA CONSOLA SOC

1. Acceda a la consola web de OpenRecon en su navegador (`http://localhost/web_dashboard/` o mediante su servidor local).
2. En la barra lateral izquierda, localice el grupo **OSINT & Operaciones Ofensivas**.
3. Haga clic en **Email Intelligence** (identificado con el icono `@`).
4. Para iniciar un nuevo análisis:
   - Pulse en **Nueva Investigación**.
   - Introduzca el correo corporativo o personal objetivo (ej. `usuario@empresa.com`).
   - Especifique el identificador del caso y la justificación legal (RoE).
   - Haga clic en **Iniciar Investigación**.
5. El sistema ejecutará en segundo plano las 5 fases de investigación:
   - Análisis de Dominio y Postura DNS (MX, SPF, DMARC, DKIM).
   - Búsqueda de Infecciones Info-Stealer (HudsonRock).
   - Detección de Presencia en Cuentas Digitales (GitHub, Adobe, Duolingo, Chess, Spotify, Twitter, etc.).
   - Menciones en Pastes Públicos.
   - Generación de Variantes e Hipótesis.
6. Explore las pestañas de **Detalle Caso**, **Leak Search**, **Account Search**, **Domain & DNS Intel**, **Grafo Relacional** y **Bóveda Forense**.
7. Si desea registrar el indicador en la base central de CTI de OpenRecon, pulse **Correlacionar como IoC**.
8. Exporte el informe forense en formato **JSON** o **CSV**.
