# INFORME DE SEGURIDAD Y PRIVACIDAD (APPSEC & DFIR)
## MÓDULO EMAIL INTELLIGENCE (INTEGRACIÓN ZEHEF v2.2.1)

> **Evaluación por:** Especialista en Seguridad de Aplicaciones (AppSec), Especialista DFIR y Oficial de Privacidad  
> **Fecha:** 11 de Noviembre de 2026  
> **Resultado:** APROBADO CON CONTROLES ESTRICTOS  

---

## 1. CONTROL DE PRIVACIDAD Y DATOS SENSIBLES (K-ANONYMITY)

1. **Prohibición de Contraseñas en Texto Claro:**
   - El script original de Zehef (`modules/breaches/hudsonrock.py`) imprimía `top_passwords` por consola.
   - **Remediación Aplicada:** En `backend/app/services/email_intel/leak_searcher.py`, la captura de contraseñas fue completamente eliminada del flujo de procesamiento. Ni en memoria ni en disco se almacenan claves en texto claro. Solo se preservan estadísticas de compromiso (cantidad de servicios corporativos y de usuario).
2. **Enmascaramiento de Identidad (K-Anonymity):**
   - Las direcciones IP y nombres de cuenta se procesan con la utilidad `mask_pii()` para evitar la sobreexposición en reportes ejecutivos.
3. **Justificación Legal Obligatoria (RoE):**
   - El formulario de investigación exige un campo obligatorio de *Autorización / Justificación Legal*. Si no se proporciona o tiene menos de 5 caracteres, el API Gateway rechaza la petición con código HTTP 400.

---

## 2. BLINDAJE CONTRA VECTORES DE ATAQUE (OWASP TOP 10)

### 2.1 Prevención de Server-Side Request Forgery (SSRF)
- **Riesgo:** Un atacante podría introducir correos apuntando a dominios internos (`admin@127.0.0.1`, `user@localhost`, `probe@169.254.169.254`, `host@corp.local`) para forzar al servidor a sondear la red interna.
- **Control Implementado:** Doble escudo anti-SSRF:
  1. En Pydantic (`schemas.py`): Validación regex RFC 5322 y lista negra de dominios loopback, link-local y sufijos `.local` / `.internal`.
  2. En el API Gateway (`api.php`): Bloqueo preventivo antes de emitir cualquier consulta DNS o HTTP.

### 2.2 Prevención de Inyección de Comandos (Command Injection)
- **Riesgo:** Ejecutar herramientas externas concatenando entradas de usuario sin escapar.
- **Control Implementado:**
  - El motor Zehef fue integrado como código Python nativo asíncrono, **sin invocar la terminal con comandos concatenados ni shells arbitrarias**.
  - El invocador del worker (`run_worker.py`) utiliza `escapeshellarg()` en PHP para pasar únicamente el identificador único de investigación validado (`EI-YYYYMMDD-XXXXXX`).

### 2.3 Prevención de Inyección SQL
- Todas las consultas a SQLite y PostgreSQL se ejecutan mediante sentencias parametrizadas con marcadores de posición (`?` en PDO y tuplas en SQLAlchemy).
- Cero concatenación directa de cadenas en cláusulas SQL.

### 2.4 Control de Concurrencia y Timeouts
- Cada sonda hacia servicios externos tiene un límite de tiempo estricto (5.0 a 8.0 segundos) en `httpx.AsyncClient`.
- Concurrencia limitada mediante `httpx.Limits(max_connections=20)` para prevenir la denegación de servicio accidental o bloqueo por parte de los proveedores.

---

## 3. AUDITORÍA FORENSE Y CADENA DE CUSTODIA (DFIR)

- Toda evidencia recolectada se firma criptográficamente con **SHA-256** del payload original.
- Los registros en `email_intel_evidence` conservan su sello temporal en formato ISO 8601 (UTC).
- La modificación o eliminación de investigaciones respeta integridad referencial con borrado en cascada controlado (`ON DELETE CASCADE`).
