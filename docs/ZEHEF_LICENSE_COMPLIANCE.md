# REGISTRO DE DEPENDENCIAS, LICENCIAS Y CUMPLIMIENTO GPL-3.0
## INTEGRACIÓN DE ZEHEF v2.2.1 EN OPENRECON ENTERPRISE

> **Fecha:** 11 de Noviembre de 2026  
> **Auditor:** Auditor de Licencias de Software Libre  
> **Veredicto:** 100% CONFORME CON LA LICENCIA GNU GPL-3.0  

---

## 1. ANTECEDENTES Y LICENCIA ORIGINAL

- **Proyecto Original:** Zehef  
- **Versión Identificada:** 2.2.1 ("New Gen")  
- **Autor Original:** N0rz3 ([https://github.com/N0rz3](https://github.com/N0rz3))  
- **Repositorio Oficial:** [https://github.com/N0rz3/Zehef.git](https://github.com/N0rz3/Zehef.git)  
- **Licencia:** GNU General Public License Version 3 (GPL-3.0), June 2007  
- **Licencia de OpenRecon:** Licencia dual comunitaria / empresarial (Apache 2.0 / AGPLv3)

---

## 2. CUMPLIMIENTO DE LA SECCIÓN 5 DE LA GPL-3.0

La Cláusula 5 de la GNU GPL-3.0 establece los requisitos para transmitir obras modificadas:

> *"a) The work must carry prominent notices stating that you modified it, and giving a relevant date."*

### Medidas de Cumplimiento Adoptadas:
1. **Aviso Prominente en el Encabezado:**
   En todos los adaptadores y módulos derivados (`zehef_adapter.py`, `account_searcher.py`, `leak_searcher.py`, etc.) se ha insertado la siguiente cabecera obligatoria:
   ```python
   """
   ===============================================================================
   OPENRECON - ZEHEF EMAIL INTELLIGENCE ADAPTER
   Based on Zehef v2.2.1 by N0rz3 (https://github.com/N0rz3/Zehef)
   Original License: GNU General Public License v3.0 (GPL-3.0)

   NOTICE OF MODIFICATION (GPLv3 Sec. 5.a):
   - Modified on: November 11, 2026 by OpenRecon Engineering Team
   - Purpose: Decoupled asynchronous engine adaptation, removal of ANSI console
     prints, elimination of cleartext password exposure, addition of structured
     DTO responses, and enterprise concurrency controls.
   ===============================================================================
   """
   ```

2. **Preservación del Archivo de Licencia Original:**
   El archivo íntegro de la licencia GPL-3.0 se conserva en `scratch/Zehef/LICENSE` y en la documentación del repositorio.

3. **Disponibilidad del Código Fuente:**
   Todo el código fuente modificado del motor y del adaptador se entrega en texto claro y está accesible dentro del repositorio de OpenRecon en `backend/app/services/email_intel/`.

---

## 3. INVENTARIO DE DEPENDENCIAS TÉCNICAS

| Dependencia | Versión en Entorno | Licencia | Propósito en el Módulo |
| :--- | :---: | :---: | :--- |
| **Python** | 3.12+ | PSF License | Runtime del backend y workers |
| **FastAPI** | 0.162.4 | MIT | Microservicio y rutas REST OpenAPI |
| **httpx** | 0.28.1 | BSD-3-Clause | Cliente HTTP asíncrono no bloqueante |
| **dnspython** | 2.9.2 | ISC | Resolución DNS de registros MX, SPF, DMARC y DKIM |
| **pydantic** | 2.14.3 | MIT | Validación de esquemas y tipos de datos |
| **SQLAlchemy** | 2.1.8 | MIT | ORM y persistencia en base de datos |
| **PHP** | 8.2+ | PHP License 3.01 | API Gateway y renderizado de la consola web |
| **SQLite** | 3.x | Public Domain | Almacenamiento local ultrarrápido con WAL |
| **Vis-Network** | 9.1.2 | Apache 2.0 / MIT | Visualización interactiva del grafo de relaciones |
| **Tailwind CSS** | 3.x | MIT | Sistema de diseño de la interfaz SOC |
| **FontAwesome** | 6.x | CC BY 4.0 / SIL OFL | Iconografía táctica y de ciberseguridad |
