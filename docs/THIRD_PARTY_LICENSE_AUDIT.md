# AUDITORÍA DE LICENCIAS DE TERCEROS — OPENRECON 3.0

> **Fecha:** 2026-11-14  
> **Objetivo:** Evaluar compatibilidad de licencias, dependencias transitivas y obligaciones de atribución antes de distribuir o integrar herramientas externas.

---

## 1. MATRIZ DE HERRAMIENTAS Y COMPONENTES EXTERNOS

| Componente / Herramienta | Versión / Origen | Licencia | Modo de Integración | Compatibilidad & Obligaciones |
|---|---|---|---|---|
| **Zehef** | v2.2.1 (`scratch/Zehef`) | **GNU GPL-3.0** (Copyleft fuerte) | Adaptador derivado en `backend/app/services/email_intel/` | **Atención crítica:** Obliga a mantener código fuente abierto bajo GPL-3.0 / AGPLv3 y conservar avisos de modificación (Sec. 5.a) y archivo `LICENSE`. Incompatible con distribución propietaria cerrada. |
| **ProjectDiscovery (`subfinder`, `httpx`, `naabu`, `nuclei`)** | v2.6.6 / v1.6.0 / v2.3.1 / v3.2.4 | **MIT** (`subfinder`, `httpx`, `naabu`, `nuclei`) | Binarios CLI desacoplados (`subprocess`) | **Compatible.** Conservar avisos de copyright MIT en documentación/SBOM. |
| **Gitleaks** | CLI opcional | **MIT** | Invocación CLI desacoplada (`subprocess` en `GitHubIntelConnector`) | **Compatible.** Sin copia de código fuente. |
| **TruffleHog** | CLI opcional | **AGPL-3.0** | Invocación CLI desacoplada únicamente | **Compatible por aislamiento de proceso.** No enlazar ni copiar código fuente directamente en módulos no-AGPL. |
| **OpenCTI** | API GraphQL externa | **Apache-2.0** | Cliente HTTP GraphQL desacoplado (`opencti_client.py`) | **Compatible.** |
| **MISP** | API REST externa | **AGPL-3.0** | Cliente HTTP REST desacoplado (`misp_client.py`) | **Compatible por API remota.** |
| **FastAPI / Pydantic / SQLAlchemy / Alembic / Uvicorn** | Python backend | **MIT / BSD** | Dependencias Python | **Compatible.** |
| **httpx / dnspython / certifi / cryptography / tldextract** | Python backend | **BSD-3 / ISC / MPL-2.0 / Apache-2.0** | Dependencias Python | **Compatible.** |
| **Vis-Network / Tailwind CSS / FontAwesome** | Frontend `web_dashboard/` | **Apache-2.0 / MIT / CC BY 4.0 / SIL OFL** | Assets estáticos en `web_dashboard/assets/` | **Compatible.** Conservar atribuciones. |

---

## 2. DIRECTRICES DE CUMPLIMIENTO

1. **No copiar código de terceros** con licencias copyleft incompatibles dentro del núcleo; usar **integración desacoplada por CLI o API REST/GraphQL**.
2. Mantener `docs/ZEHEF_LICENSE_COMPLIANCE.md` y `scratch/Zehef/LICENSE` junto a cualquier distribución que incluya `email_intel`.
3. Mantener actualizado `docs/SBOM.md` ante cualquier nueva dependencia Python, PHP o binaria.
