# ESTRATEGIA DE ASEGURAMIENTO DE CALIDAD (QA) — OPENRECON 3.0

> **Fecha:** 2026-11-14  
> **Principio Rector:** Ningún módulo se declara funcional sin pruebas reproducibles y criterios de aceptación medibles.

---

## 1. PIRÁMIDE DE PRUEBAS

| Nivel | Ubicación | Alcance | Política de Mocks |
|---|---|---|---|
| **Unitarias** | `tests/test_*.py` | Servicios, clasificadores, sanitizadores, reglas de riesgo | Mocks permitidos exclusivamente para APIs externas no disponibles en CI |
| **Integración** | `tests/integration/` | SQLAlchemy/SQLite WAL+FK, `EvidenceManager`, `BaseConnector`, STIX/CTI, AFP | Base de datos real (en memoria o aislada) |
| **Seguridad** | `tests/security/` | TLS estricto, MITM, SSRF, DNS Rebinding, Redirects, RoE, Kill-Switch distribuido, Auth/CORS, redacción de secretos | Sin desactivar validaciones de seguridad |
| **E2E & Rendimiento** | `tests/e2e/` | Flujo completo API (`Org -> Seed -> RoE -> Kill-Switch -> Metrics`), concurrencia HTTP y volumen AFP | Sin datos ficticios en producción |

---

## 2. CRITERIOS DE ACEPTACIÓN POR MÓDULO

- **Seguridad P0:** 0 ocurrencias de `verify=False` / `CERT_NONE` / `CURLOPT_SSL_VERIFYPEER=false`; 100% de secretos redactados en evidencias y logs; Kill-Switch persistente tras reinicio.
- **Persistencia:** 100% de consultas multiempresa filtradas por `organization_id`; migración Alembic limpia (`alembic upgrade head`).
- **Anti-Falsos Positivos:** 0% de cambios automáticos por IA en hallazgos `CRITICAL`/`HIGH`; procesamiento de >= 200 hallazgos en < 2.0 s.
- **Observabilidad:** Cabecera `X-Correlation-ID` en todas las respuestas y métricas válidas en `GET /metrics`.
