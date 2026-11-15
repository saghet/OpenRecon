# ROADMAP OPENRECON 3.0

> **Última Actualización:** 2026-11-14

---

## ESTADO DE FASES

| Fase | Nombre | Estado | Evidencia Principal |
|---|---|---|---|
| **Fase 0** | Auditoría Obligatoria y Línea Base | COMPLETADA | [AUDIT_OPENRECON_3.md](AUDIT_OPENRECON_3.md) |
| **Fase 1** | Hardening de Seguridad Crítica (P0) | COMPLETADA | [SECURITY_HARDENING_REPORT.md](SECURITY_HARDENING_REPORT.md), `tests/security/test_p0_security_hardening.py` |
| **Fase 2** | Consolidación de Arquitectura y Persistencia | COMPLETADA | [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md), `backend/alembic/`, `tests/integration/test_phase2_architecture.py` |
| **Fase 3** | Domain, Email, GitHub y Web Security Intel | COMPLETADA | [EMAIL_INTELLIGENCE_REVIEW.md](EMAIL_INTELLIGENCE_REVIEW.md), [THIRD_PARTY_LICENSE_AUDIT.md](THIRD_PARTY_LICENSE_AUDIT.md), `tests/integration/test_phase3_intelligence.py` |
| **Fase 4** | CTI, Correlación y Anti-Falsos Positivos | COMPLETADA | [CTI_AND_CORRELATION_REVIEW.md](CTI_AND_CORRELATION_REVIEW.md), [ANTI_FALSE_POSITIVE_STRATEGY.md](ANTI_FALSE_POSITIVE_STRATEGY.md), `tests/integration/test_phase4_cti_and_afp.py` |
| **Fase 5** | Estrategia QA, E2E y Rendimiento | COMPLETADA | [OPENRECON_QA_STRATEGY.md](OPENRECON_QA_STRATEGY.md), `tests/e2e/test_e2e_workflows_and_performance.py` |
| **Fase 6** | Consolidación UI PHP → FastAPI y Release Final | EN PROGRESO | Pendiente migrar acciones heredadas de `web_dashboard/api.php` y validar despliegue Docker completo con PostgreSQL + Redis + Tor |

---

## PRÓXIMOS HITOS PARA RELEASE 3.0.0 GA

1. Desmantelar acciones heredadas en `web_dashboard/api.php` enrutando 100% de mutaciones hacia FastAPI con autenticación de sesión/token.
2. Ejecutar pruebas de integración en vivo con Docker Compose (`PostgreSQL 16 + Redis 7 + Tor + ProjectDiscovery`).
3. Eliminar carpetas duplicadas heredadas (`web_dashboard/backend/tools/`, `web_dashboard/engine/`) una vez verificada la transición.
