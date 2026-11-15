# ROADMAP OPENRECON 3.0

> **Última Actualización:** 2026-11-15

---

## ESTADO DE FASES

| Fase | Nombre | Estado | Evidencia Principal |
|---|---|---|---|
| **Fase 0** | Auditoría Obligatoria y Línea Base | COMPLETADA | [AUDIT_OPENRECON_3.md](AUDIT_OPENRECON_3.md) |
| **Fase 1** | Hardening de Seguridad Crítica (P0) | COMPLETADA | [SECURITY_HARDENING_REPORT.md](SECURITY_HARDENING_REPORT.md), `tests/security/test_p0_security_hardening.py` |
| **Fase 2** | Consolidación de Arquitectura y Persistencia | COMPLETADA | [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md), `backend/alembic/`, `tests/integration/test_phase2_architecture.py` |
| **Fase 3** | Domain, Email, GitHub y Web Security Intel | COMPLETADA | [EMAIL_INTELLIGENCE_REVIEW.md](EMAIL_INTELLIGENCE_REVIEW.md), [THIRD_PARTY_LICENSE_AUDIT.md](THIRD_PARTY_LICENSE_AUDIT.md), `tests/integration/test_phase3_intelligence.py` |
| **Fase 4** | CTI, Correlación y Anti-Falsos Positivos | COMPLETADA | [CTI_AND_CORRELATION_REVIEW.md](CTI_AND_CORRELATION_REVIEW.md), [ANTI_FALSE_POSITIVE_STRATEGY.md](ANTI_FALSE_POSITIVE_STRATEGY.md), `tests/integration/test_phase4_cti_and_afp.py` |
| **Fase 5** | Estrategia QA, E2E y Rendimiento | COMPLETADA | [OPENRECON_QA_STRATEGY.md](OPENRECON_QA_STRATEGY.md), `tests/e2e/test_e2e_workflows_and_performance.py`, `tests/integration/test_phase5_metrics_benchmark.py` |
| **Fase 5.5** | Cierre de Deuda P0/P1/P2, Contrato Único y Docker Hardened | COMPLETADA | [BINARIES_AND_DOCKER.md](BINARIES_AND_DOCKER.md), `finding_contract.py`, `misp_galaxy.py`, `tests/integration/test_master_improvement_program.py`, `tests/integration/test_p1_p2_debt_closure.py` |
| **Fase 6** | Consolidación UI PHP → FastAPI y Release 3.0.0 GA | EN PROGRESO | [STRANGLER_MIGRATION_MATRIX.md](STRANGLER_MIGRATION_MATRIX.md) (Kill-Switch, Scan Stop, Domain/Email Intel migrados; pendiente ola CRUD Seeds/Scope/Assets/Vulns y validación Docker Compose en vivo) |

---

## PRÓXIMOS HITOS PARA RELEASE 3.0.0 GA

1. Completar la migración de acciones `LEGACY_COMPAT` en `web_dashboard/api.php` (`get_seeds`, `add_seed`, `delete_seed`, `get_scope`, `add_scope`, `delete_scope`, `get_assets`, `get_vulnerabilities`, `update_vuln_status`, `run_scan`) hacia FastAPI + PostgreSQL.
2. Ejecutar pruebas de integración en vivo con Docker Compose (`PostgreSQL 16 + Redis 7 + Tor + ProjectDiscovery`).
3. Eliminar carpetas duplicadas heredadas (`web_dashboard/backend/tools/`, `web_dashboard/engine/`) una vez verificada la transición completa.
