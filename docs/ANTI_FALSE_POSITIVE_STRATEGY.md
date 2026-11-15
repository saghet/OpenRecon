# ESTRATEGIA ANTI-FALSOS POSITIVOS E IA — OPENRECON 3.0 (FASE 4)

> **Fecha:** 2026-11-14  
> **Motor:** `backend/app/services/validation/anti_false_positive.py` + `web_dashboard/vuln_validator_engine.php`

---

## 1. PIPELINE DE VALIDACIÓN EN 8 ETAPAS

`AntiFalsePositiveEngine` ejecuta un flujo determinista y auditable:

1. **Detección inicial** (`CandidateFinding`).
2. **Normalización** (activo en minúsculas y sanitización vía `EvidenceSanitizer`).
3. **Eliminación de duplicados** (huella SHA-256 por organización, activo, título y método).
4. **Verificación de evidencia técnica** (si falta evidencia técnica suficiente → `NO_REPRODUCIBLE`).
5. **Segunda comprobación independiente** (`second_verifier` opcional).
6. **Clasificación** en los 7 estados formales:
   - `NUEVO`, `PENDIENTE_DE_VERIFICACION`, `CONFIRMADO`, `PROBABLE`, `FALSO_POSITIVO`, `NO_REPRODUCIBLE`, `REMEDIADO`.
7. **Confirmación o descarte** (solo `CONFIRMADO` si hay evidencia técnica + segunda comprobación positiva + confianza >= 0.8).
8. **Registro inmutable de la decisión** (`decision_log` con actor, hash SHA-256 de evidencia y timestamp UTC).

---

## 2. GOBERNANZA DE IA (DEEPSEEK)

- **DeepSeek (`deepseek_engine.py`) actúa exclusivamente como asistente analítico** (resumen de evidencias, correlación MITRE ATT&CK, explicación de riesgos y recomendaciones).
- **Regla Innegociable:** `AntiFalsePositiveEngine` bloquea con `PermissionError` cualquier intento de un actor IA (`is_ai_actor=True`) de modificar automáticamente el estado de hallazgos `CRITICAL` o `HIGH`.
- Los datos técnicos verificados permanecen separados de las interpretaciones generadas por el modelo.
