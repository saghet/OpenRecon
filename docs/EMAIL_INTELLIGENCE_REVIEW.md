# REVISIÓN DE EMAIL INTELLIGENCE — OPENRECON 3.0 (FASE 3)

> **Fecha:** 2026-11-14  
> **Módulos Auditados:** `backend/app/services/email_intel/*`, `scratch/Zehef/*`

---

## 1. CAPACIDADES VERIFICADAS

- **Validación de sintaxis y permutaciones:** `EmailGenerator` y `EmailVerificationClassifier.validate_syntax()`.
- **Postura DNS de correo:** `DomainIntelEngine` verifica `MX`, `SPF`, `DMARC` y `DKIM` mediante `dnspython`.
- **Filtraciones autorizadas:** `LeakSearcher` consolida **HudsonRock Cavalier OSINT API** y **XposedOrNot v1** (con caché TTL e historical diff) y `PasteSearcher` realiza consultas pasivas.
- **Protección de evidencias:** Toda evidencia generada por `LeakSearcher`, `AccountSearcher` y `EmailIntelOrchestrator` pasa por `EvidenceSanitizer.sanitize_raw_content()` (cero secretos ni HTML ejecutable en BD).

---

## 2. DIFERENCIACIÓN ESTRICTA DE CONFIANZA

Implementado `EmailVerificationClassifier` (`backend/app/services/email_intel/confidence_classifier.py`) que separa de forma explícita:

1. `SYNTACTICALLY_VALID`: Formato RFC válido.
2. `DOMAIN_HAS_MAIL_INFRA`: Dominio con registros MX activos.
3. `REGISTERED_ACCOUNT_CONFIRMED`: Solo cuando un proveedor confirma inequívocamente la cuenta (`status == "CONFIRMED"` y `confidence_level == "HIGH"`).
4. `BREACH_ASSOCIATED`: Correo presente en fuentes de filtraciones verificadas.
5. `AMBIGUOUS_OR_INCONCLUSIVE`: Respuestas HTTP 429/403/timeout/error nunca se promueven a existencia confirmada (`account_existence_confirmed = False`).

---

## 3. CUMPLIMIENTO GPL-3.0 (ZEHEF)

- `zehef_adapter.py` conserva los avisos obligatorios de modificación (GPL-3.0 Sec. 5.a) y la licencia íntegra en `scratch/Zehef/LICENSE`.
- Se recomienda mantener la licencia **AGPLv3 / GPL-3.0 compatible** para distribuciones que incluyan el código derivado de Zehef, o aislar su ejecución vía CLI/microservicio separado si se distribuye bajo licencia permisiva.
