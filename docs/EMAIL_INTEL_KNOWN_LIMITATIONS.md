# INFORME DE LIMITACIONES CONOCIDAS Y RECOMENDACIONES OPERATIVAS
## MÓDULO EMAIL INTELLIGENCE (INTEGRACIÓN ZEHEF)

> **Fecha:** 11 de Noviembre de 2026  
> **Área:** Threat Intelligence, OSINT & DFIR  

---

## 1. LIMITACIONES DE FUENTES EXTERNAS Y COMPORTAMIENTO ESPERADO

1. **WAFs Anti-Bot en Plataformas Específicas (Instagram / Meta):**
   - **Situación:** Instagram aplica protección estricta con Cloudflare / Meta Edge, devolviendo `HTTP 429 Too Many Requests` ante consultas no autenticadas procedentes de rangos de hosting o cloud.
   - **Manejo:** El motor clasifica el resultado transparentemente como `INCONCLUSIVE` (Protegido por WAF). **Bajo ninguna circunstancia se vulneran controles de acceso ni se evaden captchas**.
2. **APIs con Tokens CSRF de Ciclo Corto (Pinterest / Deezer):**
   - **Situación:** Pinterest actualizó sus endpoints internos exigiendo cookies de sesión SPA autenticadas (HTTP 403). Deezer requiere una negociación previa de token CSRF (`checkForm`).
   - **Manejo:** Si el token no puede obtenerse de forma legítima, el resultado se reporta como `INCONCLUSIVE` o `QUERY_ERROR` sin inventar resultados.
3. **Redirección Forzada en Strava:**
   - **Situación:** Strava exige login previo redirigiendo a `/login` (HTTP 307).
   - **Manejo:** Se clasifica como `INCONCLUSIVE` con nivel de confianza bajo.
4. **Google Dorking en Pastes Públicos:**
   - **Situación:** El scraping crudo de Google Search con `site:pastebin.com` es susceptible a captchas y bloqueos inmediatos de IP.
   - **Manejo:** OpenRecon utiliza un colector pasivo sobre réplicas y motores de indexación de pastes abiertos (`psbdmp.ws`, `proxynova`), mitigando la dependencia de scraping frágil.
5. **Generador de Variantes:**
   - **Situación:** Las direcciones generadas representan permutaciones matemáticas heurísticas.
   - **Manejo:** Están catalogadas innegociablemente como `HYPOTHESIS_UNVERIFIED`. El sistema nunca efectúa comprobaciones activas por SMTP (RCPT TO) para prevenir que la IP del servidor sea catalogada en listas de bloqueo o que se alerte al objetivo.
