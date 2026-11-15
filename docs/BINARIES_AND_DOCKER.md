# OpenRecon — Binarios Fijados, Docker y Matriz de Migración PHP/FastAPI

## 1. Versiones Fijadas de Binarios y Herramientas (`backend/Dockerfile`)

Ningún binario utiliza la etiqueta `latest`. Todas las descargas verifican integridad criptográfica **SHA-256** contra los `checksums.txt` oficiales de cada release durante el build:

| Herramienta | Versión fijada | Licencia | Uso en OpenRecon |
|---|---|---|---|
| `subfinder` | `v2.6.6` | MIT | Descubrimiento pasivo de subdominios (`DNSEngine`) |
| `dnsx` | `v1.2.1` | MIT | Resolución DNS concurrente y validación (`DNSEngine`) |
| `httpx` | `v1.6.0` | MIT | Fingerprinting HTTP/TLS/títulos/tecnologías (`HTTPEngine`) |
| `naabu` | `v2.3.1` | MIT | Sondeo TCP unprivileged `-s c` (`PortEngine`) |
| `nuclei` | `v3.2.4` | MIT | Escaneo `-jsonl` con exclusión `-etags dos,fuzz,intrusive,bruteforce` (`NucleiEngine`) |
| `gitleaks` | `v8.18.4` | MIT | Detección pasiva de secretos en sandbox (`GitHubIntelConnector` + `/api/v1/exposures/secrets/scan`) |
| `dnstwist` | `20240116` | Apache-2.0 | Permutaciones IDN/typosquatting (`DRPEngine`) |

## 2. Hardening del Contenedor (`backend/Dockerfile` & `docker-compose.yml`)

- **Usuario sin privilegios:** El contenedor `api` ejecuta bajo `USER openrecon` (no `root`).
- **Capacidades mínimas:** `no-new-privileges:true` en `api` y `tor-proxy`.
- **Healthcheck:** `GET http://127.0.0.1:8000/` cada 15–30 s.
- **Aislamiento Tor:** Servicio dedicado `tor-proxy` (`alpine:3.19`, `cpus: 0.50`, `memory: 256M`) en red aislada `tor-sandbox-net`.

## 3. Política de Actualización Controlada

1. Actualizar la versión exacta en `backend/Dockerfile` (nunca `:latest`).
2. Ejecutar `docker compose build --no-cache api` y validar `sha256sum` durante el build.
3. Correr la suite `tests/integration/test_master_improvement_program.py` y `tests/integration/test_p1_p2_debt_closure.py` antes de promover.

## 4. Estrategia Strangler Pattern (PHP `api.php` → FastAPI)

- **Ya en FastAPI:** `domain_intel_*`, `darkintel_ai_analyze`, `get_kill_switch`, `trigger_kill_switch`, `reset_kill_switch`.
- **Sincronización activa:** `EmailIntelOrchestrator` consulta `SecurityGovernanceGuard.get_task_control_state()` para abortar tareas si el Kill-Switch se activa desde PHP o FastAPI.
- **Pendiente de migración progresiva (sin pérdida de datos):** `add_scope`, `delete_scope`, `add_seed`, `run_scan`, `assets` y `vulnerabilities` en `web_dashboard/api.php` mantienen compatibilidad sobre `web_dashboard/openrecon.sqlite` hasta consolidar el esquema único en PostgreSQL.
