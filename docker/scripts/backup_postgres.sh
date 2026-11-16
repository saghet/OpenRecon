#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${1:-./backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PG_USER="${POSTGRES_USER:-openrecon}"
PG_DB="${POSTGRES_DB:-openrecon}"

mkdir -p "${BACKUP_DIR}"
OUT_FILE="${BACKUP_DIR}/openrecon_${PG_DB}_${TIMESTAMP}.sql.gz"

echo "[*] Creating PostgreSQL backup -> ${OUT_FILE}"
docker compose exec -T postgres pg_dump -U "${PG_USER}" -d "${PG_DB}" --clean --if-exists | gzip > "${OUT_FILE}"
sha256sum "${OUT_FILE}" > "${OUT_FILE}.sha256"
echo "[OK] Backup created and checksummed: ${OUT_FILE}"
