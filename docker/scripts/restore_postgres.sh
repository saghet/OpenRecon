#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file.sql.gz>"
    exit 1
fi

BACKUP_FILE="$1"
PG_USER="${POSTGRES_USER:-openrecon}"
PG_DB="${POSTGRES_DB:-openrecon}"

if [ -f "${BACKUP_FILE}.sha256" ]; then
    echo "[*] Verifying backup SHA-256..."
    sha256sum -c "${BACKUP_FILE}.sha256"
fi

echo "[*] Restoring ${BACKUP_FILE} into PostgreSQL (${PG_DB})..."
gunzip -c "${BACKUP_FILE}" | docker compose exec -T postgres psql -U "${PG_USER}" -d "${PG_DB}"
echo "[OK] Restore complete."
