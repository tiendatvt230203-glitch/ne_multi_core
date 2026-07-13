#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db_env.sh"
network_encryptor_load_db_env

SCHEMA_FILE="${NETWORK_ENCRYPTOR_ROOT}/schema.sql"
if [ ! -f "${SCHEMA_FILE}" ]; then
  echo "[FATAL] schema not found: ${SCHEMA_FILE}" >&2
  exit 1
fi

if grep -qiE '(^|[[:space:];])(DROP[[:space:]]+(ROLE|USER)|CREATE[[:space:]]+(ROLE|USER)|DROP[[:space:]]+DATABASE)\b' "${SCHEMA_FILE}"; then
  echo "[FATAL] ${SCHEMA_FILE} must not drop/create users, roles, or databases" >&2
  exit 1
fi

echo "=== ne_init_db ==="
echo "postgres://${POSTGRES_USER}@${POSTGRES_SERVER}:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "scope: DROP/CREATE ne_* tables and enums only (no PostgreSQL users)"
echo

ne_psql -c "SELECT version();" >/dev/null
echo "[OK] PostgreSQL connection"

ne_psql_file "${SCHEMA_FILE}"
echo "[OK] schema.sql applied"

n=$(ne_psql -t -A -c "
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('ne_profiles','ne_policies','ne_lan','ne_wan');")
if [ "${n:-0}" != "4" ]; then
  echo "[FATAL] expected 4 ne_* tables, found ${n:-?}" >&2
  exit 1
fi
echo "[OK] ne_profiles, ne_policies, ne_lan, ne_wan"
