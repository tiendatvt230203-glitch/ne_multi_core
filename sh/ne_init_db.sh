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
echo "scope: apply schema.sql (11 BE tables) — run once before sql_options seeds"
echo

ne_psql -c "SELECT version();" >/dev/null
echo "[OK] PostgreSQL connection"
echo "[INFO] DB identity:"
ne_psql -c "SELECT current_database() AS db, current_user AS usr, current_schema() AS schema, inet_server_addr() AS host, inet_server_port() AS port;"

ne_psql -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" >/dev/null
ne_psql -c "SELECT gen_random_uuid();" >/dev/null
echo "[OK] pgcrypto/gen_random_uuid available"

ne_psql_file "${SCHEMA_FILE}"
echo "[OK] schema.sql applied"

missing=$(ne_psql -t -A -c "
WITH expected(table_name) AS (
  VALUES
    ('ne_profiles'),('ne_policies'),('ne_lan'),('ne_wan'),
    ('bridges'),('bridge_interfaces'),('pqc_keys'),('pqc_exchange_tunnels'),
    ('policy_pqc_ref'),('profile_tunnel_ref'),('profile_bridge_ref')
)
SELECT string_agg(e.table_name, ', ' ORDER BY e.table_name)
FROM expected e
LEFT JOIN information_schema.tables t
  ON t.table_schema = 'public'
 AND t.table_type = 'BASE TABLE'
 AND t.table_name = e.table_name
WHERE t.table_name IS NULL;")
if [ -n "${missing}" ]; then
  echo "[FATAL] missing schema tables: ${missing}" >&2
  exit 1
fi

n=$(ne_psql -t -A -c "
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
  AND table_name IN (
    'ne_profiles','ne_policies','ne_lan','ne_wan',
    'bridges','bridge_interfaces','pqc_keys','pqc_exchange_tunnels',
    'policy_pqc_ref','profile_tunnel_ref','profile_bridge_ref'
  );")
if [ "${n:-0}" != "11" ]; then
  echo "[FATAL] expected 11 schema tables, found ${n:-?}" >&2
  exit 1
fi

echo "[INFO] schema tables in public:"
ne_psql -c "
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
ORDER BY table_name;"

echo "[OK] ne_profiles, ne_policies, ne_lan, ne_wan, bridges, pqc_keys, ..."