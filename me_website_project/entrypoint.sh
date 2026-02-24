#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

DATABASE_HOST="${DATABASE_HOST:-""}"
DATABASE_PORT="${DATABASE_PORT:-""}"
DATABASE_USER="${DATABASE_USER:-""}"
DATABASE_PASSWORD="${DATABASE_PASSWORD:-""}"
DATABASE_NAME="${DATABASE_NAME:-""}"
DATABASE_URL="${DATABASE_URL:-""}"

# Construct DATABASE_URL only if missing AND all components exist
if [[ -z "$DATABASE_URL" ]]; then
   if [[ -n "$DATABASE_HOST" && -n "$DATABASE_PORT" && -n "$DATABASE_USER" && -n "$DATABASE_PASSWORD" && -n "$DATABASE_NAME" ]]; then
       echo "DATABASE_URL not provided; constructing from individual components..."
       export DATABASE_URL="postgres://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}?sslmode=require"
   else
       echo "DATABASE_URL missing and insufficient components to construct it."
       exit 1
   fi
fi

# Extract database components using Python's urllib.parse
DB_HOST=$(python3 - <<EOF
from urllib.parse import urlparse
print(urlparse("$DATABASE_URL").hostname)
EOF
)

DB_PORT=$(python3 - <<EOF
from urllib.parse import urlparse
print(urlparse("$DATABASE_URL").port)
EOF
)

DB_USER=$(python3 - <<EOF
from urllib.parse import urlparse
print(urlparse("$DATABASE_URL").username)
EOF
)

DB_PASS=$(python3 - <<EOF
from urllib.parse import urlparse
print(urlparse("$DATABASE_URL").password)
EOF
)

# Wait for PostgreSQL to be ready (with timeout)
wait_for_postgres() {
   echo "Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
   timeout 30s bash -c "until pg_isready -h \"$DB_HOST\" -p \"$DB_PORT\" -U \"$DB_USER\"; do sleep 1; done"
}

# Wait for MySQL/MariaDB to be ready (with timeout and credentials)
wait_for_mysql_mariadb() {
   echo "Waiting for $1 at $DB_HOST:$DB_PORT..."
   timeout 30s bash -c "until mysqladmin ping -h \"$DB_HOST\" -P \"$DB_PORT\" -u \"$DB_USER\" -p\"$DB_PASS\" --silent; do sleep 1; done"
}

# Determine database type and wait for it
if [[ "$DATABASE_URL" == postgres* ]]; then
   wait_for_postgres || { echo "PostgreSQL not available after 30 seconds!"; exit 1; }
elif [[ "$DATABASE_URL" == mysql* ]]; then
   wait_for_mysql_mariadb "MySQL" || { echo "MySQL not available after 30 seconds!"; exit 1; }
elif [[ "$DATABASE_URL" == mariadb* ]]; then
   wait_for_mysql_mariadb "MariaDB" || { echo "MariaDB not available after 30 seconds!"; exit 1; }
fi

echo "Starting Gunicorn..."
exec "$@"
