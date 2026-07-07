#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Extract database components using Python's urllib.parse
DB_HOST=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').hostname)")
DB_PORT=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').port)")
DB_USER=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').username)")
DB_PASS=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').password)")

# Wait for PostgreSQL to be ready (with timeout)
wait_for_postgres() {
    echo "Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
    timeout 30s bash -c "until pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER; do sleep 1; done"
}

# Wait for MySQL/MariaDB to be ready (with timeout and credentials)
wait_for_mysql_mariadb() {
    echo "Waiting for $1 at $DB_HOST:$DB_PORT..."
    timeout 30s bash -c "until mysqladmin ping -h $DB_HOST -P $DB_PORT -u $DB_USER -p'$DB_PASS' --silent; do sleep 1; done"
}

# Determine database type and wait for it
if [[ "$DATABASE_URL" == postgres* ]]; then
    wait_for_postgres || { echo "PostgreSQL not available after 30 seconds!"; exit 1; }
elif [[ "$DATABASE_URL" == mysql* ]]; then
    wait_for_mysql_mariadb "MySQL" || { echo "MySQL not available after 30 seconds!"; exit 1; }
elif [[ "$DATABASE_URL" == mariadb* ]]; then
    wait_for_mysql_mariadb "MariaDB" || { echo "MariaDB not available after 30 seconds!"; exit 1; }
fi

# Run Django management commands
echo "Running database migrations..."
python3 manage.py migrate --noinput

echo "Collecting static files..."
python3 manage.py collectstatic --noinput --clear

echo "Starting Gunicorn server..."
exec "$@"
