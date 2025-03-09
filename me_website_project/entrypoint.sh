#!/bin/bash

# Extract database components using Python's urllib.parse
DB_HOST=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').hostname)")
DB_PORT=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').port)")

# Extract username and password for MySQL
DB_USER=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').username)")
DB_PASS=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$DATABASE_URL').password)")

# Wait for PostgreSQL to be ready(with timeout)
wait_for_postgres() {
    echo "Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
    timeout 30s bash -c "until pg_isready -h $DB_HOST -p $DB_PORT; do sleep 1; done"
}

# Wait for MySQL/MariaDB to be ready(with timeout and credentials)
wait_for_mysql_mariadb() {
    timeout 30s bash -c "until mysqladmin ping -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASS --silent; do sleep 1; done"
}

# Determine database type
if [[ "$DATABASE_URL" == postgres* ]]; then
    wait_for_postgres || {
        echo "PostgreSQL not available after 30 seconds!"
        exit 1
    }
elif [[ "$DATABASE_URL" == mysql* ]]; then
    echo "Waiting for MySQL at $DB_HOST:$DB_PORT..."
    wait_for_mysql_mariadb || {
        echo "MySQL not available after 30 seconds!"
        exit 1
    }
elif [[ "$DATABASE_URL" == mariadb* ]]; then
    echo "Waiting for MariaDB at $DB_HOST:$DB_PORT..."
    wait_for_mysql_mariadb || {
        echo "MariaDB not available after 30 seconds!"
        exit 1
    }
fi

# Run Django management commands
python3 manage.py migrate --noinput
python3 manage.py collectstatic --noinput --clear

exec "$@"