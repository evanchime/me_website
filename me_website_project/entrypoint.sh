#!/bin/bash

# Database connection check
if [[ "$DATABASE_URL" == postgres* ]]; then
    until pg_isready -d $DATABASE_URL; do
        echo "Waiting for PostgreSQL..."
        sleep 2
    done
elif [[ "$DATABASE_URL" == mysql* ]]; then
    HOST=$(echo $DATABASE_URL | awk -F'@' '{print $2}' | awk -F'/' '{print $1}')
    until mysqladmin ping -h $HOST --silent; do
        echo "Waiting for MySQL..."
        sleep 2
    done
fi

# Django setup
python3 manage.py migrate --noinput
python3 manage.py collectstatic --noinput

# Start server
exec "$@"