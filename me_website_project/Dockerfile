# Stage 1: Builder (install dependencies)
FROM python:3.11-slim as builder

# Install essential build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime (lean production image)
FROM python:3.11-slim

# Install runtime dependencies for databases
RUN apt-get update && apt-get install -y --no-install-recommends \
libpq5 \
libmariadb3 \
postgresql-client \
default-mysql-client \
mariadb-client \
ca-certificates \
&& rm -rf /var/lib/apt/lists/*

# Environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PATH="/app/.local/bin:${PATH}"
ENV PYTHONPATH="${PYTHONPATH}:/app/.local/lib/python3.11/site-packages"

# Create non-root user, app directory and set ownership
RUN useradd -m appuser && mkdir /app && chown appuser:appuser /app

# Create staticfiles directory with proper permissions
RUN mkdir -p /app/staticfiles && chown appuser:appuser /app/staticfiles

# Grant ownership
RUN chown -R appuser:appuser /app
USER appuser

WORKDIR /app

# Copy installed packages from builder
COPY --chown=appuser:appuser --from=builder /root/.local /app/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Set entrypoint script permissions and command
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "gunicorn --workers ${GUNICORN_WORKERS:-4} --timeout ${GUNICORN_TIMEOUT:-30} me_website_project.wsgi:application --bind 0.0.0.0:8000"]
    