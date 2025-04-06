# Environment Variables Template

## Email Configuration (Gmail Example)
- EMAIL_HOST_USER='your.name@gmail.com'  # Gmail account address
- EMAIL_HOST_PASSWORD='abcd efgh ijkl mnop'  # Google App Password (NOT your Gmail password)
- EMAIL_PORT=587
- EMAIL_USE_TLS=True

## Django Core Settings
### Generate new Django secret key: 
```
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```
- SECRET_KEY='generated secret'
- DEBUG=False  # Always False in production. True in development!
- ALLOWED_HOSTS='Django list of allowed hosts' # eg 'localhost,127.0.0.1,your-domain.com,0.0.0.0'
- CSRF_TRUSTED_ORIGINS='List of trusted origins' # eg  'https://*.your-domain.com,http://localhost:8080,http://127.0.0.1:8080'

## Application Specific
- APP_VERSION='1.0.0'  # Follow semantic versioning

## Database (PostgreSQL)
- POSTGRES_USER='postgresql user'
- POSTGRES_PASSWORD='postgresql user password'
- POSTGRES_DB='postgresql database'

## Constructed from above variables (alternative to separate config)
- DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}

## Security
- HEALTH_CHECK_SECRET='your health check secret'  # Generate UUID4