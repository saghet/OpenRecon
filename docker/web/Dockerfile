FROM php:8.2.26-apache-bookworm

# Install PHP extensions required by OpenRecon SOC Console (SQLite compat + PostgreSQL + cURL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-dev \
    libpq-dev \
    libcurl4-openssl-dev \
    curl \
    && docker-php-ext-install pdo pdo_sqlite pdo_pgsql curl \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

# Configure Apache DocumentRoot and security headers
RUN printf '<Directory /var/www/html>\n\tOptions -Indexes +FollowSymLinks\n\tAllowOverride All\n\tRequire all granted\n</Directory>\n' \
    > /etc/apache2/conf-available/openrecon.conf \
    && a2enconf openrecon

WORKDIR /var/www/html

COPY web_dashboard/ /var/www/html/

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1/index.php >/dev/null || exit 1
