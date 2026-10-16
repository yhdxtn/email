#!/bin/sh
set -eu
# Runtime secrets are read only from deployment-mounted files; never baked into the image.
export DATABASE_PASSWORD="$(cat /run/secrets/database-password)"
export MIGRATION_PASSWORD="$(cat /run/secrets/migration-password)"
exec java -XX:MaxRAMPercentage=65.0 -XX:+ExitOnOutOfMemoryError -jar /app/mail-admin.jar
