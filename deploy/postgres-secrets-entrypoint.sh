#!/bin/sh
# Docker's official entrypoint drops to the postgres OS account. Do not make host secrets
# world-readable to accommodate it: copy only first-init credentials to a private tmpfs.
set -eu
mkdir -p /run/astrogate-init
chmod 700 /run/astrogate-init
chown postgres:postgres /run/astrogate-init
for name in database-password migration-password; do
    install -o postgres -g postgres -m 600 "/run/secrets/$name" "/run/astrogate-init/$name"
done
exec /usr/local/bin/docker-entrypoint.sh "$@"
