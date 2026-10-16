#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Docker Engine + Compose plugin are required; none will be installed automatically.' >&2; exit 1; }
if [[ ! -e .env ]]; then python3 scripts/init_secrets.py --dev; fi
if ! grep -qx 'LOCAL_DEV=true' .env || ! grep -qx 'APP_ORIGIN=http://127.0.0.1:8088' .env; then
  echo 'Existing configuration is not the explicit loopback development configuration. Refusing to change it.' >&2; exit 1
fi
docker compose up --build -d
printf '%s\n' 'Control plane requested at http://127.0.0.1:8088; check docker compose logs/status. No mail node is preconfigured.'
