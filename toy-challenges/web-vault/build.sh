#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -q -t web-vault-svc service/
echo "built: web-vault-svc"
