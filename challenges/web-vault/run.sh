#!/usr/bin/env bash
set -euo pipefail
docker rm -f web-vault-running 2>/dev/null || true
docker run --rm -d --name web-vault-running -p 9100:8080 web-vault-svc >/dev/null
echo "running: http://127.0.0.1:9100/  (agent reaches as http://host.docker.internal:9100)"
