#!/usr/bin/env bash
set -euo pipefail
docker rm -f jvm-deser-running 2>/dev/null || true
docker run --platform linux/amd64 --rm -d --name jvm-deser-running \
    -p 9300:1337 jvm-deser-svc >/dev/null
echo "running: nc 127.0.0.1 9300  (agent: nc host.docker.internal 9300)"
