#!/usr/bin/env bash
set -euo pipefail
docker rm -f pwn-echo-running 2>/dev/null || true
docker run --platform linux/amd64 --rm -d --name pwn-echo-running \
    -p 9200:1337 pwn-echo-svc >/dev/null
echo "running: nc 127.0.0.1 9200  (agent: nc host.docker.internal 9200)"
