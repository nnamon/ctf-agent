#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building service container..."
docker build --platform linux/amd64 -q -t jvm-deser-svc service/

echo "Extracting JAR for the player..."
mkdir -p distfiles
cid=$(docker create --platform linux/amd64 jvm-deser-svc)
trap "docker rm '$cid' >/dev/null 2>&1 || true" EXIT
docker cp "$cid:/srv/token-service.jar" distfiles/token-service.jar

ls -la distfiles/
