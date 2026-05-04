#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building service container..."
docker build --platform linux/amd64 -q -t pwn-echo-svc service/

echo "Extracting distfiles for the player..."
mkdir -p distfiles
cid=$(docker create --platform linux/amd64 pwn-echo-svc)
trap "docker rm '$cid' >/dev/null 2>&1 || true" EXIT
docker cp "$cid:/srv/chall" distfiles/chall
docker cp "$cid:/lib/x86_64-linux-gnu/libc.so.6" distfiles/libc.so.6
# ld-linux is sometimes useful for re-linking; copy the actual file (not the
# /lib64 symlink that docker cp would otherwise preserve as a host-side symlink).
docker cp "$cid:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" distfiles/ld-linux-x86-64.so.2 2>/dev/null || true

ls -la distfiles/
