#!/usr/bin/env bash
# Build the ctf-agent sandbox image and smoke-test it.
#
# The smoke-test script (sandbox/smoke.sh) is bind-mounted into a throwaway
# container — it never lands in the runtime image. Exits non-zero if any
# smoke check fails so this script is safe to chain with `&& docker push`
# in a CI pipeline.
#
# Usage:
#   sandbox/build.sh                    # builds ctf-sandbox, runs smoke
#   sandbox/build.sh ctf-sandbox-vnext  # custom tag
#   sandbox/build.sh --no-test          # skip smoke (build only)
#   sandbox/build.sh --no-build         # skip build (smoke existing image)

set -euo pipefail

IMAGE="ctf-sandbox"
DO_BUILD=1
DO_TEST=1

while [ $# -gt 0 ]; do
    case "$1" in
        --no-test)  DO_TEST=0 ;;
        --no-build) DO_BUILD=0 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# //;s/^#//'
            exit 0 ;;
        -*)
            echo "unknown flag: $1" >&2; exit 2 ;;
        *)
            IMAGE="$1" ;;
    esac
    shift
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="$REPO_ROOT/sandbox/Dockerfile.sandbox"
SMOKE="$REPO_ROOT/sandbox/smoke.sh"

if [ "$DO_BUILD" -eq 1 ]; then
    echo "==[ build: $IMAGE ]=="
    docker build -f "$DOCKERFILE" -t "$IMAGE" "$REPO_ROOT"
fi

if [ "$DO_TEST" -eq 1 ]; then
    if [ ! -f "$SMOKE" ]; then
        echo "ERROR: smoke script not found at $SMOKE" >&2
        exit 1
    fi
    echo "==[ smoke: $IMAGE ]=="
    docker run --rm -v "$SMOKE:/tmp/smoke.sh:ro" "$IMAGE" bash /tmp/smoke.sh
    echo "==[ smoke: PASS ]=="
fi
