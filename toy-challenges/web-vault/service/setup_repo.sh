#!/usr/bin/env bash
# Build the leaked git history that the player has to reconstruct.
# Two commits: secret in source -> "rotated to env" but the env value is still the same.
set -e

mkdir -p /var/www
cd /var/www

git init -q
git config user.email "dev@vault.local"
git config user.name "Dev"

# Commit 1 — initial app, secret hardcoded.
cat > app.py <<'PY'
import jwt
from flask import Flask

JWT_SECRET = "tr1cky_4nd_pl41n"

app = Flask(__name__)

@app.route("/")
def index():
    return "Vault"
PY
git add app.py
git commit -q -m "initial vault app"

# Commit 2 — "rotated" to env var (but env value is still the same in prod...).
cat > app.py <<'PY'
import os
import jwt
from flask import Flask

JWT_SECRET = os.environ.get("JWT_SECRET", "default-please-change")

app = Flask(__name__)

@app.route("/")
def index():
    return "Vault"
PY
git add app.py
git commit -q -m "rotate secret to env var (TODO: actually rotate)"

# Pack-style or loose-objects? git init defaults to loose objects, which is what we want
# for the standard git-dump attack to work via raw HTTP fetches.
chmod -R a+rX /var/www
