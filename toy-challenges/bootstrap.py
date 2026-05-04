#!/usr/bin/env python3
"""Bootstrap a fresh CTFd with the toy challenges.

  1. Wait for CTFd at $CTFD_URL (default http://localhost:8000) to come up.
  2. Run the /setup wizard — admin / admin / event name "ctf-agent demo".
  3. Create an API token (the value gets saved to ./token.txt).
  4. For each subdirectory of toy-challenges/, register the challenge
     in CTFd: title / category / value from metadata.yml, flag from
     a hardcoded map below, distfiles uploaded as challenge files,
     hints created if present, state set to "visible".

Idempotent on re-run: if a challenge with the same name already exists,
it's skipped (no update).

Usage:
  docker compose up -d
  ./bootstrap.py                       # admin/admin, port 8000
  CTFD_URL=http://other:9000 ./bootstrap.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests
import yaml

CTFD_URL = os.environ.get("CTFD_URL", "http://localhost:12001").rstrip("/")
ADMIN_NAME = os.environ.get("CTFD_ADMIN_NAME", "admin")
ADMIN_EMAIL = os.environ.get("CTFD_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("CTFD_ADMIN_PASSWORD", "admin")
EVENT_NAME = os.environ.get("CTFD_EVENT_NAME", "ctf-agent demo")
EVENT_DESC = "Self-hosted CTFd instance for ctf-agent end-to-end testing."

HERE = Path(__file__).resolve().parent

# Flags for each toy challenge (this whole directory is a deliberate
# spoiler — it's a test instance, not a real competition).
FLAGS: dict[str, str] = {
    "Toy XOR-B64":   "flag{x0r_b64_warmup_complete}",
    "Echo Service":  "flag{r3t2libc_l34k_th3n_pwn_n0_c4n4ry}",
    "Token Service": "flag{j4v4_d3s3r1al1z4t10n_h0w_d1d_w3_g3t_h3r3}",
    "Web Vault":     "flag{g1t_l34k_jwt_f0rg3_ssrf_ch41n}",
}


def _wait_for_ctfd(s: requests.Session, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = s.get(f"{CTFD_URL}/", timeout=3, allow_redirects=True)
            if r.status_code in (200, 302):
                return
        except requests.RequestException as e:
            last_err = e
        time.sleep(1.0)
    raise RuntimeError(f"CTFd at {CTFD_URL} not reachable: {last_err}")


def _csrf_nonce(s: requests.Session, path: str) -> str:
    r = s.get(f"{CTFD_URL}{path}", timeout=10)
    r.raise_for_status()
    import re
    for pat in (r"id=\"nonce\"[^>]*value=\"([^\"]+)\"",
                r"name=\"nonce\"[^>]*value=\"([^\"]+)\"",
                r"'csrfNonce':\s*\"([A-Fa-f0-9]+)\""):
        m = re.search(pat, r.text)
        if m:
            return m.group(1)
    raise RuntimeError(f"Could not locate CSRF nonce on {path}")


def _is_setup_done(s: requests.Session) -> bool:
    r = s.get(f"{CTFD_URL}/setup", timeout=10, allow_redirects=False)
    return r.status_code in (302, 303)


def _do_setup(s: requests.Session) -> None:
    if _is_setup_done(s):
        print(f"  /setup already done — skipping wizard")
        return
    nonce = _csrf_nonce(s, "/setup")
    form = {
        "ctf_name": EVENT_NAME,
        "ctf_description": EVENT_DESC,
        "user_mode": "users",
        "name": ADMIN_NAME,
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
        "ctf_theme": "core-beta",
        "challenge_visibility": "public",
        "account_visibility": "public",
        "score_visibility": "public",
        "registration_visibility": "public",
        "verify_emails": "false",
        "team_size": "",
        "nonce": nonce,
        "_submit": "Finish",
    }
    r = s.post(f"{CTFD_URL}/setup", data=form, timeout=30, allow_redirects=False)
    if r.status_code not in (200, 302, 303):
        raise RuntimeError(f"setup wizard failed: {r.status_code} {r.text[:200]}")
    print(f"  /setup OK — admin user '{ADMIN_NAME}' created")


def _login(s: requests.Session) -> None:
    nonce = _csrf_nonce(s, "/login")
    r = s.post(
        f"{CTFD_URL}/login",
        data={"name": ADMIN_NAME, "password": ADMIN_PASSWORD, "nonce": nonce, "_submit": "Submit"},
        timeout=10,
        allow_redirects=False,
    )
    if r.status_code not in (200, 302, 303):
        raise RuntimeError(f"login failed: {r.status_code}")
    if r.status_code == 200:
        # CTFd returns 200 on bad credentials (re-renders login page).
        raise RuntimeError("login failed — bad credentials")
    print(f"  logged in as {ADMIN_NAME}")


def _api_csrf(s: requests.Session) -> str:
    r = s.get(f"{CTFD_URL}/admin/challenges", timeout=10)
    r.raise_for_status()
    import re
    m = re.search(r"'csrfNonce':\s*\"([A-Fa-f0-9]+)\"", r.text)
    if not m:
        raise RuntimeError("could not locate API csrfNonce on /admin/challenges")
    return m.group(1)


def _create_token(s: requests.Session, csrf: str) -> str:
    body = {"description": "ctf-agent bootstrap token", "expiration": None}
    r = s.post(
        f"{CTFD_URL}/api/v1/tokens",
        json=body,
        headers={"Content-Type": "application/json", "CSRF-Token": csrf},
        timeout=10,
    )
    r.raise_for_status()
    data = r.json().get("data", {})
    tok = data.get("value") or data.get("token")
    if not tok:
        raise RuntimeError(f"unexpected /api/v1/tokens response: {r.text[:200]}")
    return tok


def _api(method: str, path: str, token: str, **kw):
    headers = kw.pop("headers", {})
    headers["Authorization"] = f"Token {token}"
    headers.setdefault("Content-Type", "application/json")
    r = requests.request(method, f"{CTFD_URL}/api/v1{path}",
                         headers=headers, timeout=30, **kw)
    return r


def _existing_names(token: str) -> set[str]:
    r = _api("GET", "/challenges?per_page=500&view=admin", token)
    r.raise_for_status()
    return {c["name"] for c in r.json().get("data", [])}


def _register_challenge(token: str, ch_dir: Path) -> str:
    """Returns the action taken: 'created', 'skipped', or 'failed'."""
    meta_path = ch_dir / "metadata.yml"
    if not meta_path.exists():
        return "skipped (no metadata.yml)"
    meta = yaml.safe_load(meta_path.read_text())
    name = meta["name"]
    flag = FLAGS.get(name)
    if not flag:
        return f"skipped ({name!r} has no entry in FLAGS)"

    if name in _existing_names(token):
        return "exists"

    body = {
        "name": name,
        "category": meta.get("category", "misc"),
        "description": (meta.get("description") or "").strip(),
        "value": int(meta.get("value", 0)),
        "type": "standard",
        "state": "visible",
    }
    if meta.get("connection_info"):
        body["connection_info"] = meta["connection_info"]

    r = _api("POST", "/challenges", token, data=json.dumps(body))
    if not r.ok:
        return f"failed ({r.status_code} {r.text[:200]})"
    cid = r.json()["data"]["id"]

    # Flag
    _api("POST", "/flags", token, data=json.dumps({
        "challenge": cid, "type": "static", "content": flag, "data": "",
    })).raise_for_status()

    # Tags
    for tag in meta.get("tags") or []:
        _api("POST", "/tags", token, data=json.dumps({
            "challenge": cid, "value": str(tag),
        }))

    # Hints
    for h in meta.get("hints") or []:
        _api("POST", "/hints", token, data=json.dumps({
            "challenge": cid,
            "content": h.get("content", ""),
            "cost": int(h.get("cost", 0)),
        }))

    # Distfile uploads. Skip non-existent files (e.g. binaries that build.sh
    # would regenerate — operator can build first and re-run bootstrap).
    dist = ch_dir / "distfiles"
    if dist.exists():
        for f in sorted(dist.iterdir()):
            if not f.is_file():
                continue
            with f.open("rb") as fh:
                fr = requests.post(
                    f"{CTFD_URL}/api/v1/files",
                    headers={"Authorization": f"Token {token}"},
                    files={"file": (f.name, fh)},
                    data={"challenge": str(cid), "type": "challenge"},
                    timeout=60,
                )
            if not fr.ok:
                print(f"    file upload failed for {f.name}: {fr.status_code}")
    return "created"


def main() -> int:
    print(f"Bootstrapping CTFd at {CTFD_URL}")
    s = requests.Session()
    _wait_for_ctfd(s)
    _do_setup(s)
    if _is_setup_done(s):
        # Even if setup was already done, we need a logged-in session to
        # create an API token.
        _login(s)
    csrf = _api_csrf(s)
    token = _create_token(s, csrf)
    print(f"  API token: {token}")
    (HERE / "token.txt").write_text(token + "\n")
    print(f"  saved to {(HERE / 'token.txt').relative_to(HERE.parent)}")

    print("\nRegistering challenges:")
    failures = 0
    for ch_dir in sorted(p for p in HERE.iterdir() if p.is_dir()):
        if not (ch_dir / "metadata.yml").exists():
            continue
        try:
            outcome = _register_challenge(token, ch_dir)
        except Exception as e:
            outcome = f"error: {e}"
        if "fail" in outcome or "error" in outcome:
            failures += 1
        print(f"  {ch_dir.name:25s}  {outcome}")

    print()
    print(f"Done. CTFd at {CTFD_URL}  (admin / {ADMIN_PASSWORD})")
    print(f"Use the token in the next step:")
    print(f"  ctf-session create toys --ctfd-url {CTFD_URL} --quota-usd 1.00")
    print(f"  ctf-session use toys")
    print(f"  echo CTFD_TOKEN=$(cat {(HERE / 'token.txt').relative_to(HERE.parent)}) "
          f">> sessions/toys/.env")
    print(f"  ctf-pull")
    print(f"  ctf-solve --max-challenges 2 -v")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
