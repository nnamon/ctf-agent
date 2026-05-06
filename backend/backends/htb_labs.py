"""HackTheBox Labs backend (Pwn/Crypto/Reversing/etc. challenges).

Authenticates with a personal app token (Bearer JWT). Token format:
  - issued at https://app.hackthebox.com/profile/settings → "App Tokens"
  - audience claim `aud:5` (labs platform) — distinct from the MCP token
    (`aud:1`, scope `mcp:use`) that authenticates against the CTF events
    platform; the two are NOT interchangeable.

Free-tier accounts see all currently-active challenges (~190 visible at
time of writing). Retired challenges require VIP+. Server-side rate limit
is 20 requests/minute per token — keep it modest with a semaphore + retry
on 429.

Scope of this backend:
  - List active challenges, with HTB's per-user solve markers
  - Per-challenge metadata fetch (description, difficulty, points)
  - Distfile download (returns application/zip)
  - Flag submission (POST /api/v4/challenge/own)

NOT covered (yet):
  - Instance-backed challenges where `docker: true` — need a
    start_container / stop_container lifecycle around solver runs.
    For now they're returned with `connection_info: ""` and the LLM
    will have to notice the `docker` field in the description.
  - Machines (full pwnable boxes) — needs OpenVPN inside the sandbox
    and two-flag (user/root) submission. Separate backend later.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.backends.base import Backend, SubmitResult

logger = logging.getLogger(__name__)


HTB_API_BASE = "https://labs.hackthebox.com/api/v4"
USER_AGENT = "ctf-agent/htb-labs (+httpx)"

# HTB rate-limits 20 req/min per token. We cap concurrent in-flight
# requests so a swarm of solvers fetching distfiles doesn't burn the
# whole budget in one tick. Per-call retries handle transient 429s.
_HTB_REQ_SEMAPHORE = asyncio.Semaphore(4)


def _slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "challenge"


@dataclass
class HtbLabsBackend(Backend):
    """Bearer-token-auth backend for the HackTheBox Labs API."""

    app_token: str = ""
    base_url: str = HTB_API_BASE

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    # name → stub dict, including HTB challenge_id (int) and difficulty.
    # Populated by fetch_challenge_stubs; used by submit_flag and
    # pull_challenge to map slug → numeric id without re-fetching.
    _stubs_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    # ---------- HTTP plumbing ----------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self.app_token:
                raise RuntimeError(
                    "HtbLabsBackend: app_token is required (see "
                    "https://app.hackthebox.com/profile/settings → App Tokens)"
                )
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
                headers={
                    "Authorization": f"Bearer {self.app_token}",
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Wrapped request with concurrency guard + 429 backoff.

        HTB returns x-ratelimit-remaining; on 429 it includes Retry-After.
        We retry up to twice with exponential backoff on transient 429/5xx.
        """
        client = await self._ensure_client()
        async with _HTB_REQ_SEMAPHORE:
            backoff = 2.0
            for attempt in range(3):
                resp = await client.request(method, path, **kwargs)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", backoff))
                    logger.warning(
                        "HTB rate-limited on %s %s — sleeping %.1fs (attempt %d)",
                        method, path, retry_after, attempt + 1,
                    )
                    await asyncio.sleep(retry_after)
                    backoff *= 2
                    continue
                if 500 <= resp.status_code < 600 and attempt < 2:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            return resp  # last attempt, return whatever we got

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """GET /api/v4/challenge/list → list of stubs, CTFd-shaped.

        HTB's list endpoint returns a single 'category_name'-less envelope
        (the field is null on the list endpoint and only present on
        /challenge/info/{id}). We carry HTB's challenge_category_id
        through and translate it to category_name using the categories
        index, fetched once and cached on the instance.
        """
        cats = await self._fetch_categories()
        resp = await self._request("GET", "/challenge/list")
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTB /challenge/list: HTTP {resp.status_code}: {resp.text[:200]}"
            )
        challenges = resp.json().get("challenges", [])
        out: list[dict[str, Any]] = []
        for c in challenges:
            name = c.get("name") or ""
            slug = _slugify(name)
            cat_id = c.get("challenge_category_id")
            category = cats.get(cat_id, "Unknown")
            stub = {
                "id": c.get("id"),
                "name": slug,
                "title": name,
                "category": category,
                "value": int(c.get("points") or 0),
                "solves": c.get("solves") or 0,
                "type": "standard",
                "description": "",  # filled by fetch_all_challenges
                "connection_info": "",
                "_htb": {
                    "id": c.get("id"),
                    "difficulty": c.get("difficulty") or "",
                    "retired": bool(c.get("retired")),
                    "solved": bool(c.get("authUserSolve")),
                },
            }
            self._stubs_by_name[slug] = stub
            out.append(stub)
        return out

    async def _fetch_categories(self) -> dict[int, str]:
        """GET /api/v4/challenge/categories/list → {id: name}.

        Cached on first call; categories are static (Pwn, Crypto, etc.).
        """
        if not hasattr(self, "_cats_cache"):
            self._cats_cache: dict[int, str] = {}
        if self._cats_cache:
            return self._cats_cache
        resp = await self._request("GET", "/challenge/categories/list")
        if resp.status_code != 200:
            logger.warning(
                "HTB /challenge/categories/list: HTTP %d (continuing with id-only)",
                resp.status_code,
            )
            return self._cats_cache
        for entry in resp.json().get("info", []):
            self._cats_cache[entry["id"]] = entry.get("name", "Unknown")
        return self._cats_cache

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """Stubs + per-challenge /info detail (description, file_name)."""
        stubs = await self.fetch_challenge_stubs()
        out: list[dict[str, Any]] = []
        for stub in stubs:
            cid = stub["_htb"]["id"]
            info = await self._fetch_challenge_info(cid)
            stub["description"] = info.get("description") or ""
            stub["_htb"]["download"] = bool(info.get("download"))
            stub["_htb"]["file_name"] = info.get("file_name") or ""
            stub["_htb"]["sha256"] = info.get("sha256") or ""
            stub["_htb"]["docker"] = bool(info.get("docker"))
            out.append(stub)
        return out

    async def _fetch_challenge_info(self, cid: int) -> dict[str, Any]:
        resp = await self._request("GET", f"/challenge/info/{cid}")
        if resp.status_code != 200:
            logger.warning("HTB /challenge/info/%d: HTTP %d", cid, resp.status_code)
            return {}
        return resp.json().get("challenge", {})

    async def fetch_solved_names(self) -> set[str]:
        """Derived from the per-challenge 'authUserSolve' marker on /list.

        Saves a separate /user/profile call. Refreshes the stubs cache
        as a side effect so subsequent calls have current data.
        """
        if not self._stubs_by_name:
            await self.fetch_challenge_stubs()
        return {
            name for name, stub in self._stubs_by_name.items()
            if stub["_htb"].get("solved")
        }

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """POST /api/v4/challenge/own with {challenge_id, flag, difficulty}.

        HTB's response (observed in practice — the API is not formally
        documented but the SPA submits this shape):
          - 200 + {message: "...", success: true}      → CORRECT
          - 200 + {message: "...", success: false}     → WRONG / wrong-difficulty
          - 200 + {message: "Challenge already owned"} → ALREADY_SOLVED
        The 'difficulty' field is the user's perceived difficulty (1-10).
        We always send 5 (medium) as a neutral mid-point — HTB factors
        this into per-challenge difficulty stats but does not gate on it.
        """
        if challenge_name not in self._stubs_by_name:
            await self.fetch_challenge_stubs()
        stub = self._stubs_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB challenge {challenge_name!r} not found in listing")
        cid = stub["_htb"]["id"]

        resp = await self._request(
            "POST",
            "/challenge/own",
            json={
                "challenge_id": cid,
                "flag": flag.strip(),
                "difficulty": 5,
            },
        )
        if resp.status_code != 200:
            return SubmitResult(
                "unknown",
                f"HTTP {resp.status_code}",
                f"submit_flag transport error: HTTP {resp.status_code} {resp.text[:200]}",
            )

        try:
            body = resp.json()
        except Exception:
            return SubmitResult(
                "unknown", "non-json",
                f"HTB returned non-JSON body: {resp.text[:200]}",
            )

        msg = (body.get("message") or "").strip()
        success = bool(body.get("success"))
        msg_lower = msg.lower()
        if "already" in msg_lower and "owned" in msg_lower:
            return SubmitResult(
                "already_solved", msg,
                f'ALREADY SOLVED — "{flag}" was previously accepted',
            )
        if success:
            return SubmitResult(
                "correct", msg or "owned",
                f'CORRECT — "{flag}" accepted on HTB ({msg})',
            )
        return SubmitResult(
            "incorrect", msg or "rejected",
            f'INCORRECT — "{flag}" rejected by HTB ({msg})',
        )

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Download the distfile zip + write metadata.yml."""
        from pathlib import Path

        import yaml
        try:
            from markdownify import markdownify as html2md
        except Exception:
            html2md = None

        stub = challenge if "_htb" in challenge else self._stubs_by_name.get(
            challenge.get("name", "")
        )
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _htb metadata for {challenge.get('name')!r}"
            )
        # Hydrate description/file_name if we only have a list-level stub.
        if not stub.get("description"):
            info = await self._fetch_challenge_info(stub["_htb"]["id"])
            stub["description"] = info.get("description") or ""
            stub["_htb"]["download"] = bool(info.get("download"))
            stub["_htb"]["file_name"] = info.get("file_name") or ""

        slug = _slugify(challenge.get("name") or stub.get("name", "challenge"))
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # Distfile (zip). HTB returns application/zip; the SPA downloads
        # it via /api/v4/challenge/download/{id} as a single archive.
        if stub["_htb"].get("download"):
            cid = stub["_htb"]["id"]
            fname = stub["_htb"].get("file_name") or f"{slug}.zip"
            dest_dir = ch_dir / "distfiles"
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / fname
            if not dest.exists():
                resp = await self._request("GET", f"/challenge/download/{cid}")
                if resp.status_code == 200:
                    dest.write_bytes(resp.content)
                    logger.info(
                        "HTB: pulled %s (%d bytes)", fname, len(resp.content)
                    )
                else:
                    logger.warning(
                        "HTB: download for %s failed: HTTP %d",
                        slug, resp.status_code,
                    )

        desc = stub.get("description", "") or ""
        if html2md and desc:
            try:
                desc = html2md(desc, heading_style="atx").strip()
            except Exception:
                pass

        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": stub.get("category", "Unknown"),
            "description": desc,
            "value": stub.get("value", 0),
            "connection_info": stub.get("connection_info", ""),
            "tags": ["htb", "labs", stub["_htb"].get("difficulty", "").lower()],
            "solves": stub.get("solves", 0),
            "htb": {
                "id": stub["_htb"]["id"],
                "difficulty": stub["_htb"].get("difficulty", ""),
                "docker": stub["_htb"].get("docker", False),
            },
        }
        (ch_dir / "metadata.yml").write_text(
            yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False)
        )
        return str(ch_dir)

    # ---------- lifecycle ----------

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
