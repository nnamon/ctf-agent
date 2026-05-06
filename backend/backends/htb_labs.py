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
    # Set of challenge slugs we've actively spawned an instance for in
    # this process. stop_instance only hits the API for these; static
    # challenges we never started skip the no-op 404 round-trip.
    _started_instances: set[str] = field(default_factory=set, repr=False)

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
            stub["_htb"]["solved"] = True
            return SubmitResult(
                "already_solved", msg,
                f'ALREADY SOLVED — "{flag}" was previously accepted',
            )
        if success:
            # Flip cached solved-flag so a follow-up fetch_solved_names
            # reflects the new state without waiting for the poller's
            # next /list refresh — important when the coord uses solved
            # state for prerequisite gating or skip filtering.
            stub["_htb"]["solved"] = True
            return SubmitResult(
                "correct", msg or "owned",
                f'CORRECT — "{flag}" accepted on HTB ({msg})',
            )
        return SubmitResult(
            "incorrect", msg or "rejected",
            f'INCORRECT — "{flag}" rejected by HTB ({msg})',
        )

    # ---------- per-challenge instance lifecycle ----------

    def _format_connection(self, category: str, ip: str, ports: list[int]) -> str:
        """Render a category-appropriate connection_info string.

        Web/Blockchain → http://ip:port (most are HTTP services).
        Pwn/GamePwn/Crypto → nc ip port (interactive socket).
        Anything else → bare ip:port + a hint for the solver to probe.
        """
        if not ports:
            return ip or ""
        port = ports[0]
        cat = (category or "").lower()
        if cat in ("web", "blockchain"):
            return f"http://{ip}:{port}"
        if cat in ("pwn", "gamepwn", "crypto"):
            return f"nc {ip} {port}"
        return f"{ip}:{port}  (try `nc {ip} {port}` for interactive services or `curl http://{ip}:{port}/` for HTTP)"

    async def start_instance(self, challenge_name: str) -> str | None:
        """Spawn a per-user docker instance via POST /challenge/start.

        Idempotent: if the challenge already has a running instance for
        this user (visible in /challenge/info → play_info.status), we
        skip the start call and return the existing connection_info.

        For non-docker challenges, returns None (no-op).
        """
        if challenge_name not in self._stubs_by_name:
            await self.fetch_challenge_stubs()
        stub = self._stubs_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB challenge {challenge_name!r} not found")
        cid = stub["_htb"]["id"]

        info = await self._fetch_challenge_info(cid)
        if not bool(info.get("docker")):
            return None  # static challenge — no instance needed

        play = info.get("play_info") or {}
        existing_ip = play.get("ip") or info.get("docker_ip")
        existing_ports = play.get("ports") or info.get("docker_ports") or []
        if existing_ip and existing_ports and (
            play.get("status") == "ready" or info.get("docker_status") == "ready"
        ):
            logger.info(
                "HTB %s: reusing existing instance %s:%s",
                challenge_name, existing_ip, existing_ports[0],
            )
            self._started_instances.add(challenge_name)
            return self._format_connection(stub["category"], existing_ip, existing_ports)

        resp = await self._request(
            "POST", "/challenge/start",
            json={"challenge_id": cid},
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTB start_instance({challenge_name}): HTTP {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        logger.info("HTB %s: %s (instance_id=%s)",
                    challenge_name, body.get("message", "started"), body.get("id"))

        # Poll /info until play_info.ip + ports are populated. VE
        # challenges are typically ready in the same response, but harder
        # ones may need a few seconds. Cap at 30 s to fail fast on stuck
        # instances rather than blocking the swarm forever.
        deadline = asyncio.get_event_loop().time() + 30.0
        while asyncio.get_event_loop().time() < deadline:
            info = await self._fetch_challenge_info(cid)
            play = info.get("play_info") or {}
            ip = play.get("ip") or info.get("docker_ip")
            ports = play.get("ports") or info.get("docker_ports") or []
            status = play.get("status") or info.get("docker_status") or ""
            if ip and ports and status == "ready":
                expires = play.get("expires_at") or "(unknown)"
                logger.info(
                    "HTB %s: instance ready at %s:%s (expires %s)",
                    challenge_name, ip, ports[0], expires,
                )
                self._started_instances.add(challenge_name)
                return self._format_connection(stub["category"], ip, ports)
            await asyncio.sleep(2.0)
        raise RuntimeError(
            f"HTB start_instance({challenge_name}): instance never became ready within 30s"
        )

    async def stop_instance(self, challenge_name: str) -> None:
        """POST /challenge/stop with {challenge_id}. Skipped if we never
        called start_instance for this challenge in this process — HTB
        returns 404 for non-existent containers and the noise pollutes
        the trace for static-only swarms."""
        if challenge_name not in self._started_instances:
            return
        stub = self._stubs_by_name.get(challenge_name)
        if stub is None:
            return
        cid = stub["_htb"]["id"]
        try:
            resp = await self._request(
                "POST", "/challenge/stop",
                json={"challenge_id": cid},
            )
            if resp.status_code == 200:
                logger.info("HTB %s: %s", challenge_name, resp.json().get("message", "stopped"))
            else:
                # Don't raise — teardown errors shouldn't mask solver outcome.
                logger.warning(
                    "HTB stop_instance(%s): HTTP %d %s",
                    challenge_name, resp.status_code, resp.text[:200],
                )
        except Exception as e:
            logger.warning("HTB stop_instance(%s) failed: %s", challenge_name, e)
        finally:
            self._started_instances.discard(challenge_name)

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

        # For docker challenges, the per-user instance IP+port is
        # dynamic and only meaningful at solve time. Write a placeholder
        # so the on-disk metadata stays stable across spawns; the swarm
        # overrides connection_info live via Backend.start_instance().
        is_docker = bool(stub["_htb"].get("docker"))
        connection_info = (
            "(spawned at solve time — backend will populate live IP+port)"
            if is_docker else stub.get("connection_info", "")
        )
        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": stub.get("category", "Unknown"),
            "description": desc,
            "value": stub.get("value", 0),
            "connection_info": connection_info,
            "tags": ["htb", "labs", stub["_htb"].get("difficulty", "").lower()],
            "solves": stub.get("solves", 0),
            "htb": {
                "id": stub["_htb"]["id"],
                "difficulty": stub["_htb"].get("difficulty", ""),
                "docker": is_docker,
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
