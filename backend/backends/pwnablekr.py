"""pwnable.kr backend.

pwnable.kr is a long-running PHP-based wargame at https://pwnable.kr —
challenges live as SSH-accessible binaries on the same host (port 2222),
each under a per-challenge user account. The agent SSHes in (password is
always `guest`), exploits a SUID binary to escalate to the challenge's
flag-owning user, reads the flag file, and POSTs the resulting auth
string back to the website.

There is no challenge tarball / downloadable distfile — the binary lives
remotely on the challenge user's home dir. The solver works the binary
over SSH from inside the local sandbox; metadata.yml carries the
SSH connection string so the prompt's `connection_info` slot renders.

Auth flow:
  - POST /lib.php?cmd=login with form fields `username`, `password`.
    Response is a tiny HTML fragment (<100B) that issues a
    `location.href` JS redirect to /index.php on success. PHPSESSID
    cookie carries the session.
  - No CSRF token / nonce.

Listing flow:
  - /play.php (post-login) renders 50+ category sections, each with
    `<figure><img onclick='onLayer(<int>);' ...><figcaption><slug>`
    blocks. The integer is a stable per-challenge ID; the slug
    matches /img/<slug>.png.
  - Per-challenge details come from /playproc.php?id=<int> — returns
    a small HTML fragment containing points, a <textarea> with the
    free-form description (and embedded `ssh user@pwnable.kr -p2222
    (pw:guest)` line), and an empty auth form.

Submit flow:
  - POST /lib.php?cmd=auth with `flag=<value>`. The form has no
    hidden challenge_id — the server matches the auth string against
    every challenge the user hasn't solved yet. Response is a JS
    fragment (`<script>alert('...');</script>`), text varies by
    correctness. We surface raw text on first observation; refine the
    correct/incorrect detection once we've actually seen one.

Solved-set:
  - /rankproc.php?id=<user_id> returns a comma-separated slug list
    of every challenge the user has authed. user_id is the numeric
    pwnable.kr account id; the rank.php page's `<font onclick='makeRequest("<id>")'>`
    tags expose it for visible users. We discover it lazily via
    rank.php?id=<username> (search for our row in the focused page),
    or accept a pre-supplied PWNABLEKR_USER_ID env var.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.backends.base import Backend, SubmitResult

logger = logging.getLogger(__name__)


USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _slugify(name: str) -> str:
    """pwnable.kr challenge captions are lowercase ASCII with spaces /
    underscores (e.g. "brain fuck", "md5 calculator", "tiny_easy"). We
    normalise to a kebab-case slug so the rest of the agent can use it
    as a directory / log name without quoting."""
    s = name.strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "challenge"


# Section headers in /play.php look like `[Toddler's Bottle]`, `[Rookiss]`,
# `[Grotesque]`, `[Hacker's Secret]`. Anchored at the start of a line-ish
# context (after a `<br>` or section break) so we don't catch arbitrary
# bracketed text inside descriptions.
_CATEGORY_RE = re.compile(r"\[([^\[\]<>\n]{1,40})\]<br>")
# Each visible challenge in /play.php is rendered as a <figure> with an
# onclick handler firing onLayer(<int>) and a <figcaption><slug>.
# We bind the layer-id and slug together via re.findall so they never
# desync if the markup gets a stray newline.
_CHALLENGE_RE = re.compile(
    r"onclick='onLayer\((\d+)\);'[^>]*src='/img/([^']+)\.png'"
    r"[^<]*<figcaption>([^<]+)</figcaption>"
)


@dataclass
class PwnableKrBackend(Backend):
    """Form-auth + HTML-scraping backend for pwnable.kr."""

    base_url: str = "https://pwnable.kr"
    username: str = ""
    password: str = ""
    # Optional: pre-supplied account id. When unset the backend tries to
    # discover it lazily from rank.php?id=<username>. None of the agent
    # workflows fail when discovery comes up empty — we just return an
    # empty solved-set and let attempts.db dedup carry the load.
    user_id: str = ""

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _logged_in: bool = field(default=False, repr=False)
    # slug → stub dict; populated by fetch_challenge_stubs and read by
    # pull_challenge / submit_flag for layer-id resolution.
    _stubs_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    # Cache /playproc.php fragments per layer-id so a pull_challenge that
    # follows fetch_all_challenges reuses one HTTP round-trip.
    _detail_cache: dict[int, dict[str, Any]] = field(default_factory=dict, repr=False)

    # ---------- HTTP plumbing ----------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url.rstrip("/"),
                follow_redirects=False,
                timeout=30.0,
                headers={"User-Agent": USER_AGENT},
            )
        return self._client

    async def _ensure_logged_in(self) -> None:
        if self._logged_in:
            return
        if not self.username or not self.password:
            raise RuntimeError(
                "PwnableKrBackend: username + password are required"
            )
        client = await self._ensure_client()

        # POST credentials. pwnable.kr's response on success is a tiny
        # HTML fragment (~90 bytes) containing
        # `<script>location.href = '/index.php';</script>` plus a fresh
        # PHPSESSID cookie. On failure we get an alert() instead.
        resp = await client.post(
            "/lib.php?cmd=login",
            data={"username": self.username, "password": self.password},
            headers={"Referer": f"{self.base_url}/"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"POST /lib.php?cmd=login: HTTP {resp.status_code}")
        body = resp.text or ""
        if "alert(" in body and "location.href" not in body:
            # Extract the alert message for diagnostics.
            m = re.search(r"alert\(['\"]([^'\"]+)['\"]\)", body)
            msg = m.group(1) if m else body[:120]
            raise RuntimeError(f"pwnable.kr login failed — {msg}")
        if "PHPSESSID" not in client.cookies:
            raise RuntimeError("pwnable.kr login: no PHPSESSID cookie set")
        self._logged_in = True
        logger.info("pwnable.kr login OK as %s", self.username)

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Walk /play.php once + lazily fetch /playproc.php?id=<n> per
        challenge. The play page only has slug + layer-id + category; the
        per-challenge fragment supplies points, description, and the SSH
        command line."""
        await self._ensure_logged_in()
        client = await self._ensure_client()
        resp = await client.get("/play.php")
        if resp.status_code != 200:
            raise RuntimeError(f"GET /play.php: HTTP {resp.status_code}")
        text = resp.text

        # Walk the document linearly. Track the most-recent category
        # header so we can tag each challenge with its section.
        out: list[dict[str, Any]] = []
        cat_matches = list(_CATEGORY_RE.finditer(text))
        ch_matches = list(_CHALLENGE_RE.finditer(text))

        def _category_for(pos: int) -> str:
            cur = "uncategorized"
            for m in cat_matches:
                if m.start() < pos:
                    cur = m.group(1).strip()
                else:
                    break
            return cur

        for m in ch_matches:
            layer_id = int(m.group(1))
            img_slug = m.group(2)            # e.g. "brain fuck"
            caption = m.group(3).strip()     # e.g. "brain fuck"
            slug = _slugify(caption or img_slug)
            category = _category_for(m.start())
            stub: dict[str, Any] = {
                "id": layer_id,
                "name": slug,
                "title": caption,
                "category": category,
                "value": 0,                  # filled in by detail fetch
                "solves": 0,                 # filled in by detail fetch
                "type": "standard",
                "description": "",           # filled in by detail fetch
                "connection_info": "",       # filled in by detail fetch
                "_pwnkr": {
                    "id": layer_id,
                    "img_slug": img_slug,
                },
            }
            self._stubs_by_name[slug] = stub
            out.append(stub)
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """Listing-only — the description / points come from the
        per-challenge popup endpoint. Pull lazily here so the poller
        first sync isn't slow with N HTTP round-trips."""
        if not self._stubs_by_name:
            await self.fetch_challenge_stubs()
        for slug in list(self._stubs_by_name.keys()):
            await self._hydrate_stub(slug)
        return list(self._stubs_by_name.values())

    async def _hydrate_stub(self, slug: str) -> dict[str, Any]:
        """Populate description / value / connection_info / solves on a
        stub by GETting /playproc.php?id=<layer_id>. Cached per layer-id
        so we never refetch within one process."""
        stub = self._stubs_by_name.get(slug)
        if stub is None:
            raise RuntimeError(f"unknown pwnable.kr challenge slug {slug!r}")
        layer_id = int(stub["_pwnkr"]["id"])
        if stub.get("description"):
            return stub
        if layer_id in self._detail_cache:
            stub.update(self._detail_cache[layer_id])
            return stub

        client = await self._ensure_client()
        resp = await client.get(f"/playproc.php?id={layer_id}")
        if resp.status_code != 200 or not resp.text:
            return stub
        body = resp.text

        pts_m = re.search(r"\[(\d+)\s*points?\]", body)
        value = int(pts_m.group(1)) if pts_m else 0

        ta_m = re.search(
            r"<textarea[^>]*>(.*?)</textarea>", body, re.DOTALL
        )
        textarea = ta_m.group(1).strip() if ta_m else ""

        # Description = textarea minus trailing ssh line; SSH command =
        # the literal `ssh <user>@pwnable.kr -p2222 (pw:guest)` line. Keep
        # both so the prompt's connection-info slot renders the SSH
        # invocation directly without the agent having to parse the
        # description.
        ssh_m = re.search(
            r"ssh\s+\S+@pwnable\.kr\s+-p\s*\d+(?:\s*\(pw:\s*[^)]+\))?",
            textarea,
        )
        connection_info = ssh_m.group(0).strip() if ssh_m else ""
        description = textarea
        if connection_info:
            description = textarea.replace(connection_info, "").strip()

        solves_m = re.search(r"pwned\s*\(\s*(\d+)\s*\)\s*times", body)
        solves = int(solves_m.group(1)) if solves_m else 0

        update: dict[str, Any] = {
            "value": value,
            "solves": solves,
            "description": description,
            "connection_info": connection_info,
        }
        self._detail_cache[layer_id] = update
        stub.update(update)
        return stub

    # ---------- solved-set ----------

    async def _resolve_user_id(self) -> str:
        """Discover our own numeric pwnable.kr user_id. Cached after the
        first successful resolve; returns "" if the search fails (and the
        caller falls back to an empty solved-set)."""
        if self.user_id:
            return self.user_id
        await self._ensure_logged_in()
        client = await self._ensure_client()
        # rank.php?id=<username> renders a leaderboard page focused
        # around our row. Each user row carries
        # `<font onclick='makeRequest("<user_id>")'>POINTS</font>` —
        # match the row that contains our exact username and pull its id.
        resp = await client.get(
            f"/rank.php?id={self.username}",
            headers={"Referer": f"{self.base_url}/"},
        )
        if resp.status_code != 200:
            logger.warning("rank.php?id=%s: HTTP %s", self.username, resp.status_code)
            return ""
        # `<tr class='user' ...><td>RANK</td><td>NICK</td>...<td>
        #     <font onclick='makeRequest("USER_ID")'>POINTS</font></td>...</tr>`
        # Anchor on `<tr class='user'` then check whether our nickname is
        # in this row before extracting the id.
        for m in re.finditer(
            r"<tr class='user'[^>]*>(.*?)</tr>", resp.text, re.DOTALL,
        ):
            row = m.group(1)
            # nickname column is the second <td>; allow any anchor /
            # font / span styling around it.
            if re.search(rf">\s*{re.escape(self.username)}\s*<", row):
                uid_m = re.search(
                    r"makeRequest\(['\"](\d+)['\"]\)", row
                )
                if uid_m:
                    self.user_id = uid_m.group(1)
                    logger.info(
                        "pwnable.kr: resolved user_id=%s for %s",
                        self.user_id, self.username,
                    )
                    return self.user_id
        # Fallback for accounts at rank > displayed window — pwnable.kr's
        # rank page only shows a fixed window around the requested user.
        # If we got an empty match, the username might be lowercased by
        # the server; try a case-insensitive fallback.
        for m in re.finditer(
            r"makeRequest\(['\"](\d+)['\"]\)", resp.text,
        ):
            # Walk backwards 200 chars looking for our username (case-insensitive)
            ctx = resp.text[max(0, m.start() - 600): m.start()]
            if self.username.lower() in ctx.lower():
                self.user_id = m.group(1)
                logger.info(
                    "pwnable.kr: resolved user_id=%s for %s (loose)",
                    self.user_id, self.username,
                )
                return self.user_id
        logger.warning(
            "pwnable.kr: could not resolve user_id for %s — solved-set will "
            "be empty until set explicitly via PWNABLEKR_USER_ID",
            self.username,
        )
        return ""

    async def fetch_solved_names(self) -> set[str]:
        """`/rankproc.php?id=<user_id>` returns a comma-separated string
        of slugs (matching the /img/<slug>.png caption). Map back to our
        normalised slugs and return the set."""
        uid = await self._resolve_user_id()
        if not uid:
            return set()
        await self._ensure_logged_in()
        client = await self._ensure_client()
        resp = await client.get(
            f"/rankproc.php?id={uid}",
            headers={"Referer": f"{self.base_url}/rank.php"},
        )
        if resp.status_code != 200 or not resp.text:
            return set()
        raw = resp.text.strip().rstrip(",")
        if not raw:
            return set()
        # Need stubs cached so we can remap raw img-slugs → kebab-slugs.
        if not self._stubs_by_name:
            await self.fetch_challenge_stubs()
        img_to_slug = {
            stub["_pwnkr"]["img_slug"]: name
            for name, stub in self._stubs_by_name.items()
        }
        out: set[str] = set()
        for token in (s.strip() for s in raw.split(",")):
            if not token:
                continue
            if token in img_to_slug:
                out.add(img_to_slug[token])
            else:
                # Server returns the raw caption ("brain fuck"); fall
                # back to slugifying directly so a captioning change
                # doesn't accidentally hide a real solve.
                out.add(_slugify(token))
        return out

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """POST /lib.php?cmd=auth. The pwnable.kr endpoint matches the
        submitted auth string against every unsolved challenge for the
        logged-in user — the auth form has no hidden challenge_id field.
        That means a `correct` response unambiguously means the user
        scored on _some_ challenge, but not necessarily this one (very
        rare in practice; auth strings are 50+ char random)."""
        await self._ensure_logged_in()
        client = await self._ensure_client()

        resp = await client.post(
            "/lib.php?cmd=auth",
            data={"flag": flag.strip()},
            headers={
                "Referer": f"{self.base_url}/play.php",
                "Origin": self.base_url,
            },
        )
        if resp.status_code != 200:
            return SubmitResult(
                "unknown",
                f"HTTP {resp.status_code}",
                f"submit_flag transport error: HTTP {resp.status_code}",
            )

        body = (resp.text or "").strip()
        # pwnable.kr returns a JS fragment shaped like
        # `<script>alert('...');</script><script>location.href='...';</script>`.
        # Pull the alert text — it carries the human-readable verdict.
        alert_m = re.search(r"alert\(['\"]([^'\"]+)['\"]\)", body)
        verdict = (alert_m.group(1) if alert_m else body[:200]).strip()
        verdict_low = verdict.lower()

        # Verdict heuristics — calibrated against real responses observed
        # in the wild on agentamon's account:
        #   correct       → "Congratz!. you got <N> points"
        #   already_solved → "You already authenticated this flag"
        #                  → "already authenticated" / "duplicat" (older variants)
        #   incorrect     → "wrong" / "incorrect" / "Wrong auth code"
        #   transport     → "no such task" (server-side issue)
        if any(s in verdict_low for s in ("already auth", "duplicat")):
            return SubmitResult(
                "already_solved", verdict,
                f"ALREADY SOLVED: {verdict}",
            )
        if (
            "congratz" in verdict_low
            or re.search(r"got\s+\d+\s*points?", verdict_low)
            or any(s in verdict_low for s in ("ok!", "got it", "correct", "success"))
        ):
            return SubmitResult(
                "correct", verdict,
                f"CORRECT — pwnable.kr accepted: {verdict}",
            )
        if any(s in verdict_low for s in ("wrong", "incorrect", "fail", "no such")):
            return SubmitResult(
                "incorrect", verdict,
                f"INCORRECT — pwnable.kr rejected: {verdict}",
            )
        # Anything else: surface raw and treat as unknown so the
        # operator can iterate.
        return SubmitResult(
            "unknown", verdict or "(empty)",
            f"pwnable.kr returned: {verdict[:200] or '(empty body)'}",
        )

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Materialise a challenge directory with metadata.yml only.
        pwnable.kr challenges have no downloadable artifacts — the binary
        lives on the SSH host under /home/<user>/<binary>. The solver
        accesses it over SSH using the connection string in metadata."""
        from pathlib import Path

        import yaml

        # Resolve stub from cache if the caller passed only a name.
        stub: dict[str, Any] | None = None
        if "_pwnkr" in challenge:
            stub = challenge
        else:
            stub = self._stubs_by_name.get(challenge.get("name", ""))
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _pwnkr metadata for {challenge.get('name')!r}"
            )

        slug = _slugify(stub.get("name") or "challenge")
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # Make sure description / connection_info are populated. fetch_all
        # would have done this earlier, but pull may be called fresh from
        # an operator command.
        await self._hydrate_stub(slug)

        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": stub.get("category", "pwn"),
            "description": stub.get("description", ""),
            "value": stub.get("value", 0),
            "connection_info": stub.get("connection_info", ""),
            "tags": ["pwnablekr", _slugify(stub.get("category", "")) or "uncategorized"],
            "solves": stub.get("solves", 0),
            "pwnablekr": {
                "id": stub["_pwnkr"]["id"],
                "img_slug": stub["_pwnkr"]["img_slug"],
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
