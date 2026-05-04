"""pwnable.tw backend.

pwnable.tw is a custom Django site (not CTFd-based) hosting binary
exploitation wargame challenges. Each challenge ships a downloadable
binary plus a remote netcat target; you exploit the service to read a
flag and submit it back through the site.

Auth: Django form-login at `/user/login` with a `csrfmiddlewaretoken`
hidden form field and a `csrftoken` cookie. Successful POST returns 302
and sets a `sessionid` cookie. Subsequent state-changing POSTs (flag
submission) must include `X-CSRFToken: <csrftoken cookie>` plus a
`Referer:` header pointing at the same origin (Django's standard CSRF
middleware checks both).

Challenge listing: `/challenge/` HTML page contains every challenge
inline — id, title, score, description (with the netcat target and
distfile links embedded), solve count. Logged-in renders the same set
plus per-challenge solve markers.

Flag submission: `POST /challenge/submit_flag` with form fields
`{flag, id}` returns a JSON-encoded body. Response values observed
(verified against the dojo theme's challenge.js handler):
  - `"<int>"`      — CORRECT. The integer is the challenge id; the JS
                     uses it to mark `#flag-id-<int>` as solved.
  - `"wrong"`      — flag rejected
  - `"duplicated"` — already submitted by this user
  - `"error"`      — server-side transport error
The JS treats *any non-empty value other than 'error'/'wrong'/
'duplicated'* as success — i.e. any int (or future string) means the
flag landed. We mirror that: known-bad strings → incorrect/etc.,
anything else truthy → correct.

Solver flow:
  - Local Docker sandbox runs the agent (no remote workspace).
  - Connection info `nc chall.pwnable.tw <port>` lands in metadata.yml
    so the prompt's "service connection" hint kicks in automatically.
  - Distfiles bind-mounted at /challenge/distfiles/<name> like any
    other CTFd-shaped backend.
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
    """pwnable.tw titles are short ASCII words; lowercased + hyphenated."""
    s = name.strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "challenge"


@dataclass
class PwnableTwBackend(Backend):
    """Django-form-auth + HTML-scraping backend for pwnable.tw."""

    base_url: str = "https://pwnable.tw"
    username: str = ""
    password: str = ""

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _logged_in: bool = field(default=False, repr=False)
    # name → CTFd-style stub dict, including challenge_id (int) and the
    # raw description with embedded distfile links + netcat target.
    _stubs_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

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

    @property
    def _csrftoken(self) -> str:
        """Latest csrftoken cookie value, refreshed each time the
        session cookie jar updates."""
        if self._client is None:
            return ""
        return self._client.cookies.get("csrftoken", "")

    async def _ensure_logged_in(self) -> None:
        if self._logged_in:
            return
        if not self.username or not self.password:
            raise RuntimeError(
                "PwnableTwBackend: username + password are required (no "
                "API token / cookie auth path is exposed)"
            )
        client = await self._ensure_client()

        # GET login page — sets csrftoken cookie + form nonce
        resp = await client.get("/user/login")
        if resp.status_code != 200:
            raise RuntimeError(
                f"GET /user/login: HTTP {resp.status_code}"
            )
        m = re.search(
            r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text
        )
        if not m:
            raise RuntimeError(
                "Could not find csrfmiddlewaretoken on /user/login"
            )
        nonce = m.group(1)

        # POST credentials. Django requires:
        #   - csrfmiddlewaretoken form field matching the csrftoken cookie
        #   - Referer header pointing at the same origin
        # Successful login: 302 redirect + sessionid cookie set.
        # Failed login: 200 with the form re-rendered (cookie unchanged).
        resp = await client.post(
            "/user/login",
            data={
                "csrfmiddlewaretoken": nonce,
                "username": self.username,
                "password": self.password,
                "next": "",
            },
            headers={
                "Referer": f"{self.base_url}/user/login",
                "Origin": self.base_url,
            },
        )
        if resp.status_code != 302:
            # Most common case: 200 with "Please enter a correct
            # email and password" alert in the body.
            err = re.search(
                r'<div class="alert alert-danger">.*?</div>',
                resp.text,
                re.DOTALL,
            )
            if err:
                msg = re.sub(r"\s+", " ", err.group(0))[:200]
                raise RuntimeError(f"pwnable.tw login failed — {msg}")
            raise RuntimeError(
                f"pwnable.tw login: unexpected HTTP {resp.status_code}"
            )
        if "sessionid" not in client.cookies:
            raise RuntimeError(
                "pwnable.tw login returned 302 but no sessionid cookie was set"
            )
        self._logged_in = True
        logger.info("pwnable.tw login OK as %s", self.username)

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Scrape the /challenge/ HTML for every visible challenge.

        Each challenge block is a `<li class="challenge-entry unlocked"
        id="challenge-id-<int>">` with title / score / description /
        distfile links inline. We also grab the netcat target out of
        the description (always shaped `<code>nc chall.pwnable.tw
        <port></code>`) and stash it as `connection_info` so the solver
        prompt's existing service-hint logic kicks in.
        """
        await self._ensure_logged_in()
        client = await self._ensure_client()
        resp = await client.get("/challenge/")
        if resp.status_code != 200:
            raise RuntimeError(
                f"GET /challenge/: HTTP {resp.status_code}"
            )

        # Split into per-challenge blocks. Each starts with the entry
        # marker and runs until the next one (or end of section).
        blocks = re.findall(
            r'class="challenge-entry unlocked"[^>]*id="challenge-id-(\d+)">'
            r'(.*?)(?=<li class="challenge-entry|</ul>\s*</div>\s*</section>)',
            resp.text,
            re.DOTALL,
        )
        out: list[dict[str, Any]] = []
        for cid_str, body in blocks:
            title_m = re.search(r'<span class="tititle">([^<]+)</span>', body)
            if not title_m:
                continue
            title = title_m.group(1).strip()
            slug = _slugify(title)

            score_m = re.search(r'<span class="score"><i>(\d+)\s*pts?', body)
            value = int(score_m.group(1)) if score_m else 0

            solved_m = re.search(r"Solved\s+(\d+)\s+times", body)
            solves = int(solved_m.group(1)) if solved_m else 0

            desc_m = re.search(
                r'<div class="description"[^>]*>(.*?)</div>', body, re.DOTALL
            )
            desc_html = desc_m.group(1).strip() if desc_m else ""

            nc_m = re.search(r"<code>(nc\s+[^<]+)</code>", desc_html)
            connection_info = nc_m.group(1).strip() if nc_m else ""

            distfiles = re.findall(r'href="?(/static/chall/[^"\'\s>]+)', desc_html)

            stub = {
                "id": int(cid_str),
                "name": slug,
                "title": title,                     # original case for prompts
                "category": "pwn",
                "value": value,
                "solves": solves,
                "type": "standard",
                "description": desc_html,
                "connection_info": connection_info,
                "_pwntw": {
                    "id": int(cid_str),
                    "distfile_paths": distfiles,
                },
            }
            self._stubs_by_name[slug] = stub
            out.append(stub)
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """The listing page already includes full descriptions. No
        per-challenge fetch needed."""
        return await self.fetch_challenge_stubs()

    async def fetch_solved_names(self) -> set[str]:
        """Read the `/user/` profile's "Solved Challenges" table.

        The /challenge/ listing's per-flag markers are identical for
        solved and unsolved (every entry renders `glyphicon-ok`), so
        that page is useless as a solve oracle. The user's profile,
        however, has a table:

          <h4>Solved Challenges</h4>
          <table>
            <tr><td>1</td><td><a href="/challenge/#2">orw</a></td>...
            <tr><td>2</td><td><a href="/challenge/#1">Start</a></td>...
            ...

        We pull `/challenge/#<int>` ids from each row and map each to
        a slug via the cached fetch_challenge_stubs map (which keys by
        slug → _pwntw.id). Re-fetches the stubs on cold cache so a
        fresh backend boot Just Works.
        """
        await self._ensure_logged_in()
        client = await self._ensure_client()

        try:
            resp = await client.get("/user/", follow_redirects=True)
            resp.raise_for_status()
        except Exception as e:
            logger.warning("Could not fetch /user/ profile: %s", e)
            return set()

        # Snip out the "Solved Challenges" section and pull the int IDs.
        idx = resp.text.find("Solved Challenges")
        if idx < 0:
            return set()
        section = resp.text[idx:]
        ids = {
            int(m.group(1))
            for m in re.finditer(r'href="/challenge/#(\d+)"', section)
        }
        if not ids:
            return set()

        # Map int id → slug. Populate stubs cache if cold.
        if not self._stubs_by_name:
            await self.fetch_challenge_stubs()
        id_to_name = {
            stub["_pwntw"]["id"]: name
            for name, stub in self._stubs_by_name.items()
        }
        return {id_to_name[i] for i in ids if i in id_to_name}

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """POST /challenge/submit_flag with {flag, id}. The endpoint
        returns plain text:
          - 'correct'     → success
          - 'duplicated'  → already solved by this user
          - 'error'       → wrong flag (or transport error)

        Failed submissions return HTTP 200 with one of the strings; we
        translate to our standard SubmitResult shape.
        """
        await self._ensure_logged_in()
        client = await self._ensure_client()

        # Resolve slug → int challenge_id via cached stubs; refresh on
        # cache miss in case the operator handed us a slug we haven't
        # seen yet.
        if challenge_name not in self._stubs_by_name:
            await self.fetch_challenge_stubs()
        stub = self._stubs_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(
                f'Challenge "{challenge_name}" not found in pwnable.tw listing'
            )
        challenge_id = stub["_pwntw"]["id"]

        # Django CSRF for AJAX: cookie value must be sent in
        # X-CSRFToken header, AND the request must carry a Referer.
        csrf = self._csrftoken
        if not csrf:
            raise RuntimeError("No csrftoken cookie — login state is broken")
        resp = await client.post(
            "/challenge/submit_flag",
            data={"flag": flag.strip(), "id": str(challenge_id)},
            headers={
                "X-CSRFToken": csrf,
                "Referer": f"{self.base_url}/challenge/",
                "Origin": self.base_url,
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        if resp.status_code != 200:
            return SubmitResult(
                "unknown",
                f"HTTP {resp.status_code}",
                f"submit_flag transport error: HTTP {resp.status_code}",
            )

        # The endpoint returns a JSON-encoded body. The frontend's
        # response logic (dojo_theme/static/js/challenge.js) checks
        # against three known-bad strings; anything else truthy is
        # treated as success and the value happens to be the challenge
        # id (used to mark `#flag-id-<id>` as solved client-side).
        raw = (resp.text or "").strip()
        body = raw.lower()
        if body.startswith('"') and body.endswith('"'):
            body = body[1:-1]

        if body == "duplicated":
            return SubmitResult(
                "already_solved", "duplicated",
                f'ALREADY SOLVED — "{flag}" was previously accepted',
            )
        if body == "wrong":
            return SubmitResult(
                "incorrect", "wrong",
                f'INCORRECT — "{flag}" rejected by pwnable.tw',
            )
        if body == "error":
            # Transport error on the server side; the JS client retries.
            return SubmitResult(
                "unknown", "error",
                'pwnable.tw returned "error" — transient transport failure, retry',
            )
        if body:
            # Truthy non-error → success. Body is typically the int
            # challenge id (e.g. '"2"' for orw); occasionally pwnable.tw
            # may return literal "correct" — handle both.
            return SubmitResult(
                "correct", body or "correct",
                f'CORRECT — "{flag}" accepted on pwnable.tw',
            )
        # Empty body — treat as transport failure, not silently success.
        return SubmitResult(
            "unknown", "",
            "pwnable.tw returned empty body — assume transport failure",
        )

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Download every distfile listed in the challenge description
        plus write a metadata.yml the solver prompt can render."""
        from pathlib import Path
        from urllib.parse import urlparse

        import yaml
        try:
            from markdownify import markdownify as html2md
        except Exception:
            html2md = None  # graceful degrade — keep raw HTML

        stub = challenge if "_pwntw" in challenge else self._stubs_by_name.get(
            challenge.get("name", "")
        )
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _pwntw metadata for {challenge.get('name')!r}"
            )

        slug = _slugify(challenge.get("name") or stub.get("name", "challenge"))
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        await self._ensure_logged_in()
        client = await self._ensure_client()

        # Distfiles. The links are typically site-relative
        # (`/static/chall/<name>`) but tolerate absolute too.
        for url in stub["_pwntw"]["distfile_paths"]:
            full = url if url.startswith("http") else f"{self.base_url.rstrip('/')}{url}"
            fname = urlparse(full).path.rsplit("/", 1)[-1] or "file"
            dest_dir = ch_dir / "distfiles"
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / fname
            if dest.exists():
                continue
            try:
                resp = await client.get(full, follow_redirects=True, timeout=120.0)
                resp.raise_for_status()
                dest.write_bytes(resp.content)
                logger.info("pwnable.tw: pulled %s (%d bytes)", fname, len(resp.content))
            except Exception as e:
                logger.warning("pwnable.tw: pull %s failed: %s", full, e)

        # Description: convert to markdown if we can — the prompt
        # builder embeds it as-is, and HTML in a Markdown context
        # mostly works but is uglier than rendered text.
        desc = stub.get("description", "") or ""
        if html2md and desc:
            try:
                desc = html2md(desc, heading_style="atx").strip()
            except Exception:
                pass

        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": "pwn",
            "description": desc,
            "value": stub.get("value", 0),
            "connection_info": stub.get("connection_info", ""),
            "tags": ["pwnabletw"],
            "solves": stub.get("solves", 0),
            "pwnabletw": {
                "id": stub["_pwntw"]["id"],
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
