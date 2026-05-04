"""pwn.college backend.

pwn.college is a CTFd plugin (the `dojo` plugin) that organises challenges
as `dojo → module → challenge`. The standard CTFd `/api/v1/challenges`
listing endpoint is disabled in production, so we discover challenges via
the dojo plugin's own API at `/pwncollege_api/v1/dojos/<id>/modules`. Flag
submission still flows through the standard CTFd path
(`/api/v1/challenges/attempt`) — we just have to resolve the dojo-level
slug name to the underlying CTFd integer challenge_id, which we do by
parsing the authenticated challenge HTML page.

This backend authenticates via session cookie only (subclassing
`CTFdSessionBackend`). pwn.college's API token UI is locked behind email
verification + isn't exposed to most users, so cookie auth is the path of
least resistance: log in to the site, copy the `session` cookie value,
done.

Configuration:
  - `base_url`        : https://pwn.college (or a self-hosted dojo)
  - `session_cookie`  : value of the `session` browser cookie
  - `dojos`           : list of dojo IDs to scope solving to (e.g.
                        ["welcome"] or ["intro-to-cybersecurity"]).
                        Discovery walks every dojo in this list; an empty
                        list means "discover all dojos visible to the
                        authenticated user", which is usually too broad.

Challenge naming:
  Names are `<dojo>/<module>/<challenge_slug>`, e.g.
  `welcome/welcome/terminal`. This collides cleanly with our existing
  challenge slug rules and survives round-tripping through metadata.yml.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from backend.backends.base import SubmitResult
from backend.backends.ctfd import CTFdSessionBackend

logger = logging.getLogger(__name__)


@dataclass
class PwnCollegeBackend(CTFdSessionBackend):
    """CTFd-with-dojo-plugin backend for pwn.college.

    Inherits CTFd cookie auth, CSRF nonce scraping, and the standard
    `/api/v1/challenges/attempt` submission path. Overrides:

      - challenge listing (uses the dojo plugin's API)
      - solved-names lookup (per-dojo, since the global one is heavy)
      - challenge-id resolution (slug name → CTFd int via HTML parse)
      - distfile pull (no distfiles — the challenge IS a remote container)
    """

    base_url: str = "https://pwn.college"
    # Dojo IDs to scope discovery to. Empty list means "all dojos visible
    # to the authenticated user", which is rarely what you want.
    dojos: list[str] = field(default_factory=list)

    # Cached metadata for resolved challenges, keyed by `<dojo>/<mod>/<chal>`.
    _challenge_meta: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    # CTFd int challenge_id cache keyed by (dojo, module). The dojo plugin
    # uses one int per module across all its slug-challenges, so this saves
    # us an HTTP round trip after the first resolve in the module.
    _module_int_ids: dict[tuple[str, str], int] = field(default_factory=dict, repr=False)

    # ---------- CSRF override ----------

    async def _get_csrf(self) -> str:
        """Scrape csrfNonce from /dojos.

        The dojo plugin redirects /challenges (301), so the upstream
        CTFdBackend._get_csrf can't find the nonce. /dojos is the dojo
        plugin's listing page; same csrfNonce template variable, served
        as 200, available pre- and post-login.
        """
        if self._csrf_token:
            return self._csrf_token
        client = await self._ensure_client()
        resp = await client.get("/dojos")
        m = re.search(r"csrfNonce':\s*\"([A-Fa-f0-9]+)\"", resp.text)
        if not m:
            m = re.search(r'csrfNonce["\']?\s*:\s*["\']([A-Fa-f0-9]+)["\']', resp.text)
        if not m:
            raise RuntimeError("Could not find csrfNonce on pwn.college /dojos page")
        self._csrf_token = m.group(1)
        return self._csrf_token

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Walk the configured dojos and flatten every module's challenges.

        Returns CTFd-shaped dicts so existing poller / coordinator code
        doesn't have to learn pwn.college's idea of a challenge. The
        `_pwn` key carries the dojo/module/slug triple for downstream
        operations (workspace spawn, flag submission, pull).
        """
        await self._ensure_logged_in()
        client = await self._ensure_client()

        dojos_to_walk = list(self.dojos)
        if not dojos_to_walk:
            # Fall back to listing all visible dojos. This can be large.
            try:
                resp = await client.get("/pwncollege_api/v1/dojos")
                resp.raise_for_status()
                dojos_to_walk = [d["id"] for d in resp.json().get("dojos", [])]
                logger.info("Walking %d dojos (no scope given)", len(dojos_to_walk))
            except Exception as e:
                logger.warning("Could not list dojos: %s", e)
                return []

        out: list[dict[str, Any]] = []
        for dojo_id in dojos_to_walk:
            try:
                resp = await client.get(f"/pwncollege_api/v1/dojos/{dojo_id}/modules")
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.warning("Could not fetch dojo %r modules: %s", dojo_id, e)
                continue
            if not data.get("success"):
                logger.warning("Dojo %r modules: %s", dojo_id, data)
                continue
            for module in data.get("modules", []):
                for ch in module.get("challenges", []):
                    name = f"{dojo_id}/{module['id']}/{ch['id']}"
                    stub = {
                        # The CTFd integer ID isn't returned by the dojo API,
                        # so we use 0 as a placeholder. submit_flag resolves
                        # the real ID lazily via _resolve_challenge_id.
                        "id": 0,
                        "name": name,
                        "category": f"{dojo_id}/{module.get('name') or module['id']}",
                        "value": 1,
                        "type": "standard",
                        "solves": 0,
                        "description": ch.get("description") or "",
                        # Carry the triple through for the spawn/submit/pull
                        # paths. Keep this under a `_pwn` namespace so it
                        # doesn't collide with CTFd-native fields.
                        "_pwn": {
                            "dojo": dojo_id,
                            "module": module["id"],
                            "module_name": module.get("name") or module["id"],
                            "challenge": ch["id"],
                            "challenge_name": ch.get("name") or ch["id"],
                            "required": bool(ch.get("required")),
                        },
                    }
                    self._challenge_meta[name] = stub["_pwn"]
                    out.append(stub)
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        # The dojo modules listing already returns descriptions; we don't
        # need a per-challenge follow-up like CTFd does. Just reuse stubs.
        return await self.fetch_challenge_stubs()

    async def fetch_solved_names(self) -> set[str]:
        """Aggregate per-dojo solves into a flat name set.

        The standard CTFd `/users/<id>/solves` endpoint also works on
        pwn.college, but it returns *underlying CTFd Challenge.name* values
        which collide across dojos (e.g. the same "embryoio_level1" name
        appears in multiple dojos). Per-dojo solves are unambiguous.
        """
        await self._ensure_logged_in()
        client = await self._ensure_client()

        # Discover the current user's username for the dojo-solves endpoint.
        try:
            me = await client.get("/api/v1/users/me", headers=self._base_headers())
            me.raise_for_status()
            username = me.json().get("data", {}).get("name")
        except Exception as e:
            logger.warning("Could not read /api/v1/users/me: %s", e)
            return set()
        if not username:
            return set()

        solved: set[str] = set()
        for dojo_id in (self.dojos or []):
            try:
                resp = await client.get(
                    f"/pwncollege_api/v1/dojos/{dojo_id}/solves",
                    params={"username": username},
                )
                resp.raise_for_status()
                for s in resp.json().get("solves", []):
                    solved.add(f"{dojo_id}/{s['module_id']}/{s['challenge_id']}")
            except Exception as e:
                logger.warning("Could not fetch solves for dojo %r: %s", dojo_id, e)
        return solved

    # ---------- submission ----------

    async def get_challenge_id(self, name: str) -> int:
        """Resolve `<dojo>/<module>/<challenge>` to the CTFd int challenge_id.

        The dojo plugin uses one underlying CTFd Challenge per *module*, so
        the int is a per-module constant — the dojo plugin disambiguates
        which `<challenge_slug>` a flag belongs to via the user's currently-
        active workspace. The int is embedded in the rendered page template
        as `<input id="challenge-id" type="hidden" value="...">`, but the
        page always reflects whichever challenge the user's workspace is
        on, so we have to make sure the workspace matches BEFORE reading
        the page.

        We treat the int as a per-module cache: once we've resolved it for
        any (dojo, module, *) we reuse it across all challenges in that
        module — saves an extra workspace re-spawn on subsequent calls.
        """
        if name in self._challenge_ids:
            return self._challenge_ids[name]

        meta = self._challenge_meta.get(name)
        if meta is None:
            # Cold cache — repopulate via listing.
            await self.fetch_challenge_stubs()
            meta = self._challenge_meta.get(name)
        if meta is None:
            raise RuntimeError(f"Challenge {name!r} not found in any configured dojo")

        # Per-module cache lookup
        module_key = (meta["dojo"], meta["module"])
        if module_key in self._module_int_ids:
            chid = self._module_int_ids[module_key]
            self._challenge_ids[name] = chid
            return chid

        # Make sure the workspace is on a challenge in this dojo+module
        # before we trust the page's challenge-id. We avoid POSTing if we
        # can — every /pwncollege_api/v1/docker POST tears down whatever
        # the workspace is currently running, which is expensive and
        # disruptive if it's mid-solve.
        current = await self.current_workspace_challenge()
        same_module = (
            current
            and current["dojo"] == meta["dojo"]
            and current["module"] == meta["module"]
        )
        if not same_module:
            logger.info(
                "get_challenge_id: spawning workspace for %s/%s/%s (was %s)",
                meta["dojo"], meta["module"], meta["challenge"], current,
            )
            await self.start_workspace(
                meta["dojo"], meta["module"], meta["challenge"]
            )

        await self._ensure_logged_in()
        client = await self._ensure_client()
        # The dojo blueprint registers the challenge view at the bare
        # /<dojo>/<module>/<challenge>/ path (without a /dojo/ prefix).
        # /dojo/<id>/* is reserved for admin/join/etc, NOT the listing.
        page_url = f"/{meta['dojo']}/{meta['module']}/{meta['challenge']}/"
        resp = await client.get(page_url, headers=self._base_headers())
        if resp.status_code != 200:
            raise RuntimeError(
                f"Could not load challenge page {page_url}: HTTP {resp.status_code}"
            )

        # The dojo theme renders the int challenge_id as a hidden input:
        #   <input id="challenge-id" type="hidden" value="18402">
        # alongside the slug ones (id="module" / id="challenge"). Pluck
        # the int; submission goes through standard CTFd /attempt with it.
        m = re.search(
            r'id=["\']challenge-id["\']\s+type=["\']hidden["\']\s+value=["\'](\d+)["\']',
            resp.text,
        )
        if not m:
            # Looser fallback in case attribute order changes:
            m = re.search(
                r'<input[^>]*id=["\']challenge-id["\'][^>]*value=["\'](\d+)["\']',
                resp.text,
            )
        if not m:
            # Last-resort fallback for older theme variants that exposed it
            # as a JSON value in template context.
            m = re.search(r'["\']challenge_id["\']\s*:\s*(\d+)', resp.text)
        if not m:
            raise RuntimeError(
                f"Could not find numeric challenge_id on {page_url}. "
                "The dojo theme may have changed; please report."
            )

        chid = int(m.group(1))
        self._challenge_ids[name] = chid
        self._module_int_ids[(meta["dojo"], meta["module"])] = chid
        return chid

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """Standard CTFd submission with our resolved int ID."""
        # Inherits CTFdBackend.submit_flag which calls get_challenge_id,
        # which we override above. So just delegate.
        return await super().submit_flag(challenge_name, flag)

    # ---------- pull ----------

    # ---------- workspace lifecycle (used by PwnCollegeEnv) ----------

    async def upload_ssh_key(self, public_key: str) -> None:
        """Register a public key for the current user.

        Idempotent: pwn.college returns 400 "SSH Key already in use" if the
        key was previously uploaded by ANY user (including this one). We
        treat that as success — re-uploading a key the server already
        knows about is the desired end-state.
        """
        if not public_key.strip():
            raise ValueError("upload_ssh_key: empty key")
        # /pwncollege_api/v1/ssh_key is the dojo plugin's endpoint (note the
        # underscore — the namespace is registered as "/ssh_key"). Not to
        # be confused with the standard CTFd /api/v1, which doesn't exist.
        await self._ensure_logged_in()
        client = await self._ensure_client()
        headers = self._base_headers()
        if not self.token:
            headers["CSRF-Token"] = await self._get_csrf()
        resp = await client.post(
            "/pwncollege_api/v1/ssh_key",
            json={"ssh_key": public_key.strip()},
            headers=headers,
        )
        if resp.status_code == 200 and resp.json().get("success"):
            logger.info("pwn.college SSH key registered")
            return
        # 400 + "already in use" is fine — the server has it.
        try:
            err = (resp.json() or {}).get("error", "")
        except Exception:
            err = resp.text[:200]
        if resp.status_code == 400 and "already in use" in err.lower():
            logger.info("pwn.college SSH key already registered")
            return
        resp.raise_for_status()
        # If we got here without error, the response shape was unexpected.
        raise RuntimeError(f"upload_ssh_key: unexpected response: {err or resp.text[:200]}")

    async def start_workspace(
        self,
        dojo: str,
        module: str,
        challenge: str,
        practice: bool = False,
    ) -> None:
        """Spawn (or replace) the user's per-challenge workspace container.

        pwn.college's docker_locked semantics mean this implicitly tears
        down any previously running workspace. The server returns 200 with
        a streaming JSON body on success; we drain it and check the final
        status."""
        await self._ensure_logged_in()
        client = await self._ensure_client()
        headers = self._base_headers()
        if not self.token:
            headers["CSRF-Token"] = await self._get_csrf()
        resp = await client.post(
            "/pwncollege_api/v1/docker",
            json={
                "dojo": dojo,
                "module": module,
                "challenge": challenge,
                "practice": bool(practice),
            },
            headers=headers,
            timeout=120.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"start_workspace({dojo}/{module}/{challenge}): "
                f"HTTP {resp.status_code}: {resp.text[:300]}"
            )
        # The endpoint streams progress; the final line is JSON with
        # {"success": true} on a clean spawn.
        body = resp.text.strip().splitlines()
        last = body[-1] if body else ""
        try:
            import json as _json
            status = _json.loads(last)
        except Exception:
            raise RuntimeError(
                f"start_workspace: could not parse final status: {last[:200]}"
            )
        if not status.get("success"):
            raise RuntimeError(
                f"start_workspace failed: {status.get('error') or status}"
            )
        logger.info(
            "pwn.college workspace started: %s/%s/%s", dojo, module, challenge
        )

    async def reset_workspace_home(self) -> None:
        """Wipe /home/hacker on the user's workspace.

        Use this between challenges to keep solver runs isolated. No-op if
        no workspace is currently running."""
        await self._ensure_logged_in()
        client = await self._ensure_client()
        headers = self._base_headers()
        if not self.token:
            headers["CSRF-Token"] = await self._get_csrf()
        resp = await client.post(
            "/pwncollege_api/v1/workspace/reset_home",
            headers=headers,
            json={},
        )
        if resp.status_code == 200 and resp.json().get("success"):
            logger.info("pwn.college workspace home reset")
            return
        # No-running-workspace and other soft failures: don't raise.
        try:
            err = resp.json().get("error", "")
        except Exception:
            err = resp.text[:200]
        logger.warning("reset_workspace_home soft-failed: %s", err)

    async def current_workspace_challenge(self) -> dict[str, str] | None:
        """Return {dojo, module, challenge} of the running workspace, or None."""
        await self._ensure_logged_in()
        client = await self._ensure_client()
        headers = self._base_headers()
        try:
            resp = await client.get(
                "/pwncollege_api/v1/workspace",
                headers=headers,
            )
            data = resp.json() if resp.status_code == 200 else {}
        except Exception:
            return None
        info = data.get("current_challenge") if isinstance(data, dict) else None
        if not info:
            return None
        return {
            "dojo": info.get("dojo_id", ""),
            "module": info.get("module_id", ""),
            "challenge": info.get("challenge_id", ""),
        }

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Write a metadata.yml with the dojo/module/challenge triple.

        pwn.college challenges are containerised on their side — there are
        no distfiles to download. The metadata is what the orchestrator
        needs to spawn the workspace and run the solver.
        """
        from pathlib import Path

        import yaml

        pwn = challenge.get("_pwn") or self._challenge_meta.get(challenge.get("name", ""))
        if not pwn:
            raise RuntimeError(
                f"PwnCollegeBackend.pull_challenge: challenge {challenge.get('name')!r} "
                "has no pwn.college metadata — was it produced by fetch_challenge_stubs?"
            )

        slug = (
            re.sub(r"[^a-z0-9-]+", "-", challenge["name"].lower().replace("/", "-"))
            .strip("-")
            or "challenge"
        )
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        meta = {
            "name": challenge["name"],
            "category": challenge.get("category", ""),
            "description": (challenge.get("description") or "").strip(),
            "value": challenge.get("value", 0),
            "tags": ["pwncollege", pwn["dojo"], pwn["module"]],
            "solves": challenge.get("solves", 0),
            # The 'pwncollege' block is the orchestration contract for the
            # solver: which workspace to spawn, what env to target, and
            # the slug triple needed to call `/api/v1/docker`.
            "pwncollege": {
                "dojo": pwn["dojo"],
                "module": pwn["module"],
                "challenge": pwn["challenge"],
                "exec_env": "pwncollege",
            },
        }

        (ch_dir / "metadata.yml").write_text(
            yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False)
        )
        return str(ch_dir)
