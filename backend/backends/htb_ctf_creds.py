"""HackTheBox CTF events backend, talking to ctf.hackthebox.com directly.

Stable fallback for when the MCP server (htb-ctf-mcp) shifts under us
or for events that haven't opted in to AI participation. Same event
catalog, same flag submission, same container/machine lifecycle —
but accessed via the human-facing REST API at /api/* with Laravel
session cookies + XSRF-TOKEN, not via JSON-RPC over MCP.

# Auth: cookie import (primary) vs programmatic SSO (not implemented)

ctf.hackthebox.com doesn't host its own login form — auth comes from
HTB's central SSO at account.hackthebox.com via the OAuth-style
flow (`/sso/redirect` → cross-domain login at account.htb → callback
with auth code → laravel_session cookie set). Driving that
programmatically is brittle:

  - Anti-bot / Cloudflare challenges on account.hackthebox.com
  - CSRF tokens rotated between flow steps
  - JS-driven elements in some login states (TOTP, captcha)

Cookie import is what this backend supports today. The operator:

  1. Logs into ctf.hackthebox.com via their normal browser
  2. Opens DevTools → Application → Cookies → ctf.hackthebox.com
  3. Copies XSRF-TOKEN and htb_session into sessions/<name>/.env:
        htb_creds_xsrf_token=<XSRF-TOKEN cookie value, URL-decoded>
        htb_creds_session=<htb_session cookie value>
  4. Cookies typically last 1-2 days; refresh when 401 starts hitting

A future commit may add `programmatic_login(email, password)` for
non-MFA accounts where the SSO flow is stable enough to automate.

# VPN-machine support

Some CTF events ship full VMs reachable only over OpenVPN. The
endpoints exist (`/api/challenges/machines/spawn/`,
`/api/ctfs/vpn/download/`) and pair with the same VPN sidecar
mechanism we built for htb-machines. start_instance dispatches based
on whether a challenge `hasMachine` (VPN-tunnelled) or `hasDocker`
(plain container).
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.backends.base import Backend, SubmitResult

logger = logging.getLogger(__name__)


CTF_HOST = "https://ctf.hackthebox.com"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "challenge"


@dataclass
class HtbCtfCredsBackend(Backend):
    """Cookie-import-driven backend for HTB CTF events."""

    # Cookie values from the operator's browser session.
    xsrf_token: str = ""        # URL-decoded XSRF-TOKEN cookie value
    session_cookie: str = ""    # htb_session cookie value
    event_id: int = 0
    base_url: str = CTF_HOST
    # Sidecar image for VPN-tunnelled machine challenges. Default
    # matches the htb-machines convention; users on older sandbox
    # builds can override per session.
    sidecar_image: str = "ctf-vpn"

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _challenges_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _categories_by_id: dict[int, str] = field(default_factory=dict, repr=False)
    _team_id: int | None = field(default=None, repr=False)
    _live_containers: dict[str, str] = field(default_factory=dict, repr=False)
    # VPN sidecar (only spawned when a machine challenge is started).
    _vpn_container: Any = field(default=None, repr=False)
    _vpn_container_name: str = field(default="", repr=False)
    # Ref-counted machine spawns (matches htb-machines pattern; lets
    # parallel siblings share one VPN tunnel + machine slot).
    _machine_refs: set[str] = field(default_factory=set, repr=False)

    # ---------- HTTP plumbing ----------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self.session_cookie or not self.xsrf_token:
                raise RuntimeError(
                    "HtbCtfCredsBackend: both htb_creds_xsrf_token and "
                    "htb_creds_session are required. Export them from "
                    "DevTools → Application → Cookies → ctf.hackthebox.com "
                    "and put them in sessions/<name>/.env. The XSRF-TOKEN "
                    "value must be URL-decoded (replace %3D with =, etc.)."
                )
            if self.event_id <= 0:
                raise RuntimeError(
                    "HtbCtfCredsBackend: event_id required — set "
                    "htb_creds_event_id in session settings"
                )
            cookies = {
                "XSRF-TOKEN": urllib.parse.quote(self.xsrf_token, safe=""),
                "htb_session": self.session_cookie,
            }
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=60.0,
                cookies=cookies,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                    # Laravel CSRF: header value is the URL-decoded cookie value.
                    "X-XSRF-TOKEN": self.xsrf_token,
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{self.base_url}/",
                    "Origin": self.base_url,
                },
            )
        return self._client

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """One round-trip with auth + retry on transient 5xx. 401 is
        terminal — surface a clear message about cookie staleness."""
        client = await self._ensure_client()
        backoff = 2.0
        for attempt in range(3):
            resp = await client.request(method, path, **kwargs)
            if resp.status_code == 401:
                raise RuntimeError(
                    f"HTB creds: HTTP 401 on {method} {path} — session "
                    "cookies are stale. Re-export XSRF-TOKEN + htb_session "
                    "from your browser and update the .env."
                )
            if resp.status_code == 419:
                raise RuntimeError(
                    f"HTB creds: HTTP 419 on {method} {path} — XSRF token "
                    "mismatch. The cookie and X-XSRF-TOKEN header drifted; "
                    "re-export XSRF-TOKEN."
                )
            if 500 <= resp.status_code < 600 and attempt < 2:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            return resp
        return resp

    async def _get_json(self, path: str, **kwargs: Any) -> Any:
        resp = await self._request("GET", path, **kwargs)
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTB creds GET {path}: HTTP {resp.status_code} {resp.text[:200]}"
            )
        return resp.json()

    # ---------- one-time setup ----------

    async def _ensure_categories(self) -> dict[int, str]:
        """Hydrate the id → category-name map from the public endpoint
        (no auth needed but the API path is fine to use either way).
        Cached for the backend lifetime."""
        if self._categories_by_id:
            return self._categories_by_id
        try:
            body = await self._get_json("/api/public/challenge-categories")
        except Exception as e:
            logger.warning(
                "HTB creds: /api/public/challenge-categories failed (%s) — "
                "categories will fall back to category_<id>", e,
            )
            return self._categories_by_id
        # Endpoint shape: either {data: [...]} or [...] depending on Laravel
        # resource wrapper config — handle both.
        items = body.get("data", body) if isinstance(body, dict) else body
        if isinstance(items, list):
            for c in items:
                if isinstance(c, dict) and "id" in c and "name" in c:
                    self._categories_by_id[int(c["id"])] = str(c["name"])
        return self._categories_by_id

    def _category_for(self, cat_id: Any) -> str:
        if isinstance(cat_id, int) and cat_id in self._categories_by_id:
            return self._categories_by_id[cat_id]
        return f"category_{cat_id}" if cat_id is not None else "Unknown"

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """GET /api/ctfs/{event_id} — full event payload + challenges.

        Schema mirrors retrieve_ctf from the MCP wrapper (this is the
        underlying REST endpoint the MCP server proxies). Per-challenge
        fields: id, name, hasDocker, hasMachine, filename, points,
        difficulty, solved, etc.
        """
        await self._ensure_categories()
        body = await self._get_json(f"/api/ctfs/{self.event_id}")
        # The endpoint wraps the event in either `data` or top-level.
        event = body.get("data", body) if isinstance(body, dict) else body
        if not isinstance(event, dict):
            raise RuntimeError(f"HTB creds /api/ctfs/{self.event_id}: unexpected shape {body!r}")
        challenges = event.get("challenges") or []

        out: list[dict[str, Any]] = []
        for c in challenges:
            name = c.get("name") or ""
            slug = _slugify(name)
            filename = c.get("filename") or ""
            has_docker = bool(c.get("hasDocker"))
            has_machine = bool(c.get("hasMachine"))
            stub = {
                "id": c.get("id"),
                "name": slug,
                "title": name,
                "category": self._category_for(c.get("challenge_category_id")),
                "value": int(c.get("points") or 0),
                "solves": int(c.get("solves") or 0),
                "type": "standard",
                "description": c.get("description") or "",
                "connection_info": "",
                "_htb_ctf": {
                    "id": c.get("id"),
                    "difficulty": c.get("difficulty") or "",
                    "has_container": has_docker,
                    "has_machine": has_machine,
                    "has_download": bool(filename),
                    "file_name": filename,
                    "docker_instance_type": c.get("docker_instance_type") or "",
                    "solved": bool(c.get("solved")),
                },
            }
            self._challenges_by_name[slug] = stub
            out.append(stub)
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        return await self.fetch_challenge_stubs()

    async def fetch_solved_names(self) -> set[str]:
        await self.fetch_challenge_stubs()
        return {
            name for name, stub in self._challenges_by_name.items()
            if stub["_htb_ctf"].get("solved")
        }

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        if challenge_name not in self._challenges_by_name:
            await self.fetch_challenge_stubs()
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB creds: challenge {challenge_name!r} not in event {self.event_id}")
        cid = stub["_htb_ctf"]["id"]

        resp = await self._request(
            "POST", "/api/flags/own",
            json={"challenge_id": cid, "flag": flag.strip()},
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
                f"HTB returned non-JSON: {resp.text[:200]}",
            )

        msg = (body.get("message") or "").strip()
        success = bool(body.get("success"))
        msg_lower = msg.lower()

        if "already" in msg_lower and ("solved" in msg_lower or "submitted" in msg_lower or "owned" in msg_lower):
            stub["_htb_ctf"]["solved"] = True
            return SubmitResult(
                "already_solved", msg,
                f'ALREADY SOLVED — flag previously accepted ({msg})',
            )
        if success:
            stub["_htb_ctf"]["solved"] = True
            return SubmitResult(
                "correct", msg or "accepted",
                f'CORRECT — accepted by HTB ({msg})',
            )
        return SubmitResult(
            "incorrect", msg or "rejected",
            f'INCORRECT — rejected by HTB ({msg})',
        )

    # ---------- per-challenge instance lifecycle ----------

    async def start_instance(self, challenge_name: str) -> str | None:
        """Dispatch to the right spawn endpoint based on what the
        challenge actually exposes:
          - hasDocker → POST /api/challenges/containers/start (TCP/HTTP service)
          - hasMachine → spawn VPN sidecar + POST /api/challenges/machines/spawn/
          - neither → static challenge, no spawn needed
        """
        if challenge_name not in self._challenges_by_name:
            await self.fetch_challenge_stubs()
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB creds: challenge {challenge_name!r} not found")
        cid = stub["_htb_ctf"]["id"]

        if challenge_name in self._live_containers:
            return self._live_containers[challenge_name]

        if stub["_htb_ctf"].get("has_container"):
            return await self._start_docker(challenge_name, cid, stub)
        if stub["_htb_ctf"].get("has_machine"):
            return await self._start_machine(challenge_name, cid, stub)
        return None

    async def _start_docker(self, name: str, cid: int, stub: dict[str, Any]) -> str:
        resp = await self._request(
            "POST", "/api/challenges/containers/start",
            json={"challenge_id": cid},
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"HTB creds containers/start({name}): HTTP {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        ip, ports = self._extract_ip_ports(body)

        # Some events provision asynchronously — poll status if not ready.
        deadline = asyncio.get_event_loop().time() + 30.0
        while (not ip or not ports) and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2.0)
            try:
                status = await self._get_json(f"/api/challenges/containers/{cid}")
                ip, ports = self._extract_ip_ports(status)
            except Exception as e:
                logger.warning("HTB creds container_status(%s): %s", name, e)
                break
        if not ip or not ports:
            raise RuntimeError(
                f"HTB creds {name}: container never reported IP+ports within 30s"
            )

        category = (stub.get("category") or "").lower()
        instance_type = (stub["_htb_ctf"].get("docker_instance_type") or "").lower()
        if category == "web" or instance_type == "web":
            conn = f"http://{ip}:{ports[0]}"
        elif category in ("pwn", "crypto") or instance_type == "tcp":
            conn = f"nc {ip} {ports[0]}"
        else:
            conn = f"{ip}:{ports[0]}"
        self._live_containers[name] = conn
        logger.info("HTB creds %s: container at %s", name, conn)
        return conn

    async def _start_machine(self, name: str, cid: int, stub: dict[str, Any]) -> str:
        """VPN-tunnelled machine. Spawns the ctf-vpn sidecar (shared
        across all machine spawns in this session via ref-count), then
        POSTs the machine spawn, then polls for IP."""
        await self._ensure_vpn_sidecar()
        self._machine_refs.add(name)
        try:
            resp = await self._request(
                "POST", f"/api/challenges/machines/spawn/{cid}",
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"HTB creds machines/spawn({name}): HTTP {resp.status_code} {resp.text[:200]}"
                )
            # Poll machine status. The exact path varies — try the
            # container-style first, then the connection-status fallback.
            deadline = asyncio.get_event_loop().time() + 180.0
            ip = ""
            while asyncio.get_event_loop().time() < deadline:
                try:
                    status = await self._get_json(
                        f"/api/ctfs/connection-status/{self.event_id}"
                    )
                    ip = self._extract_machine_ip(status, cid)
                    if ip:
                        break
                except Exception as e:
                    logger.debug("connection-status poll: %s", e)
                await asyncio.sleep(5.0)
            if not ip:
                raise RuntimeError(
                    f"HTB creds {name}: machine never reported reachable IP"
                )
            os_hint = stub.get("category", "")
            conn = f"{ip}  (HTB CTF machine, {os_hint} — scan with `nmap -sCV {ip}`)"
            self._live_containers[name] = conn
            return conn
        except Exception:
            self._machine_refs.discard(name)
            await self._maybe_stop_vpn_sidecar()
            raise

    @staticmethod
    def _extract_ip_ports(body: Any) -> tuple[str, list[int]]:
        """Same shape as the MCP wrapper — `{hostname, ports[]}` is the
        primary shape. Fallbacks for schema drift."""
        if not isinstance(body, dict):
            return "", []
        ip = (
            body.get("hostname")
            or body.get("ip")
            or body.get("host")
            or body.get("address")
            or (body.get("data") or {}).get("hostname", "")
            or (body.get("data") or {}).get("ip", "")
        )
        ports_raw = (
            body.get("ports")
            or body.get("port")
            or (body.get("data") or {}).get("ports")
            or []
        )
        if isinstance(ports_raw, (str, int)):
            ports_raw = [ports_raw]
        ports: list[int] = []
        for p in ports_raw or []:
            try:
                ports.append(int(p))
            except (TypeError, ValueError):
                pass
        return str(ip or ""), ports

    @staticmethod
    def _extract_machine_ip(body: Any, cid: int) -> str:
        """Pull the assigned 10.10.x.x for the spawned machine out of
        connection-status — payload typically has a list of active
        machines keyed by challenge_id."""
        if not isinstance(body, dict):
            return ""
        data = body.get("data", body)
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and entry.get("challenge_id") == cid:
                    return str(entry.get("ip") or entry.get("address") or "")
        elif isinstance(data, dict):
            return str(data.get("ip") or data.get("address") or "")
        return ""

    async def stop_instance(self, challenge_name: str) -> None:
        if challenge_name not in self._live_containers:
            return
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            return
        cid = stub["_htb_ctf"]["id"]
        if challenge_name in self._machine_refs:
            try:
                await self._request("POST", f"/api/challenges/machines/destroy/{cid}")
            except Exception as e:
                logger.warning("HTB creds machine destroy(%s): %s", challenge_name, e)
            self._machine_refs.discard(challenge_name)
            await self._maybe_stop_vpn_sidecar()
        else:
            try:
                await self._request("POST", "/api/challenges/containers/stop",
                                    json={"challenge_id": cid})
            except Exception as e:
                logger.warning("HTB creds container stop(%s): %s", challenge_name, e)
        self._live_containers.pop(challenge_name, None)

    # ---------- VPN sidecar (machine-only) ----------

    async def _ensure_vpn_sidecar(self) -> None:
        if self._vpn_container is not None:
            return
        # Lazy-import — keeps the backend importable in environments
        # without aiodocker for users who only need static + Docker
        # challenges and never call _start_machine.
        import aiodocker  # type: ignore
        from pathlib import Path

        ovpn = await self._fetch_ovpn()
        from backend.sandbox import RUN_ID, CONTAINER_LABEL, RUN_LABEL
        docker = aiodocker.Docker()
        self._vpn_container_name = f"ctf-creds-vpn-{RUN_ID[:12]}"
        try:
            self._vpn_container = await docker.containers.create_or_replace(
                name=self._vpn_container_name,
                config={
                    "Image": self.sidecar_image,
                    "Cmd": ["openvpn", "--config", "/vpn.ovpn",
                            "--connect-retry-max", "3", "--script-security", "2"],
                    "Tty": False,
                    "Labels": {CONTAINER_LABEL: "true", RUN_LABEL: RUN_ID,
                               "ctf-agent.role": "vpn-sidecar"},
                    "HostConfig": {
                        "Binds": [f"{str(ovpn)}:/vpn.ovpn:ro"],
                        "CapAdd": ["NET_ADMIN"],
                        "Devices": [{
                            "PathOnHost": "/dev/net/tun",
                            "PathInContainer": "/dev/net/tun",
                            "CgroupPermissions": "rwm",
                        }],
                        "Dns": ["1.1.1.1", "8.8.8.8"],
                    },
                },
            )
            await self._vpn_container.start()
            for _ in range(20):
                await asyncio.sleep(1.5)
                exec_inst = await self._vpn_container.exec(
                    cmd=["sh", "-c", "ip addr show tun0 2>/dev/null | grep -q 'inet '"],
                    stdout=False, stderr=False,
                )
                stream = exec_inst.start(detach=False)
                async for _ in stream:
                    pass
                inspect = await exec_inst.inspect()
                if inspect.get("ExitCode") == 0:
                    logger.info("HTB creds VPN sidecar %s: tun0 up",
                                self._vpn_container_name)
                    return
            raise RuntimeError(
                f"VPN sidecar {self._vpn_container_name} never brought tun0 up "
                "within 30s — check `docker logs <name>`"
            )
        finally:
            await docker.close()

    async def _maybe_stop_vpn_sidecar(self) -> None:
        if self._machine_refs:
            return
        if self._vpn_container is None:
            return
        try:
            await self._vpn_container.stop(timeout=5)
        except Exception as e:
            logger.warning("VPN sidecar stop: %s", e)
        try:
            await self._vpn_container.delete(force=True)
        except Exception as e:
            logger.warning("VPN sidecar delete: %s", e)
        self._vpn_container = None
        self._vpn_container_name = ""

    async def _fetch_ovpn(self) -> Any:
        from pathlib import Path
        cache = Path.home() / ".ctf-agent" / f"htb-ctf-{self.event_id}.ovpn"
        if cache.exists() and cache.stat().st_size > 100:
            return cache
        # First, list servers to pick one. Endpoint is /api/ctfs/vpn-servers.
        servers = await self._get_json("/api/ctfs/vpn-servers")
        # Take the first server id we can find — operator can override
        # later if a specific region is required.
        sid: int | None = None
        items = servers.get("data", servers) if isinstance(servers, dict) else servers
        if isinstance(items, list):
            for s in items:
                if isinstance(s, dict) and s.get("id") is not None:
                    sid = int(s["id"])
                    break
        if sid is None:
            raise RuntimeError("HTB creds: no VPN servers listed at /api/ctfs/vpn-servers")
        resp = await self._request("GET", f"/api/ctfs/vpn/download/{sid}")
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTB creds vpn/download/{sid}: HTTP {resp.status_code}"
            )
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(resp.content)
        logger.info("HTB creds: wrote .ovpn (%d bytes) to %s",
                    len(resp.content), cache)
        return cache

    @property
    def network_mode(self) -> str:
        if self._vpn_container_name:
            return f"container:{self._vpn_container_name}"
        return ""

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        from pathlib import Path

        import yaml
        try:
            from markdownify import markdownify as html2md
        except Exception:
            html2md = None

        stub = challenge if "_htb_ctf" in challenge else self._challenges_by_name.get(
            challenge.get("name", "")
        )
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _htb_ctf metadata for {challenge.get('name')!r}"
            )
        slug = stub["name"]
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # Distfile via /api/challenges/{id}/download (Laravel routes it
        # differently in some events; fall back gracefully on 404).
        if stub["_htb_ctf"].get("has_download"):
            cid = stub["_htb_ctf"]["id"]
            try:
                resp = await self._request("GET", f"/api/challenges/{cid}/download")
                if resp.status_code == 200:
                    fname = stub["_htb_ctf"].get("file_name") or f"{slug}.zip"
                    dest = ch_dir / "distfiles" / fname
                    dest.parent.mkdir(exist_ok=True)
                    dest.write_bytes(resp.content)
                    logger.info("HTB creds: pulled %s (%d bytes)",
                                fname, len(resp.content))
                else:
                    logger.warning(
                        "HTB creds: download for %s: HTTP %d",
                        slug, resp.status_code,
                    )
            except Exception as e:
                logger.warning("HTB creds download(%s): %s", slug, e)

        desc = stub.get("description", "") or ""
        if html2md and desc:
            try:
                desc = html2md(desc, heading_style="atx").strip()
            except Exception:
                pass

        is_dynamic = bool(
            stub["_htb_ctf"].get("has_container")
            or stub["_htb_ctf"].get("has_machine")
        )
        connection_info = (
            "(spawned at solve time — coord will populate live IP+port)"
            if is_dynamic else ""
        )
        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": stub.get("category", "Unknown"),
            "description": desc,
            "value": stub.get("value", 0),
            "connection_info": connection_info,
            "tags": [
                "htb", "ctf-creds", str(self.event_id),
                stub["_htb_ctf"].get("difficulty", "").lower(),
            ],
            "solves": stub.get("solves", 0),
            "htb_ctf_creds": {
                "event_id": self.event_id,
                "challenge_id": stub["_htb_ctf"]["id"],
                "has_container": stub["_htb_ctf"].get("has_container"),
                "has_machine": stub["_htb_ctf"].get("has_machine"),
            },
        }
        (ch_dir / "metadata.yml").write_text(
            yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False)
        )
        return str(ch_dir)

    # ---------- explicit join helper ----------

    async def join_event(self) -> str:
        """POST /api/ctfs/join with team_id. State-changing — the
        operator runs this once per event before catalog/solve calls
        succeed (mirrors the htb-ctf-mcp join_event helper)."""
        if self._team_id is None:
            teams = await self._get_json("/api/teams/my-teams")
            items = teams.get("data", teams) if isinstance(teams, dict) else teams
            if not isinstance(items, list) or not items:
                raise RuntimeError("HTB creds: /api/teams/my-teams returned no teams")
            self._team_id = int(items[0].get("id"))
        resp = await self._request(
            "POST", "/api/ctfs/join",
            json={"ctf_id": self.event_id, "team_id": self._team_id},
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"HTB creds join: HTTP {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json() if resp.text else {}
        msg = body.get("message", "joined") if isinstance(body, dict) else "joined"
        logger.info("HTB creds joined event %d: %s", self.event_id, msg)
        return msg

    # ---------- lifecycle ----------

    async def close(self) -> None:
        for name in list(self._live_containers.keys()):
            try:
                await self.stop_instance(name)
            except Exception as e:
                logger.warning("close: stop_instance(%s): %s", name, e)
        await self._maybe_stop_vpn_sidecar()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
