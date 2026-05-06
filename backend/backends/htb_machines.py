"""HackTheBox Machines backend (full pwnable VMs over OpenVPN).

Spawns the per-user machine via labs API, brings up an OpenVPN sidecar
container so solver containers can reach the box at its 10.10.x.x
address, submits user.txt / root.txt flags through /machine/own.

Free-tier limits:
  - 1 active machine spawn at a time
  - 1 active VPN connection at a time (per location pool)
  - Active machines only (no retired)

# Architecture (VPN sidecar)

    ┌──────────────────────────┐         ┌────────────────────────┐
    │  ctf-vpn-<run_id>        │  share  │  ctf-solver-<spec>     │
    │  cmd: openvpn ...        │ ◄─────► │  --network container:  │
    │  cap: NET_ADMIN          │  netns  │     ctf-vpn-<run_id>   │
    │  /dev/net/tun            │         │  (no openvpn here)     │
    │  → tun0 → HTB lab        │         │  routes via tun0       │
    └──────────────────────────┘         └────────────────────────┘

All sibling solvers in a machine swarm share the one VPN tunnel — which
matches the free-tier 1-VPN cap. The sidecar is spawned on
start_instance and torn down on stop_instance. Solver containers attach
via Sandbox.network_mode = "container:<sidecar-name>".

# Two-flag limitation (v1)

HTB machines have *two* flags (user.txt + root.txt). This backend treats
each machine as one challenge. submit_flag accepts either, classifies
which one HTB recognised, and reports back. The solver harness exits on
first-flag-found, so the typical flow is:

  - Solver finds user.txt → swarm wins → record stops there
  - To submit root.txt, re-spawn the swarm (the box is destroyed and
    re-created; you'll have to re-exploit user → root again)

A future commit will add a SubmitResult.status == "partial_correct"
that lets the solver keep going after user.txt is accepted, sustaining
the same shell into root.txt without re-spawning. Tracked as a known
limitation; the v1 backend is still useful for proving the integration
end-to-end and chewing through user.txt-only solves.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from backend.backends.base import Backend, SubmitResult
from backend.sandbox import RUN_ID, CONTAINER_LABEL, RUN_LABEL

logger = logging.getLogger(__name__)


HTB_API_BASE = "https://labs.hackthebox.com/api/v4"
USER_AGENT = "ctf-agent/htb-machines (+httpx)"

# Same 20 req/min budget as labs challenges. The list call is paginated
# (15 per page) so a full enumeration is ~10 calls.
_HTB_REQ_SEMAPHORE = asyncio.Semaphore(4)

# Where the .ovpn config is cached on the host. Bind-mounted into the
# VPN sidecar at /vpn.ovpn. Re-fetched if the file goes stale.
DEFAULT_OVPN_PATH = Path.home() / ".ctf-agent" / "htb-machines.ovpn"


def _slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "machine"


@dataclass
class HtbMachinesBackend(Backend):
    """Bearer-token-auth backend for HTB Machines + VPN sidecar lifecycle."""

    app_token: str = ""
    # Lab server to bind the VPN to. 0 = use HTB's auto-assigned server
    # (read from /connections/servers `assigned`). Override per-session
    # (e.g. 254 for "US Machines 3") if latency matters.
    server_id: int = 0
    # Sidecar image. Defaults to the dedicated ctf-vpn image (alpine +
    # openvpn, ~12 MB) built alongside ctf-sandbox in CI. Kept separate
    # from ctf-sandbox so non-machine solver containers don't carry an
    # openvpn install they'll never use.
    sidecar_image: str = "ctf-vpn"
    base_url: str = HTB_API_BASE
    ovpn_path: Path = field(default=DEFAULT_OVPN_PATH)

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    # name → machine info dict (id, ip, os, difficulty, free, ...)
    _machines_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    # Currently-active machine slug + spawned IP. Free tier = at most one.
    _active_machine: str | None = field(default=None, repr=False)
    _active_ip: str | None = field(default=None, repr=False)
    # VPN sidecar container handle (aiodocker container object).
    _vpn_container: Any = field(default=None, repr=False)
    _vpn_container_name: str = field(default="", repr=False)

    # ---------- HTTP plumbing ----------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self.app_token:
                raise RuntimeError("HtbMachinesBackend: app_token required")
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=60.0,  # vm/spawn can take 30+s
                headers={
                    "Authorization": f"Bearer {self.app_token}",
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        client = await self._ensure_client()
        async with _HTB_REQ_SEMAPHORE:
            backoff = 2.0
            for attempt in range(3):
                resp = await client.request(method, path, **kwargs)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", backoff))
                    logger.warning("HTB rate-limited %s %s — sleep %.1fs",
                                   method, path, retry_after)
                    await asyncio.sleep(retry_after)
                    backoff *= 2
                    continue
                if 500 <= resp.status_code < 600 and attempt < 2:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            return resp

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Walk /machine/paginated, return one stub per active machine.

        Free tier sees ~15 active machines. The `free:true` flag marks
        which ones the user can spawn without VIP. Retired machines need
        VIP+ and we skip them.
        """
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = await self._request(
                "GET", "/machine/paginated",
                params={"per_page": 100, "page": page},
            )
            if resp.status_code != 200:
                logger.warning("HTB /machine/paginated p=%d: HTTP %d",
                               page, resp.status_code)
                break
            body = resp.json()
            data = body.get("data", [])
            if not data:
                break
            for m in data:
                name = m.get("name") or ""
                slug = _slugify(name)
                stub = {
                    "id": m.get("id"),
                    "name": slug,
                    "title": name,
                    "category": "Machine",
                    "value": int(m.get("static_points") or m.get("points") or 0),
                    "solves": (m.get("user_owns_count") or 0) + (m.get("root_owns_count") or 0),
                    "type": "standard",
                    "description": "",  # filled by fetch_all_challenges
                    "connection_info": "",
                    "_htb_m": {
                        "id": m.get("id"),
                        "os": m.get("os") or "",
                        "difficulty": m.get("difficultyText") or "",
                        "free": bool(m.get("free")),
                        "retired": bool(m.get("retired")),
                        "user_owned": bool(m.get("authUserInUserOwns")),
                        "root_owned": bool(m.get("authUserInRootOwns")),
                    },
                }
                self._machines_by_name[slug] = stub
                out.append(stub)
            meta = body.get("meta") or {}
            if page >= meta.get("last_page", page):
                break
            page += 1
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """Stubs + per-machine /profile (description, maker, release date)."""
        stubs = await self.fetch_challenge_stubs()
        out: list[dict[str, Any]] = []
        for stub in stubs:
            mid = stub["_htb_m"]["id"]
            info = await self._fetch_profile(mid)
            stub["description"] = self._render_profile_description(info)
            stub["_htb_m"]["release"] = info.get("release") or ""
            stub["_htb_m"]["maker"] = (info.get("maker") or {}).get("name", "")
            out.append(stub)
        return out

    async def _fetch_profile(self, mid: int) -> dict[str, Any]:
        resp = await self._request("GET", f"/machine/profile/{mid}")
        if resp.status_code != 200:
            logger.warning("HTB /machine/profile/%d: HTTP %d", mid, resp.status_code)
            return {}
        return resp.json().get("info", {})

    def _render_profile_description(self, info: dict[str, Any]) -> str:
        os_ = info.get("os", "")
        diff = info.get("difficultyText") or ""
        maker = (info.get("maker") or {}).get("name", "")
        return (
            f"HackTheBox machine ({os_}, {diff}, by {maker}).\n\n"
            f"Two flags to capture: `user.txt` (in the user home) and "
            f"`root.txt` (in /root or C:\\Users\\Administrator\\Desktop).\n\n"
            f"Submit either flag via the standard `submit_flag` tool — "
            f"the backend will tell you which one HTB recognised. v1 of "
            f"this integration ends the swarm on first-flag-accepted; "
            f"if you want both, submit `user.txt` first, then re-spawn "
            f"to chase `root.txt`."
        )

    async def fetch_solved_names(self) -> set[str]:
        """A machine is 'solved' for poller purposes when BOTH flags are
        owned. Half-owned (user but not root) still shows in the active
        list so the swarm can come back for root."""
        if not self._machines_by_name:
            await self.fetch_challenge_stubs()
        return {
            name for name, stub in self._machines_by_name.items()
            if stub["_htb_m"].get("user_owned") and stub["_htb_m"].get("root_owned")
        }

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """POST /machine/own with {id, flag, difficulty}.

        HTB classifies the flag as user.txt or root.txt by content
        (each box has unique 32-char hex flags baked in). Response
        message indicates which side was accepted.
        """
        if challenge_name not in self._machines_by_name:
            await self.fetch_challenge_stubs()
        stub = self._machines_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB machine {challenge_name!r} not found")
        mid = stub["_htb_m"]["id"]

        resp = await self._request(
            "POST", "/machine/own",
            json={"id": mid, "flag": flag.strip(), "difficulty": 50},
        )
        if resp.status_code != 200:
            return SubmitResult(
                "unknown",
                f"HTTP {resp.status_code}",
                f"submit_flag transport error: HTTP {resp.status_code} {resp.text[:200]}",
            )
        body = resp.json()
        msg = (body.get("message") or "").strip()
        success = bool(body.get("success"))
        msg_lower = msg.lower()
        if "already" in msg_lower and ("owned" in msg_lower or "submitted" in msg_lower):
            return SubmitResult(
                "already_solved", msg,
                f'ALREADY OWNED — flag previously accepted by HTB ({msg})',
            )
        if success:
            which = "user.txt" if "user" in msg_lower else "root.txt" if "root" in msg_lower else "flag"
            return SubmitResult(
                "correct", msg,
                f'CORRECT — {which} accepted on HTB ({msg})',
            )
        return SubmitResult(
            "incorrect", msg or "rejected",
            f'INCORRECT — flag rejected by HTB ({msg})',
        )

    # ---------- VPN sidecar lifecycle ----------

    async def _fetch_ovpn(self) -> Path:
        """GET /access/ovpnfile/{server_id}/0 → cached .ovpn file.

        server_id 0 → resolve via /connections/servers `assigned` field.
        """
        if self.ovpn_path.exists() and self.ovpn_path.stat().st_size > 100:
            return self.ovpn_path

        sid = self.server_id
        if sid == 0:
            resp = await self._request(
                "GET", "/connections/servers", params={"product": "labs"},
            )
            if resp.status_code == 200:
                assigned = (resp.json().get("data") or {}).get("assigned") or {}
                sid = int(assigned.get("id") or 0)
            if sid == 0:
                raise RuntimeError(
                    "Could not resolve assigned VPN server — set "
                    "htb_machines_server_id in session settings"
                )
            logger.info("HTB: using auto-assigned VPN server id=%d", sid)

        resp = await self._request("GET", f"/access/ovpnfile/{sid}/0")
        if resp.status_code != 200:
            raise RuntimeError(
                f"GET /access/ovpnfile/{sid}/0: HTTP {resp.status_code}"
            )
        self.ovpn_path.parent.mkdir(parents=True, exist_ok=True)
        self.ovpn_path.write_bytes(resp.content)
        logger.info("HTB: wrote .ovpn config (%d bytes) to %s",
                    len(resp.content), self.ovpn_path)
        return self.ovpn_path

    async def _start_vpn_sidecar(self) -> None:
        """Spawn an openvpn sidecar that solver containers can attach to.

        Idempotent: returns immediately if already running.
        """
        if self._vpn_container is not None:
            return

        import aiodocker  # type: ignore

        ovpn = await self._fetch_ovpn()
        docker = aiodocker.Docker()
        # Distinct name per run, so concurrent ctf-agent invocations
        # don't collide. Solvers reference this in network_mode.
        self._vpn_container_name = f"ctf-vpn-{RUN_ID[:12]}"
        try:
            config = {
                "Image": self.sidecar_image,
                "Cmd": [
                    "openvpn",
                    "--config", "/vpn.ovpn",
                    "--connect-retry-max", "3",
                    "--script-security", "2",
                ],
                "Tty": False,
                "Labels": {
                    CONTAINER_LABEL: "true",
                    RUN_LABEL: RUN_ID,
                    "ctf-agent.role": "vpn-sidecar",
                },
                "HostConfig": {
                    "Binds": [f"{str(ovpn)}:/vpn.ovpn:ro"],
                    "CapAdd": ["NET_ADMIN"],
                    "Devices": [{
                        "PathOnHost": "/dev/net/tun",
                        "PathInContainer": "/dev/net/tun",
                        "CgroupPermissions": "rwm",
                    }],
                    # Loosen DNS so the openvpn handshake reaches HTB —
                    # default container DNS sometimes blocks the AAAA
                    # lookup HTB's endpoint requires.
                    "Dns": ["1.1.1.1", "8.8.8.8"],
                },
            }
            self._vpn_container = await docker.containers.create_or_replace(
                name=self._vpn_container_name, config=config,
            )
            await self._vpn_container.start()
            # Wait for tun0 to come up — openvpn typically needs ~5-10s
            # to negotiate. Probe by execing `ip addr show tun0` until
            # it succeeds or we time out.
            for attempt in range(20):  # 20 * 1.5s = 30s budget
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
                    logger.info("HTB VPN sidecar %s: tun0 up",
                                self._vpn_container_name)
                    return
            raise RuntimeError(
                f"VPN sidecar {self._vpn_container_name} never brought tun0 up "
                f"within 30s — check `docker logs {self._vpn_container_name}`"
            )
        finally:
            await docker.close()

    async def _stop_vpn_sidecar(self) -> None:
        if self._vpn_container is None:
            return
        try:
            await self._vpn_container.stop(timeout=5)
        except Exception as e:
            logger.warning("VPN sidecar stop failed: %s", e)
        try:
            await self._vpn_container.delete(force=True)
        except Exception as e:
            logger.warning("VPN sidecar delete failed: %s", e)
        self._vpn_container = None
        self._vpn_container_name = ""

    @property
    def network_mode(self) -> str:
        """The string solver containers should use as Sandbox.network_mode
        once start_instance has succeeded. Empty until VPN is up."""
        if self._vpn_container_name:
            return f"container:{self._vpn_container_name}"
        return ""

    # ---------- machine spawn lifecycle ----------

    async def start_instance(self, challenge_name: str) -> str | None:
        """Spawn the machine + bring up VPN. Returns connection_info."""
        if challenge_name not in self._machines_by_name:
            await self.fetch_challenge_stubs()
        stub = self._machines_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB machine {challenge_name!r} not found")
        mid = stub["_htb_m"]["id"]
        if not stub["_htb_m"].get("free"):
            raise RuntimeError(
                f"Machine {challenge_name!r} is not in the free pool — "
                f"VIP+ subscription required"
            )

        # 1. VPN first — solver needs the route before the box is reachable.
        await self._start_vpn_sidecar()

        # 2. Spawn the machine. POST /vm/spawn with {machine_id}.
        resp = await self._request(
            "POST", "/vm/spawn", json={"machine_id": mid},
        )
        if resp.status_code != 200:
            await self._stop_vpn_sidecar()  # don't strand the VPN
            raise RuntimeError(
                f"vm/spawn({challenge_name}): HTTP {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        logger.info("HTB %s: %s", challenge_name, body.get("message", "spawn requested"))

        # 3. Poll /machine/profile until ip + isActive populated. Box
        # provisioning can take 30-90s especially for Windows machines.
        deadline = asyncio.get_event_loop().time() + 180.0
        ip: str | None = None
        while asyncio.get_event_loop().time() < deadline:
            info = await self._fetch_profile(mid)
            play = info.get("playInfo") or {}
            if info.get("ip") and play.get("isActive"):
                ip = info["ip"]
                expires = play.get("expires_at") or "(unknown)"
                life = play.get("life_remaining")
                logger.info(
                    "HTB %s: machine ready at %s (expires %s, life=%s)",
                    challenge_name, ip, expires, life,
                )
                break
            await asyncio.sleep(5.0)
        if not ip:
            await self.stop_instance(challenge_name)
            raise RuntimeError(
                f"HTB {challenge_name!r}: machine never became reachable in 180s"
            )

        self._active_machine = challenge_name
        self._active_ip = ip
        os_ = stub["_htb_m"].get("os", "?")
        return f"{ip}  (HTB machine, {os_} — scan with `nmap -sCV {ip}`)"

    async def stop_instance(self, challenge_name: str) -> None:
        """Terminate machine via POST /vm/terminate + tear down VPN."""
        stub = self._machines_by_name.get(challenge_name)
        if stub:
            mid = stub["_htb_m"]["id"]
            try:
                resp = await self._request(
                    "POST", "/vm/terminate", json={"machine_id": mid},
                )
                if resp.status_code == 200:
                    logger.info("HTB %s: %s", challenge_name,
                                resp.json().get("message", "terminated"))
                else:
                    logger.warning(
                        "HTB stop_instance(%s): HTTP %d %s",
                        challenge_name, resp.status_code, resp.text[:200],
                    )
            except Exception as e:
                logger.warning("HTB vm/terminate failed: %s", e)

        await self._stop_vpn_sidecar()
        if self._active_machine == challenge_name:
            self._active_machine = None
            self._active_ip = None

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Materialise machine metadata to disk. No distfile — the box
        IS the target; everything is recon-driven over VPN."""
        from pathlib import Path

        import yaml

        stub = challenge if "_htb_m" in challenge else self._machines_by_name.get(
            challenge.get("name", "")
        )
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _htb_m metadata for {challenge.get('name')!r}"
            )
        if not stub.get("description"):
            info = await self._fetch_profile(stub["_htb_m"]["id"])
            stub["description"] = self._render_profile_description(info)

        slug = _slugify(challenge.get("name") or stub.get("name", "machine"))
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": "Machine",
            "description": stub.get("description", ""),
            "value": stub.get("value", 0),
            "connection_info": "(spawned at solve time — backend will populate live IP)",
            "tags": [
                "htb", "machine",
                stub["_htb_m"].get("os", "").lower(),
                stub["_htb_m"].get("difficulty", "").lower(),
            ],
            "solves": stub.get("solves", 0),
            "htb_machine": {
                "id": stub["_htb_m"]["id"],
                "os": stub["_htb_m"].get("os", ""),
                "difficulty": stub["_htb_m"].get("difficulty", ""),
                "free": stub["_htb_m"].get("free", False),
            },
        }
        (ch_dir / "metadata.yml").write_text(
            yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False)
        )
        return str(ch_dir)

    # ---------- lifecycle ----------

    async def close(self) -> None:
        # If a swarm crashed before stop_instance ran, make sure we don't
        # leak a VPN sidecar or a half-spawned machine.
        if self._active_machine:
            try:
                await self.stop_instance(self._active_machine)
            except Exception as e:
                logger.warning("close(): cleanup of %s failed: %s",
                               self._active_machine, e)
        await self._stop_vpn_sidecar()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
