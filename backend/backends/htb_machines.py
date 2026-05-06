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

# Two-flag handling

HTB machines have *two* flags (user.txt + root.txt). This backend
splits each machine into two challenges named `<slug>-user` and
`<slug>-root`, both linked to the same machine_id internally. The
existing single-flag-per-challenge harness handles them naturally.

Spawn lifecycle is ref-counted by machine: the first sibling to call
start_instance triggers the actual /vm/spawn, both share the resulting
IP, and the box only terminates when the LAST sibling calls
stop_instance. Solving user.txt → escalating to root.txt → submitting
both works in a single sustained session because the foothold persists
across solver runs of the two halves.

Prerequisite chain: `<slug>-root` lists `<slug>-user` in its
metadata.yml `prerequisites`. The coord refuses to spawn root until
user is owned (do_spawn_swarm guard).

Opportunistic short-circuit: if a solver on `<slug>-user` captures
root.txt while exploring (common when priv-esc is found early), the
expected flow is:

  1. Submit user.txt via normal `submit_flag` tool — the swarm wins.
  2. notify_coordinator with: "Also captured root.txt for <slug>: <flag>".
  3. Coord LLM parses the message, dispatches submit_flag for the
     <slug>-root challenge directly (no second swarm spawn needed).
  4. Both halves marked solved, machine terminates after both swarms end.
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
    # challenge-slug ("acute-user", "acute-root") → stub dict.
    _machines_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    # Ref counts of active spawns by machine_slug ("acute"). Each
    # challenge-slug that called start_instance adds itself to the set;
    # stop_instance removes itself. The actual /vm/spawn happens on
    # transition to first ref, /vm/terminate on transition to zero refs.
    # Free-tier HTB caps total active machines at 1, so this dict has
    # at most one non-empty entry at a time, but the structure is
    # cap-agnostic.
    _spawn_refs: dict[str, set[str]] = field(default_factory=dict, repr=False)
    # machine_slug → connection_info string from the live spawn (cached
    # so sibling start_instance calls don't re-hit /machine/profile).
    _spawn_conn: dict[str, str] = field(default_factory=dict, repr=False)
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
        """Walk /machine/paginated, return TWO stubs per active machine
        — one for user.txt, one for root.txt — both linked to the same
        machine_id. Each is a normal one-flag-per-challenge stub; the
        existing harness handles them natively, and the spawn ref-count
        in start_instance/stop_instance keeps both halves on one box.
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
                base_slug = _slugify(name)
                # Half-points each. HTB awards static_points / 2 for
                # user.txt, the rest for root.txt. We surface that so
                # the coord can prioritise high-value boxes.
                pts = int(m.get("static_points") or m.get("points") or 0)
                half_pts = pts // 2 if pts > 1 else pts
                machine_meta = {
                    "machine_id": m.get("id"),
                    "machine_slug": base_slug,
                    "os": m.get("os") or "",
                    "difficulty": m.get("difficultyText") or "",
                    "free": bool(m.get("free")),
                    "retired": bool(m.get("retired")),
                    "user_owned": bool(m.get("authUserInUserOwns")),
                    "root_owned": bool(m.get("authUserInRootOwns")),
                }
                for half in ("user", "root"):
                    slug = f"{base_slug}-{half}"
                    stub = {
                        "id": m.get("id"),  # machine_id; same for both halves
                        "name": slug,
                        "title": f"{name} ({half}.txt)",
                        "category": "Machine",
                        "value": half_pts,
                        "solves": int(m.get(f"{half}_owns_count") or 0),
                        "type": "standard",
                        "description": "",
                        "connection_info": "",
                        "_htb_m": {**machine_meta, "half": half},
                    }
                    self._machines_by_name[slug] = stub
                    out.append(stub)
            meta = body.get("meta") or {}
            if page >= meta.get("last_page", page):
                break
            page += 1
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """Stubs + per-machine /profile (description, maker, release).

        Profiles are fetched once per machine_id (not per half) — both
        sibling stubs share the same description otherwise we'd double
        the rate-limit cost.
        """
        stubs = await self.fetch_challenge_stubs()
        profiles_by_id: dict[int, dict[str, Any]] = {}
        out: list[dict[str, Any]] = []
        for stub in stubs:
            mid = stub["_htb_m"]["machine_id"]
            if mid not in profiles_by_id:
                profiles_by_id[mid] = await self._fetch_profile(mid)
            info = profiles_by_id[mid]
            stub["description"] = self._render_profile_description(info, stub["_htb_m"]["half"])
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

    def _render_profile_description(self, info: dict[str, Any], half: str) -> str:
        """Per-half brief. The user half explains the foothold flow;
        the root half adds the prerequisite warning + sibling-flag
        opportunistic-submit hint."""
        os_ = info.get("os", "")
        diff = info.get("difficultyText") or ""
        maker = (info.get("maker") or {}).get("name", "")
        name = info.get("name", "this machine")
        common = (
            f"HackTheBox machine **{name}** ({os_}, {diff}, by {maker}).\n\n"
            f"Reachable only over OpenVPN at the IP the coordinator passes "
            f"in `connection_info`. Standard recon flow: nmap → enumerate "
            f"services → identify exploitable vector → land a shell.\n\n"
        )
        if half == "user":
            return common + (
                f"**Goal: capture `user.txt`** (typically `/home/<user>/user.txt` "
                f"on Linux or `C:\\Users\\<user>\\Desktop\\user.txt` on Windows). "
                f"Submit it via the standard `submit_flag` tool.\n\n"
                f"**Bonus: opportunistic `root.txt`.** Many boxes admit a "
                f"priv-esc path that lands a root shell quickly once you have "
                f"the user foothold — if you happen to capture `root.txt` "
                f"as well during exploration, submit `user.txt` first, then "
                f"send a `notify_coordinator` message:\n\n"
                f"> Also captured root.txt for `{_slugify(name)}`: <flag-value>\n\n"
                f"The coordinator will dispatch the root submission directly "
                f"without spinning up a second swarm."
            )
        else:  # root
            return common + (
                f"**Goal: capture `root.txt`** (typically `/root/root.txt` on "
                f"Linux or `C:\\Users\\Administrator\\Desktop\\root.txt` on "
                f"Windows). Submit it via the standard `submit_flag` tool.\n\n"
                f"**Prerequisite: `{_slugify(name)}-user` must be solved first.** "
                f"The coord refuses to spawn this swarm until user.txt is owned. "
                f"By the time you're running, you have a confirmed user-shell "
                f"path documented in the prior swarm's writeup — re-establish "
                f"foothold, then escalate."
            )

    async def fetch_solved_names(self) -> set[str]:
        """Each half is solved independently — `<slug>-user` when
        authUserInUserOwns, `<slug>-root` when authUserInRootOwns.
        The poller surfaces them as separate solved entries."""
        if not self._machines_by_name:
            await self.fetch_challenge_stubs()
        solved: set[str] = set()
        for slug, stub in self._machines_by_name.items():
            half = stub["_htb_m"].get("half")
            if half == "user" and stub["_htb_m"].get("user_owned"):
                solved.add(slug)
            elif half == "root" and stub["_htb_m"].get("root_owned"):
                solved.add(slug)
        return solved

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        """POST /machine/own with {id, flag, difficulty}.

        challenge_name is the half-suffixed slug (`<slug>-user` or
        `<slug>-root`). HTB itself classifies the flag's content (each
        box has a unique 32-char hex flag baked in for each side); we
        cross-check that the side HTB accepted matches the side the
        challenge name asked for.

        If a solver running on `-user` accidentally submits the root
        flag (or vice versa), the response is `incorrect` from the
        backend's perspective even though HTB technically marked the
        sibling as owned. The status flips to `already_solved` only on
        a re-submit because HTB's `authUserInRootOwns` flips on the
        first accepted submission. The coord layer should pull a fresh
        fetch_solved_names afterwards to pick up the side-effect.
        """
        if challenge_name not in self._machines_by_name:
            await self.fetch_challenge_stubs()
        stub = self._machines_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB machine {challenge_name!r} not found")
        mid = stub["_htb_m"]["machine_id"]
        expected_half = stub["_htb_m"]["half"]

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
            # HTB's response says which half it credited. If it doesn't
            # match what the challenge expected, the flag landed on the
            # sibling — surface that explicitly so the coord knows to
            # re-poll solved-names rather than mark THIS challenge done.
            accepted = (
                "user" if "user" in msg_lower
                else "root" if "root" in msg_lower
                else expected_half  # fall through if HTB ever changes wording
            )
            if accepted != expected_half:
                sibling = f"{stub['_htb_m']['machine_slug']}-{accepted}"
                return SubmitResult(
                    "incorrect", msg,
                    f'WRONG-HALF — submission accepted as `{accepted}.txt`, '
                    f'which credits the `{sibling}` challenge instead of '
                    f'`{challenge_name}`. The sibling is now solved on HTB; '
                    f'no further action needed for it. This challenge still '
                    f'wants its own `{expected_half}.txt`.',
                )
            return SubmitResult(
                "correct", msg,
                f'CORRECT — {accepted}.txt accepted on HTB ({msg})',
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
        """Spawn the machine + bring up VPN. Returns connection_info.

        Ref-counted by machine_slug: the first sibling (user OR root)
        triggers /vm/spawn and the VPN sidecar; subsequent siblings
        share the existing IP. The VPN sidecar persists across both
        halves' swarms so the foothold survives user → root.
        """
        if challenge_name not in self._machines_by_name:
            await self.fetch_challenge_stubs()
        stub = self._machines_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB machine {challenge_name!r} not found")
        if not stub["_htb_m"].get("free"):
            raise RuntimeError(
                f"Machine {challenge_name!r} is not in the free pool — "
                f"VIP+ subscription required"
            )
        machine_slug = stub["_htb_m"]["machine_slug"]
        mid = stub["_htb_m"]["machine_id"]

        # Sibling already running? Share the spawn — just register the ref.
        if machine_slug in self._spawn_refs and self._spawn_refs[machine_slug]:
            self._spawn_refs[machine_slug].add(challenge_name)
            cached = self._spawn_conn.get(machine_slug)
            if cached:
                logger.info(
                    "HTB %s: reusing sibling spawn (refs=%s)",
                    challenge_name, sorted(self._spawn_refs[machine_slug]),
                )
                return cached
            # No cache yet — fall through to a /profile poll to populate.

        # First ref — actually spawn.
        self._spawn_refs.setdefault(machine_slug, set()).add(challenge_name)

        # 1. VPN first — solver needs the route before the box is reachable.
        try:
            await self._start_vpn_sidecar()
        except Exception:
            self._spawn_refs[machine_slug].discard(challenge_name)
            raise

        # 2. Spawn the machine.
        resp = await self._request(
            "POST", "/vm/spawn", json={"machine_id": mid},
        )
        if resp.status_code != 200:
            self._spawn_refs[machine_slug].discard(challenge_name)
            await self._stop_vpn_sidecar()
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
            self._spawn_refs[machine_slug].discard(challenge_name)
            await self.stop_instance(challenge_name)
            raise RuntimeError(
                f"HTB {challenge_name!r}: machine never became reachable in 180s"
            )

        os_ = stub["_htb_m"].get("os", "?")
        conn = f"{ip}  (HTB machine, {os_} — scan with `nmap -sCV {ip}`)"
        self._spawn_conn[machine_slug] = conn
        return conn

    async def stop_instance(self, challenge_name: str) -> None:
        """Decrement ref-count for this challenge. Last sibling out
        terminates the machine via /vm/terminate AND tears down the
        VPN sidecar; earlier siblings just release their ref so the
        partner half still sees the box up."""
        stub = self._machines_by_name.get(challenge_name)
        if stub is None:
            return
        machine_slug = stub["_htb_m"]["machine_slug"]
        refs = self._spawn_refs.get(machine_slug, set())
        if challenge_name not in refs:
            return  # never started this one — nothing to do
        refs.discard(challenge_name)
        if refs:
            logger.info(
                "HTB %s: released ref, %d sibling(s) still running on %s",
                challenge_name, len(refs), machine_slug,
            )
            return

        # Last sibling out — actually terminate.
        self._spawn_refs.pop(machine_slug, None)
        self._spawn_conn.pop(machine_slug, None)
        mid = stub["_htb_m"]["machine_id"]
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

        # No machines left → drop VPN.
        if not self._spawn_refs:
            await self._stop_vpn_sidecar()

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
            info = await self._fetch_profile(stub["_htb_m"]["machine_id"])
            stub["description"] = self._render_profile_description(
                info, stub["_htb_m"]["half"]
            )

        # The slug here is already half-suffixed (e.g. "acute-user").
        slug = stub["name"]
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # Root half lists user half as a prerequisite; coord refuses to
        # spawn `<slug>-root` until `<slug>-user` is solved.
        prerequisites: list[str] = []
        if stub["_htb_m"]["half"] == "root":
            prerequisites = [f"{stub['_htb_m']['machine_slug']}-user"]

        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": "Machine",
            "description": stub.get("description", ""),
            "value": stub.get("value", 0),
            "connection_info": "(spawned at solve time — coord will populate live IP)",
            "tags": [
                "htb", "machine", stub["_htb_m"]["half"],
                stub["_htb_m"].get("os", "").lower(),
                stub["_htb_m"].get("difficulty", "").lower(),
            ],
            "solves": stub.get("solves", 0),
            "prerequisites": prerequisites,
            "htb_machine": {
                "id": stub["_htb_m"]["machine_id"],
                "machine_slug": stub["_htb_m"]["machine_slug"],
                "half": stub["_htb_m"]["half"],
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
        # leak a VPN sidecar or a half-spawned machine. Iterate over a
        # snapshot of refs so the dict can mutate as siblings drain.
        for slug, refs in list(self._spawn_refs.items()):
            for chal in list(refs):
                try:
                    await self.stop_instance(chal)
                except Exception as e:
                    logger.warning("close(): cleanup of %s failed: %s", chal, e)
        await self._stop_vpn_sidecar()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
