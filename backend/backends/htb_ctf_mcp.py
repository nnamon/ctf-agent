"""HackTheBox CTF events backend, talking to the official MCP server.

Endpoint: https://mcp.hackthebox.ai/v1/ctf/mcp/
Auth:     personal MCP token (aud:1, scope `mcp:use`) — distinct from
          the labs/machines app token (aud:5).
Identity: HTB auto-provisions an AI-team companion for each user (e.g.
          "[AI] ai-agent-of-amon") with its own user_id (sub field on
          the JWT). Score from this backend lands on the AI team, not
          your human account.

# Why this exists vs ctf-creds-based access

HTB events that opt in to AI participation accept this MCP token
through a sanctioned channel — separate ranking, no ToS issues.
Events that disable AI return permission errors from the MCP server,
which is the right behaviour: if AI's not allowed, you don't compete
with one.

# MCP transport

Streamable HTTP over POST /v1/ctf/mcp/. Each tool call is one HTTP
exchange that returns SSE-framed JSON-RPC. The server is stateful via
mcp-session-id; we capture it from the initialize response and replay
it on every subsequent call. There's no streaming-progress for tool
calls in this API — every response is a single JSON-RPC reply wrapped
in one `event: message\ndata: {...}\n\n` frame, so we don't need a
real SSE parser, just `data:` line extraction.

# Event scoping

Unlike labs (one big catalog), CTF events are time-bounded competitions
with their own challenge sets. The backend is configured with one
`event_id`; all Backend ABC methods scope to that event. Multi-event
sessions need separate ctf-agent sessions (one per event).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.backends.base import Backend, SubmitResult

logger = logging.getLogger(__name__)


HTB_MCP_URL = "https://mcp.hackthebox.ai/v1/ctf/mcp/"
USER_AGENT = "ctf-agent/htb-ctf-mcp (+httpx)"
PROTOCOL_VERSION = "2025-06-18"


def _slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^\w\-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "challenge"


# HTB CTF events return only a numeric `challenge_category_id` — no
# name table is exposed via MCP. This map was derived empirically from
# the MCP TryOut event (id 2578) by cross-referencing category_id with
# challenge filenames. Holds for all current HTB CTF events; new
# categories that HTB adds will fall through to "category_<id>".
_CATEGORY_BY_ID: dict[int, str] = {
    2: "Web",
    3: "Pwn",
    4: "Crypto",
    5: "Reversing",
    7: "Forensics",
    8: "Misc",
    11: "GamePwn",
    14: "Blockchain",
    15: "Hardware",
    16: "Misc",          # often used for sanity-check / welcome challenges
    21: "ICS",
    22: "Coding",
    23: "Secure Coding",
    24: "AI - ML",
    25: "OSINT",
    26: "Mobile",
    27: "Quantum",
}

# Filename-based fallback (e.g. "hardware_its_oops_pm.zip"). Used only
# when challenge_category_id is missing — the id-based mapping above
# is the authoritative signal because some filenames mislead (a Pwn
# challenge named "Router Web" has filename "router_web.zip" but
# category_id 3 = Pwn, not "Router").
_CATEGORY_FROM_FILENAME_RE = re.compile(r"^([a-zA-Z][a-zA-Z\- ]+?)_", re.UNICODE)


def _infer_category(filename: str, cat_id: Any) -> str:
    if isinstance(cat_id, int) and cat_id in _CATEGORY_BY_ID:
        return _CATEGORY_BY_ID[cat_id]
    if filename:
        m = _CATEGORY_FROM_FILENAME_RE.match(filename)
        if m:
            return m.group(1).strip().title()
    if cat_id is not None:
        return f"category_{cat_id}"
    return "Unknown"


class McpError(RuntimeError):
    """Wraps a JSON-RPC error response from the MCP server."""


@dataclass
class HtbCtfMcpBackend(Backend):
    """MCP-driven backend for an HTB CTF event."""

    mcp_token: str = ""
    event_id: int = 0
    base_url: str = HTB_MCP_URL

    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _session_id: str | None = field(default=None, repr=False)
    _next_request_id: int = field(default=1, repr=False)
    _initialized: bool = field(default=False, repr=False)
    _init_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    # Cached results to avoid burning tool-call quota.
    _challenges_by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _team_id: int | None = field(default=None, repr=False)
    # name → connection_info string for currently-running container.
    _live_containers: dict[str, str] = field(default_factory=dict, repr=False)

    # ---------- transport ----------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self.mcp_token:
                raise RuntimeError(
                    "HtbCtfMcpBackend: mcp_token required (HTB account → "
                    "AI Agents → MCP Token, audience aud:1 scope mcp:use)"
                )
            if self.event_id <= 0:
                raise RuntimeError(
                    "HtbCtfMcpBackend: event_id required — set "
                    "htb_mcp_event_id in session settings"
                )
            self._client = httpx.AsyncClient(
                timeout=60.0,
                headers={
                    "Authorization": f"Bearer {self.mcp_token}",
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def _post_jsonrpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON-RPC payload, parse the SSE-framed response.

        Raises on transport / protocol errors. For JSON-RPC error
        replies (server returns `error` field), raises McpError with
        the message.
        """
        client = await self._ensure_client()
        headers: dict[str, str] = {}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        resp = await client.post(self.base_url, json=payload, headers=headers)
        # Capture session id on first response (initialize sets it).
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid and not self._session_id:
            self._session_id = sid

        if resp.status_code == 202:
            # 202 = notification accepted, no body to parse.
            return {}
        if resp.status_code != 200:
            raise McpError(
                f"MCP HTTP {resp.status_code}: {resp.text[:300]}"
            )

        # SSE framing: lines like `event: message\ndata: {...}\n\n`.
        # We accept the simpler shape where there's exactly one data
        # block per response (true for all the non-streaming tool
        # calls in this API).
        data_lines: list[str] = []
        for line in resp.text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data_lines.append(line[len("data:"):].strip())
        if not data_lines:
            # Some servers omit SSE wrapping for short responses.
            try:
                return resp.json()
            except Exception as e:
                raise McpError(f"MCP unparseable response: {resp.text[:300]}") from e
        try:
            body = json.loads("\n".join(data_lines))
        except Exception as e:
            raise McpError(f"MCP non-JSON in SSE data: {data_lines[:1]!r}") from e

        if "error" in body:
            err = body["error"]
            raise McpError(f"MCP {err.get('code')}: {err.get('message', err)}")
        return body

    async def _initialize(self) -> None:
        """One-shot MCP handshake — initialize + notifications/initialized.

        Idempotent under the lock; later callers see _initialized=True
        and short-circuit.
        """
        async with self._init_lock:
            if self._initialized:
                return
            init_payload = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "ctf-agent", "version": "0.1"},
                },
            }
            init_resp = await self._post_jsonrpc(init_payload)
            server = (init_resp.get("result") or {}).get("serverInfo", {})
            logger.info(
                "HTB MCP connected: %s v%s, session=%s",
                server.get("name", "?"), server.get("version", "?"),
                self._session_id or "(none)",
            )
            # Required notification per the MCP spec; server uses it as
            # the "client is ready" signal before accepting tool calls.
            await self._post_jsonrpc({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            })
            self._initialized = True

    def _next_id(self) -> int:
        i = self._next_request_id
        self._next_request_id += 1
        return i

    async def _call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Generic MCP tools/call wrapper. Returns the raw `content`
        list from the JSON-RPC result; callers parse the embedded JSON
        text or pull text out as needed."""
        await self._initialize()
        resp = await self._post_jsonrpc({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })
        result = resp.get("result") or {}
        if result.get("isError"):
            content = result.get("content") or []
            text = "; ".join(c.get("text", "") for c in content if isinstance(c, dict))
            raise McpError(f"MCP tool {name!r} error: {text or result}")
        return result.get("content") or []

    @staticmethod
    def _content_text(content: list[dict[str, Any]]) -> str:
        """Concatenate text fields from an MCP tool's content list."""
        parts: list[str] = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
        return "\n".join(parts)

    @staticmethod
    def _content_json(content: list[dict[str, Any]]) -> Any:
        """Parse the MCP tool's content as JSON. Most HTB tools return
        a single text item with a JSON-encoded payload."""
        text = HtbCtfMcpBackend._content_text(content)
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return text

    def _check_inner_error(self, body: Any, op: str) -> None:
        """HTB MCP wraps upstream HTTP errors as a successful tool call
        whose payload is `{"error": "...", "status_code": N}`. The
        JSON-RPC `isError` flag is NOT set, so _call_tool happily
        returns. Surface those as exceptions so backend callers don't
        silently process empty results."""
        if isinstance(body, dict) and "error" in body and "status_code" in body:
            raise McpError(
                f"HTB MCP {op}: HTTP {body.get('status_code')} — "
                f"{body.get('error', '(no detail)')}"
            )

    # ---------- helpers ----------

    async def join_event(self, ctf_password: str = "") -> str:
        """Register the AI team for the configured CTF event.

        State-changing — call only with operator consent. Required
        before any retrieve_ctf / start_container / submit_flag calls
        succeed: HTB returns 403 on those tools until the team is
        joined. The sister CLI helper `ctf-htb-join` wraps this.

        `ctf_password` is the optional event-level password some
        private events require (most public ones leave it blank).
        """
        team_id = await self._get_team_id()
        args: dict[str, Any] = {
            "ctf_id": self.event_id,
            "team_id": team_id,
            "consent": True,
        }
        if ctf_password:
            args["ctf_password"] = ctf_password
        content = await self._call_tool("join_ctf_event", args)
        body = self._content_json(content)
        self._check_inner_error(body, f"join_ctf_event(ctf_id={self.event_id})")
        msg = ""
        if isinstance(body, dict):
            msg = body.get("message") or json.dumps(body)
        elif isinstance(body, str):
            msg = body
        logger.info("HTB MCP joined event %d: %s", self.event_id, msg)
        return msg or "joined"

    async def _get_team_id(self) -> int:
        if self._team_id is not None:
            return self._team_id
        content = await self._call_tool("retrieve_my_teams")
        teams = self._content_json(content) or []
        if not isinstance(teams, list) or not teams:
            raise RuntimeError(
                "HTB MCP: no teams associated with this account. The "
                "AI-team companion should be auto-provisioned; if it's "
                "missing, sign in to the HTB web UI once to trigger it."
            )
        # If multiple teams, prefer the captain'd one (the AI team is
        # captained by the auto-provisioned ai-agent-of-<user> identity).
        teams.sort(key=lambda t: 0 if t.get("isCaptain") else 1)
        self._team_id = int(teams[0].get("id"))
        logger.info("HTB MCP: using team %r (id=%s)",
                    teams[0].get("name"), self._team_id)
        return self._team_id

    # ---------- listing ----------

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Pull the configured event's challenge list via retrieve_ctf.

        retrieve_ctf returns the full event payload including the list
        of challenges. We map each into a CTFd-shaped stub.
        """
        content = await self._call_tool("retrieve_ctf", {"ctf_id": self.event_id})
        body = self._content_json(content)
        self._check_inner_error(body, f"retrieve_ctf(ctf_id={self.event_id})")
        if not isinstance(body, dict):
            raise RuntimeError(f"HTB MCP retrieve_ctf returned non-dict: {body!r}")
        challenges = body.get("challenges") or []
        out: list[dict[str, Any]] = []
        for c in challenges:
            name = c.get("name") or ""
            slug = _slugify(name)
            filename = c.get("filename") or ""
            stub = {
                "id": c.get("id"),
                "name": slug,
                "title": name,
                "category": _infer_category(filename, c.get("challenge_category_id")),
                "value": int(c.get("points") or c.get("value") or 0),
                "solves": int(c.get("solves") or 0),
                "type": "standard",
                "description": c.get("description") or "",
                "connection_info": "",
                "_htb_mcp": {
                    "id": c.get("id"),
                    "difficulty": c.get("difficulty") or "",
                    # HTB returns hasDocker as int 0/1/null; bool() handles all.
                    "has_container": bool(c.get("hasDocker")),
                    "has_download": bool(filename),
                    "file_name": filename,
                    # Pre-cached solved-state from the catalog payload —
                    # saves a separate retrieve_ctf_solves_for_team call.
                    "solved": bool(c.get("solved")),
                },
            }
            self._challenges_by_name[slug] = stub
            out.append(stub)
        return out

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """retrieve_ctf already returns full challenge data including
        descriptions, so stubs == full for this backend."""
        return await self.fetch_challenge_stubs()

    async def fetch_solved_names(self) -> set[str]:
        """Read the inline `solved` flag baked into each challenge by
        retrieve_ctf — saves a separate retrieve_ctf_solves_for_team
        tool call (and stays under the rate budget when the poller hits
        this every minute). Fresh-fetches stubs every call so a flag
        submitted by another tool elsewhere shows up promptly."""
        await self.fetch_challenge_stubs()
        return {
            name for name, stub in self._challenges_by_name.items()
            if stub["_htb_mcp"].get("solved")
        }

    # ---------- submission ----------

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        if challenge_name not in self._challenges_by_name:
            await self.fetch_challenge_stubs()
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB MCP challenge {challenge_name!r} not found in event {self.event_id}")
        cid = stub["_htb_mcp"]["id"]
        content = await self._call_tool(
            "submit_flag",
            {"challenge_id": cid, "flag": flag.strip()},
        )
        body = self._content_json(content)
        # The MCP wrapper returns a dict like
        #   {"success": true, "message": "Correct flag!", ...}
        # but the exact shape varies — also handle bare-text replies.
        msg = ""
        success = False
        if isinstance(body, dict):
            msg = (body.get("message") or "").strip()
            success = bool(body.get("success"))
            if not msg and "error" in body:
                msg = str(body["error"])
        elif isinstance(body, str):
            msg = body
            success = "correct" in body.lower() and "incorrect" not in body.lower()
        else:
            msg = self._content_text(content) or "(empty)"

        msg_lower = msg.lower()
        if "already" in msg_lower and ("solved" in msg_lower or "submitted" in msg_lower):
            stub["_htb_mcp"]["solved"] = True
            return SubmitResult(
                "already_solved", msg,
                f'ALREADY SOLVED — flag previously accepted ({msg})',
            )
        if success:
            stub["_htb_mcp"]["solved"] = True
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
        """Wrap the MCP `start_container` tool. Non-container challenges
        return None (no-op). Cached: sibling-bug-driven extra calls reuse
        the live IP+port without re-asking HTB."""
        if challenge_name not in self._challenges_by_name:
            await self.fetch_challenge_stubs()
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            raise RuntimeError(f"HTB MCP challenge {challenge_name!r} not found")
        if not stub["_htb_mcp"].get("has_container"):
            return None
        if challenge_name in self._live_containers:
            return self._live_containers[challenge_name]
        cid = stub["_htb_mcp"]["id"]
        content = await self._call_tool(
            "start_container",
            {"challenge_id": cid},
        )
        body = self._content_json(content)
        ip, ports = self._extract_ip_ports(body)
        if not ip or not ports:
            # Some events take a few seconds to provision; poll status.
            for _ in range(15):
                await asyncio.sleep(2.0)
                status = await self._call_tool(
                    "container_status",
                    {"challenge_id": cid},
                )
                ip, ports = self._extract_ip_ports(self._content_json(status))
                if ip and ports:
                    break
        if not ip or not ports:
            raise RuntimeError(
                f"HTB MCP {challenge_name}: container never reported IP+ports"
            )
        category = (stub.get("category") or "").lower()
        if category == "web":
            conn = f"http://{ip}:{ports[0]}"
        elif category in ("pwn", "crypto"):
            conn = f"nc {ip} {ports[0]}"
        else:
            conn = f"{ip}:{ports[0]}"
        self._live_containers[challenge_name] = conn
        logger.info("HTB MCP %s: container at %s", challenge_name, conn)
        return conn

    async def stop_instance(self, challenge_name: str) -> None:
        if challenge_name not in self._live_containers:
            return
        stub = self._challenges_by_name.get(challenge_name)
        if stub is None:
            return
        cid = stub["_htb_mcp"]["id"]
        try:
            await self._call_tool(
                "stop_container",
                {"challenge_id": cid},
            )
            logger.info("HTB MCP %s: container stopped", challenge_name)
        except Exception as e:
            logger.warning("HTB MCP stop_container(%s) failed: %s",
                           challenge_name, e)
        finally:
            self._live_containers.pop(challenge_name, None)

    @staticmethod
    def _extract_ip_ports(body: Any) -> tuple[str, list[int]]:
        """Pull (ip, ports) out of start_container / container_status
        responses. HTB returns `{status, hostname, ports}` — the
        primary field is `hostname` despite the name, it's the IPv4
        the user routes to. Other field names checked for forward
        compatibility."""
        if not isinstance(body, dict):
            return "", []
        ip = (
            body.get("hostname")
            or body.get("ip")
            or body.get("host")
            or body.get("address")
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

    # ---------- pull ----------

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        from pathlib import Path

        import yaml
        try:
            from markdownify import markdownify as html2md
        except Exception:
            html2md = None

        stub = challenge if "_htb_mcp" in challenge else self._challenges_by_name.get(
            challenge.get("name", "")
        )
        if stub is None:
            raise RuntimeError(
                f"pull_challenge: no _htb_mcp metadata for {challenge.get('name')!r}"
            )

        slug = stub["name"]
        ch_dir = Path(output_dir) / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # Distfile via signed URL from get_download_link.
        if stub["_htb_mcp"].get("has_download"):
            cid = stub["_htb_mcp"]["id"]
            try:
                content = await self._call_tool(
                    "get_download_link",
                    {"challenge_id": cid},
                )
                body = self._content_json(content)
                url = ""
                if isinstance(body, dict):
                    url = body.get("url") or body.get("download_url") or ""
                elif isinstance(body, str):
                    url = body
                if url:
                    fname = stub["_htb_mcp"].get("file_name") or f"{slug}.zip"
                    dest = ch_dir / "distfiles" / fname
                    dest.parent.mkdir(exist_ok=True)
                    if not dest.exists():
                        client = await self._ensure_client()
                        # Signed URL — short-lived, don't reuse our auth header.
                        async with httpx.AsyncClient(timeout=300.0) as plain:
                            r = await plain.get(url)
                            r.raise_for_status()
                            dest.write_bytes(r.content)
                            logger.info(
                                "HTB MCP: pulled %s (%d bytes)",
                                fname, len(r.content),
                            )
            except Exception as e:
                logger.warning("HTB MCP get_download_link(%s) failed: %s",
                               slug, e)

        desc = stub.get("description", "") or ""
        if html2md and desc:
            try:
                desc = html2md(desc, heading_style="atx").strip()
            except Exception:
                pass

        is_container = bool(stub["_htb_mcp"].get("has_container"))
        connection_info = (
            "(spawned at solve time — coord will populate live IP+port)"
            if is_container else ""
        )
        meta = {
            "name": stub["name"],
            "title": stub.get("title", stub["name"]),
            "category": stub.get("category", "Unknown"),
            "description": desc,
            "value": stub.get("value", 0),
            "connection_info": connection_info,
            "tags": [
                "htb", "ctf", str(self.event_id),
                stub["_htb_mcp"].get("difficulty", "").lower(),
            ],
            "solves": stub.get("solves", 0),
            "htb_ctf": {
                "event_id": self.event_id,
                "challenge_id": stub["_htb_mcp"]["id"],
                "has_container": is_container,
            },
        }
        (ch_dir / "metadata.yml").write_text(
            yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False)
        )
        return str(ch_dir)

    # ---------- lifecycle ----------

    async def close(self) -> None:
        # Best-effort teardown of any running containers.
        for name in list(self._live_containers.keys()):
            try:
                await self.stop_instance(name)
            except Exception as e:
                logger.warning("close: stop_instance(%s) failed: %s", name, e)
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
