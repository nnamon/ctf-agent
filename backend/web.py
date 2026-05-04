"""Live web dashboard for a running coordinator.

Mounts on the same port that already hosts the operator-message inbox
(replaces the hand-rolled HTTP server in coordinator_loop.py with
aiohttp.web). Serves:

  GET  /                        index.html (SSE-driven dashboard)
  GET  /api/status              full JSON snapshot
  GET  /api/events              Server-Sent Events stream
  GET  /api/logs/<chal>/<model>?tail=N
                                tail of the per-solver tracer JSONL
  POST /api/msg                 send a message to the coordinator inbox
  POST /api/swarms/<chal>/kill  cancel a swarm
  POST /api/spawn               spawn a swarm for a known challenge
                                (body: {"challenge_name": "..."})

Default-binds to 127.0.0.1 — single-user / localhost-only. No auth.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

# Embedded so deployment is one Python file. Plain HTML + small JS for
# SSE + buttons. No build step, no node, no npm.
INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>ctf-agent dashboard</title>
<style>
:root {
  --bg: #0e1116; --fg: #e6edf3; --muted: #7d8590; --line: #30363d;
  --green: #3fb950; --yellow: #d29922; --red: #f85149; --cyan: #79c0ff;
  --magenta: #d2a8ff;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); margin: 0;
  font: 13px/1.4 ui-monospace, 'SF Mono', Menlo, Consolas, monospace; }
header { padding: 12px 16px; border-bottom: 1px solid var(--line);
  display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
h1 { font-size: 14px; margin: 0; font-weight: 600; }
.muted { color: var(--muted); }
.pill { padding: 1px 8px; border: 1px solid var(--line); border-radius: 999px;
  font-size: 12px; }
.pill.run { color: var(--green); border-color: var(--green); }
.pill.done { color: var(--cyan); border-color: var(--cyan); }
.pill.killed { color: var(--red); border-color: var(--red); }
.layout { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 12px; }
.card { border: 1px solid var(--line); border-radius: 6px; padding: 10px;
  background: #161b22; }
.card h2 { font-size: 13px; margin: 0 0 8px; color: var(--magenta); font-weight: 600; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 500; }
button { background: #21262d; color: var(--fg); border: 1px solid var(--line);
  padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }
button:hover { background: #30363d; }
button.danger { color: var(--red); border-color: var(--red); }
input[type=text] { background: #0d1117; color: var(--fg); border: 1px solid var(--line);
  padding: 4px 8px; border-radius: 4px; font: inherit; flex: 1; }
form { display: flex; gap: 6px; align-items: center; }
.events { max-height: 300px; overflow-y: auto; font-size: 11px; }
.events div { padding: 2px 0; border-bottom: 1px solid var(--line); }
.tag { color: var(--cyan); }
.tag.err { color: var(--red); }
.tag.ok { color: var(--green); }
pre.log { font-size: 11px; max-height: 200px; overflow: auto;
  background: #010409; padding: 6px; border-radius: 4px; margin: 4px 0 0; }
</style></head><body>
<header>
  <h1>ctf-agent</h1>
  <span class="muted">session</span> <span id="hdr-session">—</span>
  <span class="muted">run</span> <span id="hdr-run" class="muted">—</span>
  <span class="muted">cost</span> <span id="hdr-cost">$0.00</span>
  <span class="muted" id="hdr-quota"></span>
  <span style="margin-left:auto" class="muted" id="hdr-time">—</span>
</header>
<div class="layout">
  <div class="card">
    <h2>Active swarms</h2>
    <table id="tbl-swarms">
      <thead><tr><th>Challenge</th><th>Cat</th><th>Status</th>
        <th>Solvers</th><th>Cost</th><th></th></tr></thead>
      <tbody></tbody>
    </table>
    <h2 style="margin-top:14px">Spawn / steer</h2>
    <form onsubmit="return doSpawn(event)">
      <input type="text" id="spawn-name" placeholder="challenge name to spawn">
      <button>Spawn</button>
    </form>
    <form onsubmit="return doMsg(event)" style="margin-top:6px">
      <input type="text" id="msg-text" placeholder="message to coordinator">
      <button>Send</button>
    </form>
  </div>

  <div class="card">
    <h2>Events</h2>
    <div class="events" id="events"></div>
  </div>

  <div class="card" style="grid-column: span 2">
    <h2>Solver logs <span class="muted" id="log-which"></span></h2>
    <div style="display:flex;gap:6px;margin-bottom:6px">
      <select id="log-pick" style="background:#0d1117;color:var(--fg);
        border:1px solid var(--line);padding:4px"></select>
      <button onclick="refreshLog()">Refresh</button>
    </div>
    <pre class="log" id="log-pre">(pick a solver)</pre>
  </div>
</div>

<script>
const ev = document.getElementById('events');
const tbl = document.querySelector('#tbl-swarms tbody');
const logPick = document.getElementById('log-pick');
const logPre = document.getElementById('log-pre');

function pill(status) {
  const cls = status === 'running' ? 'run' : (status === 'killed' ? 'killed' : 'done');
  return `<span class="pill ${cls}">${status}</span>`;
}

function fmtUsd(n) { return '$' + (n||0).toFixed(2); }

function renderStatus(s) {
  document.getElementById('hdr-session').textContent = s.session.name;
  document.getElementById('hdr-run').textContent = s.run_id;
  document.getElementById('hdr-cost').textContent = fmtUsd(s.cost.total_usd);
  if (s.session.quota_usd) {
    const pct = (s.cost.total_usd / s.session.quota_usd * 100).toFixed(0);
    document.getElementById('hdr-quota').textContent =
      `quota ${fmtUsd(s.session.quota_usd)} (${pct}% used)`;
  }
  document.getElementById('hdr-time').textContent =
    new Date(s.ts * 1000).toLocaleTimeString();

  // Swarms table
  tbl.innerHTML = '';
  for (const sw of s.swarms) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${sw.challenge}</td>
      <td class="muted">${sw.category||''}</td>
      <td>${pill(sw.status)}</td>
      <td class="muted">${sw.solvers.length}</td>
      <td>${fmtUsd(sw.cost_usd)}</td>
      <td><button class="danger" onclick="killSwarm('${sw.challenge}')">kill</button></td>`;
    tbl.appendChild(tr);
  }

  // Solver dropdown for log tail
  const cur = logPick.value;
  logPick.innerHTML = '<option value="">— pick solver —</option>';
  for (const sw of s.swarms) {
    for (const sv of sw.solvers) {
      const v = `${sw.challenge}/${sv.model}`;
      const opt = document.createElement('option');
      opt.value = v; opt.textContent = v;
      if (v === cur) opt.selected = true;
      logPick.appendChild(opt);
    }
  }
}

function appendEvent(e) {
  const div = document.createElement('div');
  const cls = e.kind && e.kind.includes('error') ? 'err'
            : (e.kind && e.kind.includes('correct') ? 'ok' : '');
  const t = new Date(e.ts * 1000).toLocaleTimeString();
  div.innerHTML = `<span class="muted">${t}</span> <span class="tag ${cls}">${e.kind}</span> ${e.text||''}`;
  ev.prepend(div);
  while (ev.children.length > 200) ev.lastChild.remove();
}

async function doSpawn(e) {
  e.preventDefault();
  const name = document.getElementById('spawn-name').value.trim();
  if (!name) return false;
  await fetch('/api/spawn', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({challenge_name: name})});
  document.getElementById('spawn-name').value = '';
  return false;
}

async function doMsg(e) {
  e.preventDefault();
  const text = document.getElementById('msg-text').value.trim();
  if (!text) return false;
  await fetch('/api/msg', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: text})});
  document.getElementById('msg-text').value = '';
  return false;
}

async function killSwarm(name) {
  if (!confirm(`Kill swarm for "${name}"?`)) return;
  await fetch(`/api/swarms/${encodeURIComponent(name)}/kill`, {method: 'POST'});
}

async function refreshLog() {
  const v = logPick.value;
  if (!v) { logPre.textContent = '(pick a solver)'; return; }
  document.getElementById('log-which').textContent = v;
  const [chal, model] = v.split('/');
  const r = await fetch(`/api/logs/${encodeURIComponent(chal)}/${encodeURIComponent(model)}?tail=80`);
  const data = await r.json();
  logPre.textContent = data.lines.join('\\n') || '(no log yet)';
}

// SSE wiring
const es = new EventSource('/api/events');
es.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.type === 'status') renderStatus(d.payload);
  else if (d.type === 'event') appendEvent(d.payload);
};
es.onerror = () => appendEvent({ts: Date.now()/1000, kind: 'sse-disconnect',
  text: 'reconnecting...'});

// Initial fetch in case the SSE handshake races us
fetch('/api/status').then(r => r.json()).then(renderStatus);
setInterval(refreshLog, 4000);
</script>
</body></html>
"""


# ── Event broadcaster ───────────────────────────────────────────────────────
# Each connected SSE client gets one queue. The coordinator drops events
# in via broadcast(); clients pull via _sse_handler.

class EventHub:
    def __init__(self) -> None:
        self.clients: list[asyncio.Queue[dict]] = []

    def add(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=200)
        self.clients.append(q)
        return q

    def remove(self, q: asyncio.Queue[dict]) -> None:
        with contextlib.suppress(ValueError):
            self.clients.remove(q)

    def broadcast(self, kind: str, **fields: Any) -> None:
        evt = {"ts": time.time(), "kind": kind, **fields}
        for q in list(self.clients):
            try:
                q.put_nowait({"type": "event", "payload": evt})
            except asyncio.QueueFull:
                # Drop event for laggy clients rather than blocking the loop.
                pass

    def push_status(self, snapshot: dict) -> None:
        for q in list(self.clients):
            try:
                q.put_nowait({"type": "status", "payload": snapshot})
            except asyncio.QueueFull:
                pass


# ── Snapshot builder ────────────────────────────────────────────────────────

def _build_status(deps: Any, run_id: str) -> dict:
    """Render the coordinator's live state into a JSON-serializable dict."""
    swarms_out = []
    for name, swarm in deps.swarms.items():
        cancelled = swarm.cancel_event.is_set()
        task = deps.swarm_tasks.get(name)
        done = task is not None and task.done()
        status = "killed" if cancelled and not done else (
            "done" if done else "running"
        )
        solvers_out = []
        for spec, solver in swarm.solvers.items():
            agent_name = getattr(solver, "agent_name", f"{name}/{spec}")
            cost = 0.0
            if agent_name in deps.cost_tracker.by_agent:
                cost = deps.cost_tracker.by_agent[agent_name].cost_usd
            solvers_out.append({
                "model": spec,
                "step_count": getattr(solver, "_step_count", 0),
                "cost_usd": cost,
                "flag": getattr(solver, "_flag", None),
                "confirmed": getattr(solver, "_confirmed", False),
            })
        swarm_cost = sum(s["cost_usd"] for s in solvers_out)
        meta = swarm.meta
        swarms_out.append({
            "challenge": name,
            "category": getattr(meta, "category", "") or "",
            "value": getattr(meta, "value", 0) or 0,
            "status": status,
            "cost_usd": swarm_cost,
            "solvers": solvers_out,
        })

    settings = deps.settings
    quota = getattr(settings, "quota_usd", None)
    return {
        "ts": time.time(),
        "run_id": run_id,
        "session": {
            "name": getattr(settings, "session_name", "default"),
            "quota_usd": quota,
        },
        "cost": {
            "total_usd": deps.cost_tracker.total_cost_usd,
            "total_tokens": deps.cost_tracker.total_tokens,
        },
        "swarms": swarms_out,
        "results": deps.results,
    }


# ── Route handlers ──────────────────────────────────────────────────────────

async def _index(request: web.Request) -> web.Response:
    return web.Response(text=INDEX_HTML, content_type="text/html")


async def _status(request: web.Request) -> web.Response:
    deps = request.app["deps"]
    run_id = request.app["run_id"]
    return web.json_response(_build_status(deps, run_id))


async def _events(request: web.Request) -> web.StreamResponse:
    """Server-Sent Events stream. Pushes status snapshots + ad-hoc events."""
    deps = request.app["deps"]
    run_id = request.app["run_id"]
    hub: EventHub = request.app["hub"]

    resp = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering if proxied
        },
    )
    await resp.prepare(request)

    queue = hub.add()
    # Initial snapshot so the page renders before any state change.
    queue.put_nowait({"type": "status", "payload": _build_status(deps, run_id)})

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=2.0)
                payload = json.dumps(msg, default=str)
                await resp.write(f"data: {payload}\n\n".encode())
            except asyncio.TimeoutError:
                # Send a periodic snapshot to keep the dashboard live even when
                # nothing is changing — also serves as a keepalive.
                snap = _build_status(deps, run_id)
                payload = json.dumps({"type": "status", "payload": snap}, default=str)
                await resp.write(f"data: {payload}\n\n".encode())
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        hub.remove(queue)
    return resp


async def _logs(request: web.Request) -> web.Response:
    """Tail the JSONL tracer file for one solver."""
    chal = request.match_info["chal"]
    model = request.match_info["model"]
    try:
        tail = int(request.query.get("tail", "80"))
    except ValueError:
        tail = 80

    deps = request.app["deps"]
    swarm = deps.swarms.get(chal)
    lines: list[str] = []
    if swarm:
        solver = swarm.solvers.get(model)
        if solver is not None:
            tracer = getattr(solver, "tracer", None)
            path = getattr(tracer, "path", None) if tracer else None
            if path and Path(path).exists():
                try:
                    raw = Path(path).read_text(encoding="utf-8", errors="replace")
                    lines = raw.splitlines()[-tail:]
                except OSError:
                    pass
    return web.json_response({"lines": lines})


async def _msg(request: web.Request) -> web.Response:
    """Mirror of the previous hand-rolled /msg endpoint, but at /api/msg."""
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    body = await request.json()
    text = body.get("message", "")
    if not text:
        return web.json_response({"error": "missing 'message'"}, status=400)
    deps.operator_inbox.put_nowait(text)
    hub.broadcast("operator_msg", text=text[:200])
    return web.json_response({"ok": True, "queued": text[:200]})


async def _kill_swarm(request: web.Request) -> web.Response:
    chal = request.match_info["chal"]
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    swarm = deps.swarms.get(chal)
    if not swarm:
        return web.json_response({"error": f"no swarm for {chal!r}"}, status=404)
    swarm.kill()
    hub.broadcast("swarm_killed", challenge=chal, text=f"killed via dashboard")
    return web.json_response({"ok": True})


async def _spawn(request: web.Request) -> web.Response:
    deps = request.app["deps"]
    hub: EventHub = request.app["hub"]
    body = await request.json()
    name = (body.get("challenge_name") or "").strip()
    if not name:
        return web.json_response({"error": "missing 'challenge_name'"}, status=400)
    from backend.agents.coordinator_core import do_spawn_swarm
    try:
        result = await do_spawn_swarm(deps, name)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    hub.broadcast("spawn_request", challenge=name, text=result[:200])
    return web.json_response({"ok": True, "result": result})


# ── App factory + lifecycle ─────────────────────────────────────────────────

def build_app(deps: Any, run_id: str) -> web.Application:
    app = web.Application()
    app["deps"] = deps
    app["run_id"] = run_id
    app["hub"] = EventHub()
    app.router.add_get("/", _index)
    app.router.add_get("/api/status", _status)
    app.router.add_get("/api/events", _events)
    app.router.add_get("/api/logs/{chal}/{model}", _logs)
    app.router.add_post("/api/msg", _msg)
    app.router.add_post("/api/swarms/{chal}/kill", _kill_swarm)
    app.router.add_post("/api/spawn", _spawn)
    # Back-compat: the old hand-rolled server exposed /msg directly.
    app.router.add_post("/msg", _msg)
    return app


async def start_dashboard(
    deps: Any,
    run_id: str,
    port: int = 0,
    host: str = "127.0.0.1",
) -> tuple[web.AppRunner, int]:
    """Start the dashboard. Returns (runner, actual_port).

    Caller is responsible for `await runner.cleanup()` on shutdown.
    """
    app = build_app(deps, run_id)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    actual_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    logger.info("Dashboard listening on http://%s:%d", host, actual_port)
    return runner, actual_port
