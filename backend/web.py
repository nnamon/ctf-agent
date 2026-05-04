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

Bind defaults to 0.0.0.0 (all interfaces) so an operator on the same
LAN/VPN can reach the dashboard without SSH-tunneling. There is NO
authentication — anyone who can reach the port can kill swarms and
inject messages. Lock this down before exposing on a real CTF
network: bind to 127.0.0.1 + use `ssh -L`, or put a reverse-proxy
with auth in front.
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
<html lang="en"><head><meta charset="utf-8">
<title>ctf-agent dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --bg: #0d1117;
  --bg-elev: #161b22;
  --bg-deep: #010409;
  --fg: #e6edf3;
  --fg-dim: #b1bac4;
  --muted: #7d8590;
  --line: #30363d;
  --line-soft: #21262d;
  --accent: #2f81f7;
  --green: #3fb950;
  --yellow: #d29922;
  --red: #f85149;
  --cyan: #79c0ff;
  --magenta: #d2a8ff;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui,
        "Helvetica Neue", Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }

header {
  padding: 14px 24px;
  border-bottom: 1px solid var(--line);
  display: flex;
  gap: 24px;
  align-items: center;
  flex-wrap: wrap;
  background: linear-gradient(180deg, #0e1320 0%, var(--bg) 100%);
}
.brand { display: flex; align-items: center; gap: 8px; font-weight: 600; }
.brand .dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--green); box-shadow: 0 0 8px var(--green);
  animation: pulse 2s infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
.kv { display: flex; gap: 8px; align-items: baseline; }
.kv .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.kv .v { color: var(--fg); }
.kv .v.mono { color: var(--cyan); }

.quota-bar {
  display: inline-flex; align-items: center; gap: 8px;
}
.quota-bar .track {
  width: 120px; height: 6px; border-radius: 3px;
  background: var(--line-soft); overflow: hidden;
}
.quota-bar .fill { height: 100%; background: var(--green); transition: width .3s, background .3s; }
.quota-bar.warn .fill { background: var(--yellow); }
.quota-bar.danger .fill { background: var(--red); }

main {
  display: grid;
  grid-template-columns: 1fr 360px;
  gap: 16px;
  padding: 16px 24px 24px;
  max-width: 1600px;
  margin: 0 auto;
}
main > .col-main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
main > .col-side { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
@media (max-width: 1100px) { main { grid-template-columns: 1fr; } }
.card {
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.card h2 {
  font-size: 11px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--muted);
  margin: 0 0 12px;
  font-weight: 600;
}
.card h2 .extra { color: var(--fg-dim); text-transform: none; letter-spacing: 0; font-weight: 400; margin-left: 6px; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line-soft); }
th { color: var(--muted); font-weight: 500; font-size: 11px;
     text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
tr:hover td { background: rgba(177, 186, 196, .04); }
td.right { text-align: right; }

.pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 500;
  border: 1px solid;
}
.pill.run    { color: var(--green);  border-color: rgba(63, 185, 80, .4);  background: rgba(63, 185, 80, .08); }
.pill.done   { color: var(--cyan);   border-color: rgba(121, 192, 255, .4); background: rgba(121, 192, 255, .08); }
.pill.killed { color: var(--red);    border-color: rgba(248, 81, 73, .4);  background: rgba(248, 81, 73, .08); }

button {
  background: var(--line-soft);
  color: var(--fg);
  border: 1px solid var(--line);
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font: inherit; font-size: 12px;
  transition: background .15s, border-color .15s;
}
button:hover { background: #2c333d; border-color: #444c56; }
button:active { background: #1f242c; }
button.danger { color: var(--red); border-color: rgba(248, 81, 73, .35); }
button.danger:hover { background: rgba(248, 81, 73, .12); border-color: var(--red); }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
button.primary:hover { background: #1f6feb; }

input[type=text], select {
  background: var(--bg);
  color: var(--fg);
  border: 1px solid var(--line);
  padding: 7px 10px;
  border-radius: 6px;
  font: inherit; font-size: 13px;
  flex: 1;
  min-width: 0;
}
input[type=text]:focus, select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(47, 129, 247, .2);
}

form { display: flex; gap: 8px; align-items: center; margin-top: 8px; }

.events { max-height: 360px; overflow-y: auto; font-size: 12px; }
.event-row {
  padding: 6px 8px;
  border-bottom: 1px solid var(--line-soft);
  display: grid;
  grid-template-columns: 70px 130px 1fr;
  gap: 8px;
  align-items: baseline;
}
.event-row:last-child { border-bottom: 0; }
.event-row .t { color: var(--muted); font-family: ui-monospace, monospace; font-size: 11px; }
.event-row .k { color: var(--cyan); font-weight: 500; }
.event-row.ok .k  { color: var(--green); }
.event-row.err .k { color: var(--red); }

pre.log {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.5;
  background: var(--bg-deep);
  border: 1px solid var(--line-soft);
  padding: 12px;
  border-radius: 8px;
  margin: 0;
  max-height: 360px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

.log-toolbar { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; }
.log-toolbar select { flex: 1; }

.empty {
  padding: 24px;
  text-align: center;
  color: var(--muted);
  border: 1px dashed var(--line);
  border-radius: 8px;
  font-size: 13px;
}

/* Challenge cards */
.challenge {
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: 10px;
  overflow: hidden;
}
.challenge-header {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--line-soft);
  background: linear-gradient(180deg, rgba(255,255,255,.02), transparent);
}
.challenge-header .title { font-weight: 600; font-size: 14px; }
.challenge-header .meta { color: var(--muted); font-size: 12px; }
.challenge-header .spacer { flex: 1; }
.challenge-header .cost { font-family: ui-monospace, monospace; color: var(--fg-dim); font-size: 12px; }

.solvers { width: 100%; }
.solvers th, .solvers td {
  padding: 8px 16px; border-bottom: 1px solid var(--line-soft);
  font-size: 12.5px;
}
.solvers th {
  font-size: 10.5px;
}
.solvers tr:last-child td { border-bottom: 0; }
.solvers .model { font-family: ui-monospace, monospace; color: var(--fg-dim); }
.solvers .winner td { background: rgba(63, 185, 80, .06); }
.solvers .winner .model { color: var(--green); font-weight: 500; }
.solvers .winner .model::before { content: "★ "; }
.solvers td.actions { text-align: right; }
.solvers td.actions button { padding: 3px 10px; font-size: 11px; }

.log-row td { padding: 0 16px 12px; border-bottom: 1px solid var(--line-soft); }
.log-row pre.log { max-height: 260px; }

.challenge-footer {
  display: flex; justify-content: flex-end; gap: 8px;
  padding: 8px 16px;
  background: rgba(0, 0, 0, .15);
}
</style></head>
<body>
<header>
  <div class="brand"><span class="dot"></span>ctf-agent</div>
  <div class="kv"><span class="k">session</span>
    <span class="v" id="hdr-session">—</span></div>
  <div class="kv"><span class="k">run</span>
    <span class="v mono" id="hdr-run">—</span></div>
  <div class="kv"><span class="k">spent</span>
    <span class="v mono" id="hdr-cost">$0.00</span></div>
  <div class="kv" id="hdr-quota-wrap" style="display:none">
    <span class="k">quota</span>
    <span class="quota-bar" id="hdr-quota">
      <span class="track"><span class="fill" id="hdr-quota-fill" style="width:0%"></span></span>
      <span class="v mono" id="hdr-quota-text"></span>
    </span>
  </div>
  <div class="kv" style="margin-left:auto"><span class="k">updated</span>
    <span class="v mono" id="hdr-time">—</span></div>
</header>
<main>
  <div class="col-main">
    <section class="card">
      <h2>Spawn / steer</h2>
      <form onsubmit="return doSpawn(event)">
        <input type="text" id="spawn-name" placeholder="challenge name (e.g. Toy XOR-B64)">
        <button class="primary">Spawn</button>
      </form>
      <form onsubmit="return doMsg(event)">
        <input type="text" id="msg-text" placeholder="send a message to the coordinator">
        <button>Send</button>
      </form>
    </section>

    <div id="challenges"></div>
  </div>

  <div class="col-side">
    <section class="card" style="position: sticky; top: 16px;">
      <h2>Events</h2>
      <div class="events" id="events"></div>
    </section>
  </div>
</main>

<script>
const ev = document.getElementById('events');
const challengesEl = document.getElementById('challenges');

const fmtUsd = n => '$' + (n || 0).toFixed(2);
const escapeHTML = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// Track which (challenge, model) log rows are expanded so renders preserve them.
const expandedLogs = new Set();
function logKey(chal, model) { return chal + '\\u241F' + model; }

function pill(status) {
  const cls = status === 'running' ? 'run' : (status === 'killed' ? 'killed' : 'done');
  return `<span class="pill ${cls}">${status}</span>`;
}

function renderHeader(s) {
  document.getElementById('hdr-session').textContent = s.session.name;
  document.getElementById('hdr-run').textContent = s.run_id;
  document.getElementById('hdr-cost').textContent = fmtUsd(s.cost.total_usd);
  document.getElementById('hdr-time').textContent =
    new Date(s.ts * 1000).toLocaleTimeString();

  const quotaWrap = document.getElementById('hdr-quota-wrap');
  if (s.session.quota_usd) {
    const pct = Math.min(100, (s.cost.total_usd / s.session.quota_usd) * 100);
    quotaWrap.style.display = '';
    document.getElementById('hdr-quota-fill').style.width = pct.toFixed(1) + '%';
    document.getElementById('hdr-quota-text').textContent =
      `${fmtUsd(s.cost.total_usd)} / ${fmtUsd(s.session.quota_usd)} (${pct.toFixed(0)}%)`;
    const bar = document.getElementById('hdr-quota');
    bar.classList.toggle('danger', pct >= 100);
    bar.classList.toggle('warn',   pct >= 80 && pct < 100);
  } else {
    quotaWrap.style.display = 'none';
  }
}

function renderChallenges(swarms) {
  if (!swarms.length) {
    challengesEl.innerHTML =
      '<div class="empty">No active swarms. Use the spawn box above to start one.</div>';
    return;
  }
  let html = '';
  for (const sw of swarms) {
    const cName = escapeHTML(sw.challenge);
    const cNameEnc = encodeURIComponent(sw.challenge);
    html += `<section class="challenge" data-challenge="${cName}">
      <div class="challenge-header">
        <span class="title">${cName}</span>
        <span class="meta">${escapeHTML(sw.category || '—')} · ${sw.value || 0}pts</span>
        ${pill(sw.status)}
        <span class="spacer"></span>
        <span class="cost">${fmtUsd(sw.cost_usd)} across ${sw.solvers.length} solvers</span>
      </div>
      <table class="solvers"><thead><tr>
        <th>Model</th><th>Step</th><th class="right">Cost</th>
        <th>Flag</th><th class="actions"></th>
      </tr></thead><tbody>`;
    for (const sv of sw.solvers) {
      const k = logKey(sw.challenge, sv.model);
      const isOpen = expandedLogs.has(k);
      const flagCell = sv.confirmed
        ? `<span style="color:var(--green);font-family:ui-monospace,monospace">${escapeHTML(sv.flag || '★')}</span>`
        : (sv.flag
            ? `<span class="mono" style="color:var(--yellow)">${escapeHTML(sv.flag)} (unconfirmed)</span>`
            : '<span style="color:var(--muted)">—</span>');
      html += `<tr class="${sv.confirmed ? 'winner' : ''}">
        <td class="model">${escapeHTML(sv.model)}</td>
        <td><span style="color:var(--fg-dim)">${sv.step_count}</span></td>
        <td class="right mono">${fmtUsd(sv.cost_usd)}</td>
        <td>${flagCell}</td>
        <td class="actions">
          <button onclick="toggleLog('${cNameEnc}','${encodeURIComponent(sv.model)}')">${isOpen ? 'Hide' : 'Log'}</button>
        </td>
      </tr>`;
      if (isOpen) {
        html += `<tr class="log-row" data-key="${escapeHTML(k)}">
          <td colspan="5"><pre class="log" id="log-${escapeHTML(k)}">loading…</pre></td>
        </tr>`;
      }
    }
    html += `</tbody></table>
      <div class="challenge-footer">
        <button class="danger" onclick="killSwarm('${cNameEnc}')">Kill swarm</button>
      </div>
    </section>`;
  }
  challengesEl.innerHTML = html;
  // Refresh the open logs after re-render.
  for (const k of expandedLogs) fetchLogInto(k);
}

function appendEvent(e) {
  const cls = e.kind && (e.kind.includes('error') || e.kind === 'swarm_killed') ? 'err'
            : (e.kind && (e.kind.includes('correct') || e.kind === 'swarm_finished') ? 'ok' : '');
  const t = new Date(e.ts * 1000).toLocaleTimeString();
  const div = document.createElement('div');
  div.className = `event-row ${cls}`;
  div.innerHTML = `<span class="t">${t}</span>
                   <span class="k">${escapeHTML(e.kind || '')}</span>
                   <span>${escapeHTML(e.text || '')}</span>`;
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

async function killSwarm(nameEnc) {
  const name = decodeURIComponent(nameEnc);
  if (!confirm(`Kill swarm for "${name}"?`)) return;
  await fetch(`/api/swarms/${nameEnc}/kill`, {method: 'POST'});
}

function toggleLog(chalEnc, modelEnc) {
  const chal = decodeURIComponent(chalEnc);
  const model = decodeURIComponent(modelEnc);
  const k = logKey(chal, model);
  if (expandedLogs.has(k)) expandedLogs.delete(k);
  else expandedLogs.add(k);
  // Re-render to add/remove the inline log row.
  if (latestStatus) renderChallenges(latestStatus.swarms);
}

async function fetchLogInto(k) {
  const sep = '\\u241F';
  const i = k.indexOf(sep);
  if (i < 0) return;
  const chal = k.substring(0, i);
  const model = k.substring(i + sep.length);
  const r = await fetch(
    `/api/logs/${encodeURIComponent(chal)}/${encodeURIComponent(model)}?tail=80`);
  const data = await r.json();
  const el = document.getElementById('log-' + CSS.escape(k));
  if (el) el.textContent = data.lines.join('\\n') || '(no log yet — solver may still be starting)';
}

let latestStatus = null;
function applyStatus(s) {
  latestStatus = s;
  renderHeader(s);
  renderChallenges(s.swarms);
}

// SSE wiring
const es = new EventSource('/api/events');
es.onmessage = m => {
  const d = JSON.parse(m.data);
  if (d.type === 'status') applyStatus(d.payload);
  else if (d.type === 'event') appendEvent(d.payload);
};
es.onerror = () => appendEvent({ts: Date.now()/1000, kind: 'sse-disconnect',
  text: 'reconnecting...'});

// Initial fetch in case SSE handshake races us
fetch('/api/status').then(r => r.json()).then(applyStatus).catch(()=>{});

// Periodic refresh of any expanded logs
setInterval(() => { for (const k of expandedLogs) fetchLogInto(k); }, 4000);
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
    host: str = "0.0.0.0",
) -> tuple[web.AppRunner, int]:
    """Start the dashboard. Returns (runner, actual_port).

    Defaults to host="0.0.0.0" so the dashboard is reachable on the
    local network / VPN without an SSH tunnel. No auth — bind to
    "127.0.0.1" via the coordinator's --msg-host flag for sensitive
    deployments.

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
