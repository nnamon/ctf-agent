"""ctf-review CLI: read-only browser for completed sessions.

Standalone aiohttp app that walks `sessions/` and renders three views:

  /                              index of sessions (solves, cost, last activity)
  /sessions/<name>               challenges in that session, with stats
  /sessions/<name>/c/<slug>      single challenge: writeup + per-model breakdown

No coord required; reads the session DB (`sessions/<name>/logs/session.db`,
schema v2 — attempts + usage + challenge_solves + challenge_solve_models
in one file) and writeups/*.md. Designed to run alongside or after the
live coord — default port 13338 to not collide with the dashboard's 13337.

For sessions that have not yet been migrated to v2 (still on the legacy
attempts.db + usage.db split), run `ctf-migrate --apply` first.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import yaml
from aiohttp import web

from backend.session import SESSION_DIR

logger = logging.getLogger(__name__)


# ── data layer ─────────────────────────────────────────────────────────────


def _sessions_root() -> Path:
    return Path.cwd() / SESSION_DIR


def _slugify(name: str) -> str:
    """Match postmortem._slugify so writeup files line up with challenge names."""
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return slug or "challenge"


def _resolve_session_db(session_dir: Path) -> Path | None:
    """Locate the session DB. Falls back to legacy `usage.db` when
    `session.db` is missing — keeps the review app working on
    unmigrated sessions (with degraded data; user should run
    `ctf-migrate --apply` for the full picture)."""
    unified = session_dir / "logs" / "session.db"
    if unified.exists():
        return unified
    legacy = session_dir / "logs" / "usage.db"
    if legacy.exists():
        return legacy
    return None


def _resolve_attempts_db(session_dir: Path) -> Path | None:
    """Where to read `attempts` rows from. After v1→v2 migration both
    live in `session.db`. Pre-migration the row data is in a separate
    `attempts.db` file. Reviewer needs both so unmigrated sessions
    surface their writeup history."""
    unified = session_dir / "logs" / "session.db"
    if unified.exists():
        # Verify the table is actually there — sometimes session.db
        # got created by a usage-only path before the v2 schema bump.
        try:
            with sqlite3.connect(str(unified)) as conn:
                if _table_exists(conn, "attempts"):
                    return unified
        except sqlite3.Error:
            pass
    legacy = session_dir / "logs" / "attempts.db"
    if legacy.exists():
        return legacy
    return None


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


@dataclass
class SessionSummary:
    name: str
    quota_usd: float | None
    solves: int          # challenge_solves rows with status='flag_found'
    attempts: int        # all challenge_solves rows (any status)
    total_cost: float
    writeups_count: int
    last_activity: int   # unix epoch, max(finished_at) or mtime fallback
    models: list[str]    # distinct model_specs seen


def _list_sessions() -> list[SessionSummary]:
    root = _sessions_root()
    if not root.exists():
        return []
    out: list[SessionSummary] = []
    for d in sorted(root.iterdir(), key=lambda p: p.name):
        if not d.is_dir():
            continue
        out.append(_summarize_session(d))
    return out


def _summarize_session(session_dir: Path) -> SessionSummary:
    name = session_dir.name
    quota: float | None = None
    yml = session_dir / "session.yml"
    if yml.exists():
        try:
            data = yaml.safe_load(yml.read_text()) or {}
            q = data.get("quota_usd")
            if q is not None:
                quota = float(q)
        except Exception:
            pass

    solves = attempts = 0
    total_cost = 0.0
    last_activity = 0
    models: list[str] = []

    # Stats that live in challenge_solves / challenge_solve_models /
    # usage. Post-v2 these are in session.db; legacy sessions still
    # have them in usage.db.
    sess_db = _resolve_session_db(session_dir)
    if sess_db is not None:
        try:
            with sqlite3.connect(str(sess_db)) as conn:
                conn.row_factory = sqlite3.Row
                if _table_exists(conn, "challenge_solves"):
                    row = conn.execute(
                        "SELECT COUNT(*) AS n,"
                        "       COALESCE(SUM(cost_usd), 0) AS cost,"
                        "       COALESCE(MAX(finished_at), 0) AS last_ts"
                        " FROM challenge_solves"
                    ).fetchone()
                    if row:
                        attempts = int(row["n"] or 0)
                        total_cost = float(row["cost"] or 0)
                        last_activity = int(row["last_ts"] or 0)
                if _table_exists(conn, "challenge_solve_models"):
                    rows = conn.execute(
                        "SELECT DISTINCT model_spec FROM challenge_solve_models "
                        "ORDER BY model_spec"
                    ).fetchall()
                    models = [r["model_spec"] for r in rows]
        except Exception as e:
            logger.warning("session DB read failed for %s: %s", name, e)

    # Solve count comes from the `attempts` table — post-v2 in
    # session.db, pre-migration in attempts.db. Same query works on
    # both (the migration already normalised the v0→v1 row mistakes).
    att_db = _resolve_attempts_db(session_dir)
    if att_db is not None:
        try:
            with sqlite3.connect(str(att_db)) as conn:
                conn.row_factory = sqlite3.Row
                user_ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if user_ver >= 1:
                    # Trust status — migration normalised legacy rows.
                    sql = (
                        "SELECT COUNT(DISTINCT challenge_name) AS n,"
                        "       COALESCE(MAX(ts), 0) AS last_ts FROM attempts"
                        " WHERE status IN ('correct', 'already_solved')"
                    )
                else:
                    # Pre-v1 DB; fall back to message-content matching
                    # so unmigrated sessions still render sensibly.
                    sql = (
                        "SELECT COUNT(DISTINCT challenge_name) AS n,"
                        "       COALESCE(MAX(ts), 0) AS last_ts FROM attempts"
                        " WHERE status IN ('correct', 'already_solved')"
                        "    OR (lower(message) LIKE '%correct%'"
                        "        AND lower(message) NOT LIKE '%incorrect%')"
                    )
                row = conn.execute(sql).fetchone()
                if row:
                    solves = int(row["n"] or 0)
                    if not last_activity:
                        last_activity = int(row["last_ts"] or 0)
        except Exception as e:
            logger.warning("attempts read failed for %s: %s", name, e)

    writeups_dir = session_dir / "writeups"
    writeups_count = 0
    if writeups_dir.exists():
        writeups_count = sum(1 for _ in writeups_dir.glob("*.md"))
        if not last_activity:
            try:
                last_activity = int(max(
                    p.stat().st_mtime for p in writeups_dir.glob("*.md")
                ))
            except (OSError, ValueError):
                pass

    return SessionSummary(
        name=name, quota_usd=quota, solves=solves, attempts=attempts,
        total_cost=total_cost, writeups_count=writeups_count,
        last_activity=last_activity, models=models,
    )


@dataclass
class ChallengeRow:
    name: str
    category: str | None
    points: int | None
    status: str
    flag: str | None
    winner_spec: str | None
    duration_seconds: float
    cost_usd: float
    started_at: int
    finished_at: int
    has_writeup: bool
    per_model: list[dict[str, Any]]


def _session_challenges(session_dir: Path) -> list[ChallengeRow]:
    """Union challenge_solves rows + writeup files + attempts table.

    Rationale: challenge_solves persistence landed mid-session in some
    runs — earlier solved challenges have writeups but no
    challenge_solves row. We dedupe by slug and pull whatever metadata
    is available from each source.

    DB resolution: post-v2 both tables live in session.db; pre-v2 they
    split into usage.db + attempts.db. _resolve_*_db handles both.
    """
    writeups_dir = session_dir / "writeups"
    db = _resolve_session_db(session_dir)
    attempts_db = _resolve_attempts_db(session_dir)

    by_slug: dict[str, ChallengeRow] = {}

    # 1) challenge_solves rows (richest data)
    if db is not None and db.exists():
        try:
            with sqlite3.connect(str(db)) as conn:
                conn.row_factory = sqlite3.Row
                parents = conn.execute(
                    "SELECT cs.* FROM challenge_solves cs"
                    " JOIN ("
                    "   SELECT challenge_name, MAX(finished_at) mx"
                    "   FROM challenge_solves GROUP BY challenge_name"
                    " ) latest"
                    " ON cs.challenge_name=latest.challenge_name"
                    "   AND cs.finished_at=latest.mx"
                    " ORDER BY cs.finished_at DESC"
                ).fetchall()
                for p in parents:
                    per_model = conn.execute(
                        "SELECT model_spec, steps, cost_usd, input_tokens, output_tokens,"
                        "       cache_read_tokens, won FROM challenge_solve_models"
                        " WHERE challenge_solve_id=?"
                        " ORDER BY won DESC, model_spec",
                        (p["id"],),
                    ).fetchall()
                    slug = _slugify(p["challenge_name"])
                    has_writeup = (
                        writeups_dir.exists()
                        and bool(list(writeups_dir.glob(f"{slug}-*.md")))
                    )
                    by_slug[slug] = ChallengeRow(
                        name=p["challenge_name"],
                        category=p["category"],
                        points=p["points"],
                        status=p["status"],
                        flag=p["flag"],
                        winner_spec=p["winner_spec"],
                        duration_seconds=float(p["duration_seconds"] or 0),
                        cost_usd=float(p["cost_usd"] or 0),
                        started_at=int(p["started_at"] or 0),
                        finished_at=int(p["finished_at"] or 0),
                        has_writeup=has_writeup,
                        per_model=[dict(m) for m in per_model],
                    )
        except Exception as e:
            logger.warning("session DB read failed for %s: %s", session_dir.name, e)

    # 2) `attempts` table — fills in flag for slugs without a solves
    #    row. Post-v1 we trust status; pre-v1 (unmigrated) we fall
    #    back to message-content detection so legacy DBs still work.
    if attempts_db is not None and attempts_db.exists():
        try:
            with sqlite3.connect(str(attempts_db)) as conn:
                conn.row_factory = sqlite3.Row
                if not _table_exists(conn, "attempts"):
                    rows = []
                else:
                    user_ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
                    if user_ver >= 1:
                        sql = (
                            "SELECT challenge_name, flag, message, ts FROM attempts"
                            " WHERE status IN ('correct', 'already_solved')"
                            " ORDER BY ts ASC"
                        )
                    else:
                        sql = (
                            "SELECT challenge_name, flag, message, ts FROM attempts"
                            " WHERE status IN ('correct', 'already_solved')"
                            "    OR (lower(message) LIKE '%correct%'"
                            "        AND lower(message) NOT LIKE '%incorrect%')"
                            " ORDER BY ts ASC"
                        )
                    rows = conn.execute(sql).fetchall()
                for r in rows:
                    slug = _slugify(r["challenge_name"])
                    if slug in by_slug:
                        # challenge_solves row already covers this — only
                        # backfill missing flag (sometimes the solves row
                        # has flag=NULL when status='cancelled' due to a
                        # poller race).
                        if not by_slug[slug].flag:
                            by_slug[slug].flag = r["flag"]
                        continue
                    by_slug[slug] = ChallengeRow(
                        name=r["challenge_name"],
                        category=None,
                        points=None,
                        status="flag_found",
                        flag=r["flag"],
                        winner_spec=None,
                        duration_seconds=0.0,
                        cost_usd=0.0,
                        started_at=int(r["ts"] or 0),
                        finished_at=int(r["ts"] or 0),
                        has_writeup=(
                            writeups_dir.exists()
                            and bool(list(writeups_dir.glob(f"{slug}-*.md")))
                        ),
                        per_model=[],
                    )
        except Exception as e:
            logger.warning("attempts read failed for %s: %s", session_dir.name, e)

    # 3) writeup files — catch writeup-only entries (rebuilt with
    #    ctf-rebuild-writeups but no live solve row anywhere).
    if writeups_dir.exists():
        # filename format: <slug>-<YYYYMMDD>-<HHMMSS>.md (postmortem._slugify)
        ts_re = re.compile(r"-\d{8}-\d{6}\.md$")
        for p in writeups_dir.glob("*.md"):
            slug = ts_re.sub("", p.name) or p.stem
            if slug in by_slug:
                by_slug[slug].has_writeup = True
                continue
            try:
                mtime = int(p.stat().st_mtime)
            except OSError:
                mtime = 0
            by_slug[slug] = ChallengeRow(
                name=slug,
                category=None,
                points=None,
                status="flag_found",  # writeup exists → presumed solved
                flag=None,
                winner_spec=None,
                duration_seconds=0.0,
                cost_usd=0.0,
                started_at=mtime,
                finished_at=mtime,
                has_writeup=True,
                per_model=[],
            )

    # Sort: solved first, then by finished_at desc, then by name.
    return sorted(
        by_slug.values(),
        key=lambda r: (
            0 if r.status == "flag_found" else 1,
            -(r.finished_at or 0),
            r.name,
        ),
    )


def _find_writeup(session_dir: Path, slug: str) -> Path | None:
    writeups_dir = session_dir / "writeups"
    if not writeups_dir.exists():
        return None
    candidates = sorted(
        writeups_dir.glob(f"{slug}-*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


# ── formatting helpers (mirror dashboard's fmt*) ──────────────────────────


def _fmt_usd(n: float) -> str:
    return f"${n:,.2f}" if n else "$0.00"


def _fmt_dur(secs: float) -> str:
    s = int(secs)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _fmt_ts(ts: int) -> str:
    if not ts:
        return "—"
    import datetime as _dt
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _fmt_int(n: int | None) -> str:
    if not n:
        return "0"
    return f"{n:,}"


def _status_chip(status: str) -> str:
    label, cls = {
        "flag_found": ("solved", "ok"),
        "gave_up":    ("gave up", "warn"),
        "error":      ("error", "err"),
        "cancelled":  ("killed", "warn"),
    }.get(status, (status, ""))
    return f'<span class="chip chip-{cls}">{html.escape(label)}</span>'


# ── shared HTML chrome ────────────────────────────────────────────────────


_CSS = """
:root {
  --bg: #141218;
  --panel: #1d1b20;
  --panel-2: #211f26;
  --hover: #2b2930;
  --line: #49454f;
  --text: #e6e0e9;
  --muted: #cac4d0;
  --primary: #d0bcff;
  --ok: #a5d6a7; --ok-bg: rgba(165,214,167,.12);
  --warn: #ffb74d; --warn-bg: rgba(255,183,77,.12);
  --err: #f2b8b5; --err-bg: rgba(242,184,181,.12);
  --info: #90caf9; --info-bg: rgba(144,202,249,.12);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; min-height: 100%; }
body { background: var(--bg); color: var(--text); font: 14px/1.45 "Roboto", system-ui, sans-serif; }
.mono { font-family: "Roboto Mono", ui-monospace, monospace; }
a { color: var(--primary); text-decoration: none; }
a:hover { text-decoration: underline; }

.app-bar {
  display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
  padding: 12px 20px; background: var(--panel-2);
  border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 10;
}
.app-bar .brand { font-size: 18px; font-weight: 500; }
.app-bar .crumb { color: var(--muted); }
.app-bar .crumb a { color: var(--primary); }
.app-bar .spacer { flex: 1; }
.app-bar .hint { color: var(--muted); font-size: 12px; }

main { max-width: 1180px; margin: 0 auto; padding: 20px; }

.panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 16px 18px; margin-bottom: 14px;
}
.panel h2 { margin: 0 0 12px; font-size: 13px; font-weight: 600;
  color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }

table.grid { border-collapse: collapse; width: 100%; font-size: 13px; }
table.grid th, table.grid td {
  text-align: left; padding: 8px 10px;
  border-bottom: 1px solid var(--line); vertical-align: top;
}
table.grid th { font-weight: 500; color: var(--muted); background: var(--panel-2); }
table.grid tr:hover td { background: var(--hover); }
table.grid td.right, table.grid th.right { text-align: right; }
table.grid td.mono { font-family: "Roboto Mono", monospace; }
table.grid td.flag { color: var(--primary); }

.chip {
  display: inline-block; padding: 2px 9px; border-radius: 12px;
  font-size: 11px; font-weight: 500; letter-spacing: .03em;
  border: 1px solid currentColor;
}
.chip-ok   { color: var(--ok);   background: var(--ok-bg); }
.chip-warn { color: var(--warn); background: var(--warn-bg); }
.chip-err  { color: var(--err);  background: var(--err-bg); }

.kv-row { display: flex; gap: 18px; flex-wrap: wrap; font-size: 13px; }
.kv { display: flex; gap: 6px; align-items: baseline; }
.k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.v { color: var(--text); }

.scroll-x { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table.grid.min480 { min-width: 480px; }

.writeup {
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px;
  padding: 18px 22px; line-height: 1.55; font-size: 14px;
}
.writeup h1 { font-size: 22px; border-bottom: 1px solid var(--line); padding-bottom: 8px; margin-top: 0; }
.writeup h2 { font-size: 18px; margin-top: 28px; color: var(--primary); }
.writeup h3 { font-size: 15px; margin-top: 22px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.writeup code { background: rgba(255,255,255,.06); padding: 1px 5px; border-radius: 3px;
  font-family: "Roboto Mono", monospace; font-size: 12.5px; }
.writeup pre {
  background: #0f0d13; border: 1px solid var(--line); border-radius: 6px;
  padding: 10px 12px; overflow-x: auto; font-size: 12px;
}
.writeup pre code { background: transparent; padding: 0; }
.writeup blockquote { border-left: 3px solid var(--primary); margin: 14px 0;
  padding: 6px 14px; color: var(--muted); background: rgba(208,188,255,.04); }
.writeup table { border-collapse: collapse; margin: 12px 0; }
.writeup th, .writeup td { border: 1px solid var(--line); padding: 6px 10px; }

@media (max-width: 720px) {
  main { padding: 14px; }
  .panel { padding: 12px 14px; }
  table.grid th, table.grid td { padding: 6px 8px; font-size: 12.5px; }
  .writeup { padding: 14px; }
}
"""


def _shell(title: str, crumbs_html: str, body_html: str, with_marked: bool = False) -> str:
    marked_tag = (
        '<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>'
        if with_marked else ""
    )
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
{marked_tag}
<style>{_CSS}</style>
</head><body>
<div class="app-bar">
  <span class="brand">ctf-review</span>
  <span class="crumb">{crumbs_html}</span>
  <span class="spacer"></span>
  <span class="hint">read-only · sessions/</span>
</div>
<main>{body_html}</main>
</body></html>"""


# ── handlers ───────────────────────────────────────────────────────────────


async def _index(request: web.Request) -> web.Response:
    sessions = _list_sessions()
    if not sessions:
        body = '<div class="panel">No sessions yet under <code>sessions/</code>.</div>'
        return web.Response(text=_shell("ctf-review", "", body), content_type="text/html")

    rows: list[str] = []
    for s in sessions:
        solve_rate = (
            f"{s.solves}/{s.attempts}" if s.attempts
            else f"{s.solves}" if s.solves else "—"
        )
        quota = _fmt_usd(s.quota_usd) if s.quota_usd is not None else "—"
        models = ", ".join(s.models) if s.models else "—"
        rows.append(f"""<tr>
          <td><a href="/sessions/{html.escape(s.name)}">{html.escape(s.name)}</a></td>
          <td class="mono right">{html.escape(solve_rate)}</td>
          <td class="mono right">{html.escape(_fmt_usd(s.total_cost))}</td>
          <td class="mono right">{html.escape(quota)}</td>
          <td class="mono right">{s.writeups_count}</td>
          <td class="mono">{html.escape(_fmt_ts(s.last_activity))}</td>
          <td>{html.escape(models)}</td>
        </tr>""")

    body = f"""
<div class="panel">
  <h2>Sessions ({len(sessions)})</h2>
  <div class="scroll-x">
  <table class="grid min480">
    <thead><tr>
      <th>Name</th>
      <th class="right">Solved</th>
      <th class="right">Spent</th>
      <th class="right">Quota</th>
      <th class="right">Writeups</th>
      <th>Last activity</th>
      <th>Models</th>
    </tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  </div>
</div>"""
    return web.Response(text=_shell("ctf-review", "", body), content_type="text/html")


async def _session_view(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    session_dir = _sessions_root() / name
    if not session_dir.is_dir():
        raise web.HTTPNotFound(text=f"session {name!r} not found")

    summary = _summarize_session(session_dir)
    challenges = _session_challenges(session_dir)
    crumbs = f'<a href="/">sessions</a> / <strong>{html.escape(name)}</strong>'

    rows: list[str] = []
    for c in challenges:
        link = (
            f'<a href="/sessions/{html.escape(name)}/c/{html.escape(_slugify(c.name))}">{html.escape(c.name)}</a>'
            if c.has_writeup or c.status == "flag_found"
            else html.escape(c.name)
        )
        winner = (
            f'<span class="mono">{html.escape(c.winner_spec)}</span>'
            if c.winner_spec else '<span style="color:var(--muted)">—</span>'
        )
        wu = "✓" if c.has_writeup else "—"
        rows.append(f"""<tr>
          <td>{link}</td>
          <td>{html.escape(c.category or '—')}</td>
          <td class="mono right">{c.points or '—'}</td>
          <td>{_status_chip(c.status)}</td>
          <td>{winner}</td>
          <td class="mono right">{html.escape(_fmt_dur(c.duration_seconds))}</td>
          <td class="mono right">{html.escape(_fmt_usd(c.cost_usd))}</td>
          <td class="mono">{html.escape(_fmt_ts(c.finished_at))}</td>
          <td class="mono right">{wu}</td>
        </tr>""")

    body = f"""
<div class="panel">
  <h2>{html.escape(name)}</h2>
  <div class="kv-row">
    <span class="kv"><span class="k">solved</span><span class="v mono">{summary.solves}/{summary.attempts}</span></span>
    <span class="kv"><span class="k">spent</span><span class="v mono">{html.escape(_fmt_usd(summary.total_cost))}</span></span>
    <span class="kv"><span class="k">quota</span><span class="v mono">{html.escape(_fmt_usd(summary.quota_usd) if summary.quota_usd is not None else '—')}</span></span>
    <span class="kv"><span class="k">writeups</span><span class="v mono">{summary.writeups_count}</span></span>
    <span class="kv"><span class="k">last</span><span class="v mono">{html.escape(_fmt_ts(summary.last_activity))}</span></span>
    <span class="kv"><span class="k">models</span><span class="v mono">{html.escape(', '.join(summary.models) if summary.models else '—')}</span></span>
  </div>
</div>

<div class="panel">
  <h2>Challenges ({len(challenges)})</h2>
  <div class="scroll-x">
  <table class="grid min480">
    <thead><tr>
      <th>Name</th><th>Category</th><th class="right">Pts</th>
      <th>Status</th><th>Winner</th>
      <th class="right">Duration</th><th class="right">Cost</th>
      <th>Finished</th><th class="right">Writeup</th>
    </tr></thead>
    <tbody>
      {''.join(rows) or '<tr><td colspan="9" style="color:var(--muted);text-align:center;padding:18px">No challenge_solves rows yet for this session.</td></tr>'}
    </tbody>
  </table>
  </div>
</div>"""
    return web.Response(text=_shell(f"{name} · ctf-review", crumbs, body),
                        content_type="text/html")


async def _challenge_view(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    slug = request.match_info["slug"]
    session_dir = _sessions_root() / name
    if not session_dir.is_dir():
        raise web.HTTPNotFound(text=f"session {name!r} not found")

    # Find the matching ChallengeRow by slug (slugify both sides for safety).
    challenges = _session_challenges(session_dir)
    chal = next((c for c in challenges if _slugify(c.name) == slug), None)
    writeup_path = _find_writeup(session_dir, slug)
    if chal is None and writeup_path is None:
        raise web.HTTPNotFound(text=f"challenge {slug!r} not in session {name!r}")

    crumbs = (
        f'<a href="/">sessions</a> / '
        f'<a href="/sessions/{html.escape(name)}">{html.escape(name)}</a> / '
        f'<strong>{html.escape(slug)}</strong>'
    )

    # Header card with the metadata we have.
    header_rows: list[str] = []
    if chal:
        header_rows.append(f"""<div class="kv-row">
  <span class="kv"><span class="k">status</span><span class="v">{_status_chip(chal.status)}</span></span>
  <span class="kv"><span class="k">winner</span><span class="v mono">{html.escape(chal.winner_spec or '—')}</span></span>
  <span class="kv"><span class="k">duration</span><span class="v mono">{html.escape(_fmt_dur(chal.duration_seconds))}</span></span>
  <span class="kv"><span class="k">cost</span><span class="v mono">{html.escape(_fmt_usd(chal.cost_usd))}</span></span>
  <span class="kv"><span class="k">category</span><span class="v">{html.escape(chal.category or '—')}</span></span>
  <span class="kv"><span class="k">points</span><span class="v mono">{chal.points or '—'}</span></span>
  <span class="kv"><span class="k">finished</span><span class="v mono">{html.escape(_fmt_ts(chal.finished_at))}</span></span>
</div>""")
        if chal.flag:
            header_rows.append(f'<div style="margin-top:10px"><span class="k">flag</span> '
                               f'<code>{html.escape(chal.flag)}</code></div>')

        if chal.per_model:
            mrows = []
            for m in chal.per_model:
                star = " ★" if m.get("won") else ""
                cls = " style=\"color:var(--primary)\"" if m.get("won") else ""
                mrows.append(f"""<tr{cls}>
                  <td class="mono">{html.escape(m['model_spec'])}{star}</td>
                  <td class="mono right">{_fmt_int(m['steps'])}</td>
                  <td class="mono right">{html.escape(_fmt_usd(m['cost_usd']))}</td>
                  <td class="mono right">{_fmt_int(m['input_tokens'])}</td>
                  <td class="mono right">{_fmt_int(m['output_tokens'])}</td>
                  <td class="mono right">{_fmt_int(m['cache_read_tokens'])}</td>
                </tr>""")
            header_rows.append(f"""<h3 style="margin-top:18px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">Per-model breakdown</h3>
<div class="scroll-x">
<table class="grid min480">
  <thead><tr>
    <th>Model</th>
    <th class="right">Steps</th>
    <th class="right">Cost</th>
    <th class="right">In tok</th>
    <th class="right">Out tok</th>
    <th class="right">Cache</th>
  </tr></thead>
  <tbody>{''.join(mrows)}</tbody>
</table>
</div>""")

    header_html = f'<div class="panel"><h2>{html.escape(chal.name if chal else slug)}</h2>{"".join(header_rows)}</div>' if header_rows else ""

    # Writeup body — render via marked.js client-side. Embed raw markdown
    # in a hidden <script type="text/markdown"> so it's treated as opaque
    # text by the browser parser.
    if writeup_path:
        try:
            md_text = writeup_path.read_text(encoding="utf-8")
        except OSError as e:
            md_text = f"_(could not read {writeup_path}: {e})_"
        # JSON-escape for a string literal in inline JS.
        import json
        md_js = json.dumps(md_text)
        writeup_block = f"""
<div class="panel">
  <h2>Writeup <span style="font-weight:400;color:var(--muted)">· {html.escape(writeup_path.name)}</span></h2>
  <div id="writeup-body" class="writeup"><em>Rendering…</em></div>
</div>
<script>
const md = {md_js};
const el = document.getElementById('writeup-body');
if (typeof marked !== 'undefined' && marked.parse) {{
  el.innerHTML = marked.parse(md);
}} else {{
  el.innerHTML = '<pre style="white-space:pre-wrap"></pre>';
  el.firstChild.textContent = md;
}}
</script>"""
    else:
        writeup_block = '<div class="panel"><h2>Writeup</h2><div style="color:var(--muted)">No writeup file under this session\'s writeups/.</div></div>'

    body = header_html + writeup_block
    return web.Response(
        text=_shell(f"{slug} · {name} · ctf-review", crumbs, body, with_marked=True),
        content_type="text/html",
    )


# ── CLI entrypoint ─────────────────────────────────────────────────────────


@click.command()
@click.option("--port", default=13338, type=int, show_default=True,
              help="Port for the review app (13338 by default to avoid the live coord's 13337).")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. 127.0.0.1 is localhost-only (default); 0.0.0.0 makes it LAN-reachable.")
def review_main(port: int, host: str) -> None:
    """Read-only browser for completed ctf-agent sessions.

    Walks ./sessions/ and renders each one's challenge_solves rows
    (status, winner, cost, per-model breakdown) plus the matching
    markdown writeup. No coord required.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    asyncio.run(_run(host, port))


async def _run(host: str, port: int) -> None:
    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/sessions/{name}", _session_view)
    app.router.add_get("/sessions/{name}/c/{slug}", _challenge_view)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    click.echo(f"ctf-review listening on http://{host}:{port}/  (Ctrl+C to stop)")
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    review_main()
