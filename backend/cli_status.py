"""`ctf-status` — show what each solver is doing on a challenge.

Reads the JSONL traces under logs/, grouped per challenge per model. Three
output modes:
  * default   one-shot per-solver summary table
  * --watch   Rich Live panel that refreshes every --interval seconds
  * --timeline merged chronological feed across all solvers

Designed to work both during and after a run — traces are line-buffered and
flushed on every event, so tailing a live solver works.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

TS_SUFFIX_RE = re.compile(r"-(\d{8}-\d{6})$")


def _slugify(name: str) -> str:
    return name.replace("/", "_").replace(" ", "_")


def _parse_trace_filename(path: Path) -> tuple[str, str, str] | None:
    """Return (challenge_slug, model_id, timestamp) parsed from trace filename."""
    stem = path.stem  # trace-<chal>-<model>-<YYYYMMDD-HHMMSS>
    if not stem.startswith("trace-"):
        return None
    m = TS_SUFFIX_RE.search(stem)
    if not m:
        return None
    ts = m.group(1)
    rest = stem[len("trace-") : m.start()]  # <chal>-<model>
    return rest, "", ts  # model resolved later when challenge slug is known


def _find_traces(challenge_slug: str, logs_dir: Path) -> dict[str, Path]:
    """Find latest trace per model for a challenge. Returns model_id -> path."""
    pattern = f"trace-{challenge_slug}-*.jsonl"
    candidates = list(logs_dir.glob(pattern))
    by_model: dict[str, tuple[str, Path]] = {}
    prefix = f"trace-{challenge_slug}-"
    for p in candidates:
        stem = p.stem
        m = TS_SUFFIX_RE.search(stem)
        if not m or not stem.startswith(prefix):
            continue
        ts = m.group(1)
        model_id = stem[len(prefix) : m.start()]
        if model_id not in by_model or by_model[model_id][0] < ts:
            by_model[model_id] = (ts, p)
    return {model: path for model, (_, path) in by_model.items()}


def _resolve_challenge(name: str, logs_dir: Path) -> str:
    """Map user input to the actual sanitized slug used in trace filenames."""
    target = _slugify(name).lower()
    seen: set[str] = set()
    for p in logs_dir.glob("trace-*.jsonl"):
        stem = p.stem
        m = TS_SUFFIX_RE.search(stem)
        if not m or not stem.startswith("trace-"):
            continue
        rest = stem[len("trace-") : m.start()]
        # rest is <chal>-<model>; we don't know where the boundary is, but the
        # challenge slug is the leading prefix shared by every trace for that
        # challenge. Take the longest matching prefix of any trace.
        for cand_len in range(len(rest), 0, -1):
            cand = rest[:cand_len]
            if cand.endswith("-"):
                cand = cand[:-1]
            seen.add(cand)
    # exact match (case-insensitive) wins
    for s in seen:
        if s.lower() == target:
            return s
    # otherwise: prefix match on slugified form
    matches = [s for s in seen if s.lower().startswith(target)]
    if len(matches) == 1:
        return matches[0]
    if matches:
        # pick longest unique prefix
        matches.sort(key=len)
        return matches[0]
    return _slugify(name)


def _parse_events(path: Path) -> list[dict]:
    events: list[dict] = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        return events
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _short_payload(args_blob) -> str:
    """Extract a one-line summary of a tool call's arguments."""
    if isinstance(args_blob, str):
        try:
            args = json.loads(args_blob)
        except (json.JSONDecodeError, ValueError):
            return args_blob.replace("\n", " ")[:120]
    else:
        args = args_blob
    if isinstance(args, dict):
        # Prefer command/url/path fields
        for key in ("command", "url", "path", "filename", "content", "flag"):
            if key in args and isinstance(args[key], str):
                return args[key].replace("\n", " ")[:120]
        return json.dumps(args, ensure_ascii=False)[:120]
    return str(args)[:120]


def _solver_panel(model_id: str, events: list[dict]) -> Panel:
    """Build a Rich panel summarizing one solver's progress."""
    step_count = sum(1 for e in events if e.get("type") == "tool_call")
    last_usage = next(
        (e for e in reversed(events) if e.get("type") == "usage"), None
    )
    cost = last_usage.get("cost_usd", 0.0) if last_usage else 0.0
    notes = [e for e in events if e.get("type") == "note"]
    finish = next((e for e in reversed(events) if e.get("type") == "finish"), None)
    flag_confirmed = next(
        (e for e in events if e.get("type") == "flag_confirmed"), None
    )

    # Status badge
    if flag_confirmed:
        status = Text("FLAG", style="bold green")
    elif finish:
        st = finish.get("status", "?")
        color = {
            "flag_found": "green",
            "cancelled": "yellow",
            "gave_up": "blue",
            "error": "red",
            "quota_error": "red",
        }.get(st, "white")
        status = Text(st, style=f"bold {color}")
    elif events and events[-1].get("type") != "stop":
        status = Text("running", style="cyan")
    else:
        status = Text("idle", style="dim")

    # Last 3 tool calls
    calls = [e for e in events if e.get("type") == "tool_call"]
    last_calls = calls[-3:]

    # Build the body
    body = Text()
    body.append(f"  status   : ", style="dim")
    body.append_text(status)
    body.append(f"\n  steps    : {step_count}\n  cost     : ${cost:.4f} cosmetic\n")
    if notes:
        body.append(f"  notes    : {len(notes)}\n", style="green")
    if flag_confirmed:
        body.append(
            f"  flag     : {flag_confirmed.get('flag', '?')}\n", style="bold green"
        )

    if last_calls:
        body.append("\n  recent calls:\n", style="dim")
        for e in last_calls:
            payload = _short_payload(e.get("args", ""))
            body.append(
                f"    [{e.get('step', '?'):>3}] {e.get('tool', '?'):8} {payload}\n"
            )

    if notes:
        body.append("\n  notes:\n", style="dim")
        for n in notes:
            content = str(n.get("content", "")).strip().replace("\n", " ")
            if len(content) > 200:
                content = content[:200] + "…"
            body.append(f"    [{n.get('step', '?'):>3}] {content}\n")

    return Panel(body, title=f"[bold]{model_id}[/bold]", expand=True)


def _render_summary(challenge_slug: str, traces: dict[str, Path]) -> Group:
    """One-shot summary across all solvers."""
    if not traces:
        return Group(
            Text(f"No traces found for challenge slug '{challenge_slug}'", style="red")
        )
    panels = []
    for model_id in sorted(traces.keys()):
        events = _parse_events(traces[model_id])
        panels.append(_solver_panel(model_id, events))
    header = Text(
        f"Challenge: {challenge_slug}  ·  {len(traces)} solver(s)", style="bold"
    )
    return Group(header, Text(""), *panels)


def _render_timeline(challenge_slug: str, traces: dict[str, Path], limit: int = 80) -> Group:
    """Chronological merged feed across all solvers (last N events)."""
    all_events: list[tuple[float, str, dict]] = []
    for model_id, path in traces.items():
        for e in _parse_events(path):
            ts = e.get("ts") or 0.0
            all_events.append((ts, model_id, e))
    all_events.sort(key=lambda x: x[0])
    tail = all_events[-limit:]

    table = Table.grid(padding=(0, 1))
    table.add_column("time", style="dim")
    table.add_column("model", style="cyan")
    table.add_column("event")
    for ts, model_id, e in tail:
        t = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "??:??:??"
        kind = e.get("type", "?")
        if kind == "tool_call":
            line = f"[{e.get('step', '?'):>3}] CALL {e.get('tool', '?')}: {_short_payload(e.get('args', ''))}"
            style = ""
        elif kind == "tool_result":
            line = f"[{e.get('step', '?'):>3}] RES  {e.get('tool', '?')}: {str(e.get('result', ''))[:80].replace(chr(10), ' ')}"
            style = "dim"
        elif kind == "note":
            line = f"NOTE [{e.get('step', '?')}]: {str(e.get('content', ''))[:120]}"
            style = "green"
        elif kind == "flag_confirmed":
            line = f"** FLAG CONFIRMED: {e.get('flag', '?')}"
            style = "bold green"
        elif kind == "finish":
            line = f"** FINISH: {e.get('status', '?')} (flag={e.get('flag','?')})"
            color = "green" if e.get("status") == "flag_found" else "yellow"
            style = f"bold {color}"
        elif kind == "bump":
            line = f"** BUMP: {str(e.get('insights', ''))[:80]}"
            style = "magenta"
        elif kind == "loop_break":
            line = f"** LOOP BREAK on {e.get('tool', '?')}"
            style = "red"
        elif kind == "error":
            line = f"** ERROR: {e.get('error', '?')}"
            style = "bold red"
        elif kind == "usage":
            line = f"usage: in={e.get('input_tokens',0)} out={e.get('output_tokens',0)} cost=${e.get('cost_usd',0):.4f}"
            style = "dim"
        else:
            line = f"{kind}: {json.dumps({k: v for k, v in e.items() if k not in ('ts', 'type')}, ensure_ascii=False)[:120]}"
            style = "dim"
        table.add_row(t, model_id, Text(line, style=style))

    header = Text(
        f"Timeline · {challenge_slug} · last {len(tail)} of {len(all_events)} events",
        style="bold",
    )
    return Group(header, Text(""), table)


@click.command()
@click.argument("challenge")
@click.option("--watch", is_flag=True, help="Live-updating refresh.")
@click.option("--timeline", is_flag=True, help="Merged chronological event feed.")
@click.option(
    "--interval", default=2.0, type=float, help="Refresh seconds for --watch."
)
@click.option("--limit", default=80, type=int, help="Max events shown in --timeline.")
@click.option("--logs-dir", default="logs", help="Directory containing trace files.")
def status(
    challenge: str,
    watch: bool,
    timeline: bool,
    interval: float,
    limit: int,
    logs_dir: str,
) -> None:
    """Show per-solver progress for a challenge.

    CHALLENGE can be the human name ('Self-Deprecation 1'), the slug
    ('Self-Deprecation_1'), or a unique prefix ('self-dep').
    """
    log_path = Path(logs_dir)
    if not log_path.exists():
        console.print(f"[red]No logs/ directory at {log_path.resolve()}[/red]")
        raise SystemExit(1)

    slug = _resolve_challenge(challenge, log_path)

    def _build():
        traces = _find_traces(slug, log_path)
        if timeline:
            return _render_timeline(slug, traces, limit=limit)
        return _render_summary(slug, traces)

    if not watch:
        console.print(_build())
        return

    with Live(_build(), refresh_per_second=4, console=console, screen=True) as live:
        try:
            while True:
                time.sleep(interval)
                live.update(_build())
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    status()
