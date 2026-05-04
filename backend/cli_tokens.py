"""ctf-tokens CLI: report on persisted token / cost usage.

Reads sessions/<NAME>/logs/usage.db (one row per agent per run, written
at end-of-run by CostTracker.flush_to_log).
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from backend.session import SessionContext
from backend.usage_log import session_summary

console = Console()


def _fmt_usd(v: float) -> str:
    return f"${v:.2f}"


def _fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


@click.group()
def cli() -> None:
    """Report on persisted token + cost usage."""


@cli.command("summary")
@click.option("--session", "session_name", default=None,
              help="Session to report on (default: active session).")
def summary_cmd(session_name: str | None) -> None:
    """Total cost + by-model + by-challenge + by-run breakdown."""
    ctx = SessionContext.resolve(explicit=session_name)
    if not ctx.usage_log_path.exists():
        console.print(f"[yellow]No usage data for session "
                      f"[magenta]{ctx.name}[/magenta] yet.[/yellow]")
        sys.exit(0)
    s = session_summary(ctx.usage_log_path, ctx.name)

    console.print(f"[bold]Session:[/bold] [magenta]{ctx.name}[/magenta]   "
                  f"[bold]Total:[/bold] {_fmt_usd(s['total_cost_usd'])}   "
                  f"[bold]Tokens:[/bold] "
                  f"{_fmt_tokens(s['total_input_tokens'])} in / "
                  f"{_fmt_tokens(s['total_cache_read_tokens'])} cached / "
                  f"{_fmt_tokens(s['total_output_tokens'])} out")
    if ctx.quota_usd is not None:
        pct = (s["total_cost_usd"] / ctx.quota_usd * 100) if ctx.quota_usd else 0
        color = "red" if pct >= 100 else ("yellow" if pct >= 80 else "green")
        console.print(f"[bold]Quota:[/bold] {_fmt_usd(ctx.quota_usd)} "
                      f"([{color}]{pct:.0f}% used[/{color}])\n")
    else:
        console.print()

    for label in ("by_model", "by_challenge", "by_run"):
        rows = s[label]
        if not rows:
            continue
        title = label.replace("_", " ").title()
        t = Table(title=title, show_header=True, header_style="bold")
        t.add_column(label.split("_", 1)[1].replace("_", " ").title())
        t.add_column("Cost", justify="right")
        t.add_column("In", justify="right")
        t.add_column("Cached", justify="right")
        t.add_column("Out", justify="right")
        for r in rows:
            t.add_row(
                str(r["key"]),
                _fmt_usd(r["cost_usd"]),
                _fmt_tokens(r["input_tokens"]),
                _fmt_tokens(r["cache_read_tokens"]),
                _fmt_tokens(r["output_tokens"]),
            )
        console.print(t)


@cli.command("recent")
@click.option("--session", "session_name", default=None,
              help="Session to report on (default: active session).")
@click.option("--hours", default=24.0, type=float, help="Look-back window.")
def recent_cmd(session_name: str | None, hours: float) -> None:
    """Recent activity in the last N hours."""
    import sqlite3
    import time

    ctx = SessionContext.resolve(explicit=session_name)
    if not ctx.usage_log_path.exists():
        console.print(f"[yellow]No usage data for session "
                      f"[magenta]{ctx.name}[/magenta] yet.[/yellow]")
        sys.exit(0)

    cutoff = int(time.time() - hours * 3600)
    with sqlite3.connect(str(ctx.usage_log_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ts, run_id, agent_name, model_name, "
            " cost_usd, input_tokens, output_tokens, cache_read_tokens "
            "FROM usage WHERE session_name = ? AND ts >= ? "
            "ORDER BY ts DESC LIMIT 200",
            (ctx.name, cutoff),
        ).fetchall()

    if not rows:
        console.print(f"[yellow]No activity in the last {hours}h.[/yellow]")
        return

    t = Table(title=f"Last {hours}h — {ctx.name}", show_header=True, header_style="bold")
    t.add_column("When")
    t.add_column("Run")
    t.add_column("Agent")
    t.add_column("Model")
    t.add_column("Cost", justify="right")
    t.add_column("Tokens", justify="right")
    from datetime import datetime
    for r in rows:
        when = datetime.fromtimestamp(r["ts"]).strftime("%m-%d %H:%M")
        tok = (f"{_fmt_tokens(r['input_tokens'])}/"
               f"{_fmt_tokens(r['cache_read_tokens'])}c/"
               f"{_fmt_tokens(r['output_tokens'])}")
        t.add_row(
            when, r["run_id"][:12], r["agent_name"], r["model_name"],
            _fmt_usd(r["cost_usd"]), tok,
        )
    console.print(t)


@cli.command("by-model")
@click.argument("model")
@click.option("--session", "session_name", default=None)
def by_model_cmd(model: str, session_name: str | None) -> None:
    """Filter usage to one model — useful for "what's claude costing me?"."""
    import sqlite3

    ctx = SessionContext.resolve(explicit=session_name)
    if not ctx.usage_log_path.exists():
        sys.exit(0)
    with sqlite3.connect(str(ctx.usage_log_path)) as conn:
        conn.row_factory = sqlite3.Row
        agg = conn.execute(
            "SELECT COALESCE(SUM(cost_usd),0) AS c, COUNT(*) AS n, "
            "       COALESCE(SUM(input_tokens),0) AS i, "
            "       COALESCE(SUM(cache_read_tokens),0) AS r, "
            "       COALESCE(SUM(output_tokens),0) AS o "
            "FROM usage WHERE session_name = ? AND model_name = ?",
            (ctx.name, model),
        ).fetchone()
        rows = conn.execute(
            "SELECT challenge_name, COALESCE(SUM(cost_usd),0) AS c "
            "FROM usage WHERE session_name = ? AND model_name = ? "
            "GROUP BY challenge_name ORDER BY c DESC LIMIT 50",
            (ctx.name, model),
        ).fetchall()

    console.print(f"[bold]{model}[/bold] in [magenta]{ctx.name}[/magenta]: "
                  f"{_fmt_usd(agg['c'])} across {agg['n']} agent runs   "
                  f"({_fmt_tokens(agg['i'])} in / "
                  f"{_fmt_tokens(agg['r'])} cached / "
                  f"{_fmt_tokens(agg['o'])} out)")
    for r in rows:
        console.print(f"    {r['challenge_name'] or '(unknown)':40s}  {_fmt_usd(r['c'])}")


def tokens_main() -> None:
    cli()
