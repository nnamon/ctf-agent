"""ctf-session CLI: list / create / use / info / current / delete sessions.

A session is a directory under sessions/<NAME>/ that holds all per-CTF
state (challenges, writeups, attempt log, usage log, preserved
workspaces). See backend/session.py for the layout and resolution.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from backend.session import SESSION_DIR, SESSION_DOTFILE, SessionContext

console = Console()


def _sessions_root() -> Path:
    return Path.cwd() / SESSION_DIR


def _list_sessions() -> list[str]:
    root = _sessions_root()
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


@click.group()
def cli() -> None:
    """Manage ctf-agent sessions (per-CTF state isolation)."""


@cli.command("list")
def list_cmd() -> None:
    """List all known sessions and which one is currently active."""
    active = SessionContext.resolve().name
    sessions = _list_sessions()
    if not sessions:
        console.print("[yellow]No sessions yet.[/yellow]  "
                      "Create one with `ctf-session create <name>`.")
        return
    for s in sessions:
        marker = " [bold green]*[/bold green]" if s == active else "  "
        console.print(f"{marker} {s}")
    console.print(f"\nActive: [magenta]{active}[/magenta]")


@cli.command("create")
@click.argument("name")
@click.option("--ctfd-url", default=None, help="Pre-fill ctfd_url in session.yml.")
@click.option("--quota-usd", default=None, type=float,
              help="Pre-fill quota_usd in session.yml.")
def create_cmd(name: str, ctfd_url: str | None, quota_usd: float | None) -> None:
    """Create a new session directory."""
    root = _sessions_root() / name
    if root.exists():
        console.print(f"[red]Session {name!r} already exists at {root}.[/red]")
        sys.exit(1)
    ctx = SessionContext(name=name, root=root)
    ctx.ensure_dirs()
    if ctfd_url or quota_usd is not None:
        import yaml
        cfg: dict = {}
        if ctfd_url:
            cfg["ctfd_url"] = ctfd_url
        if quota_usd is not None:
            cfg["quota_usd"] = quota_usd
        (root / "session.yml").write_text(yaml.safe_dump(cfg, sort_keys=False))
    console.print(f"[green]Created session[/green] [magenta]{name}[/magenta] at {root}")
    console.print(f"  Use it: `ctf-session use {name}` "
                  f"(or pass --session {name} per-invocation)")


@cli.command("use")
@click.argument("name")
def use_cmd(name: str) -> None:
    """Set the active session by writing .ctf-session in the cwd."""
    root = _sessions_root() / name
    if not root.exists():
        console.print(f"[red]Session {name!r} doesn't exist.[/red]  "
                      f"Create it: `ctf-session create {name}`")
        sys.exit(1)
    Path(SESSION_DOTFILE).write_text(name + "\n")
    console.print(f"[green]Active session set to[/green] [magenta]{name}[/magenta]")
    console.print(f"  ({SESSION_DOTFILE} written to {Path.cwd()})")


@cli.command("current")
def current_cmd() -> None:
    """Print the currently active session name."""
    ctx = SessionContext.resolve()
    console.print(ctx.name)


@cli.command("info")
@click.argument("name", required=False)
def info_cmd(name: str | None) -> None:
    """Show stats for a session (defaults to the active one)."""
    if name is None:
        ctx = SessionContext.resolve()
    else:
        root = _sessions_root() / name
        if not root.exists():
            console.print(f"[red]Session {name!r} doesn't exist.[/red]")
            sys.exit(1)
        ctx = SessionContext(name=name, root=root)
        ctx._load_overlay()  # noqa: SLF001 — internal API is fine here

    console.print(f"[bold]Session:[/bold] [magenta]{ctx.name}[/magenta]")
    console.print(f"  Path: {ctx.root}")

    challenges = list(ctx.challenges_dir.glob("*/metadata.yml")) if ctx.challenges_dir.exists() else []
    writeups = list(ctx.writeups_dir.glob("*.md")) if ctx.writeups_dir.exists() else []
    runs = list(ctx.runs_dir.iterdir()) if ctx.runs_dir.exists() else []
    console.print(f"  Challenges pulled: {len(challenges)}")
    console.print(f"  Writeups:          {len(writeups)}")
    console.print(f"  Runs preserved:    {len(runs)}")

    # Cost summary from usage.db, if it exists.
    if ctx.usage_log_path.exists():
        from backend.usage_log import session_summary
        s = session_summary(ctx.usage_log_path, ctx.name)
        console.print(f"  Total cost:        ${s['total_cost_usd']:.2f}")
        if ctx.quota_usd is not None:
            pct = (s["total_cost_usd"] / ctx.quota_usd * 100) if ctx.quota_usd else 0
            color = "red" if pct >= 100 else ("yellow" if pct >= 80 else "green")
            console.print(f"  Quota:             ${ctx.quota_usd:.2f} "
                          f"([{color}]{pct:.0f}% used[/{color}])")

    # Attempts.
    if ctx.attempt_log_path.exists():
        import sqlite3
        try:
            with sqlite3.connect(str(ctx.attempt_log_path)) as conn:
                row = conn.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN status IN ('correct','already_solved') THEN 1 ELSE 0 END) "
                    "FROM attempts"
                ).fetchone()
                console.print(f"  Flag attempts:     {row[0]} ({row[1] or 0} correct)")
        except sqlite3.OperationalError:
            pass


@cli.command("delete")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def delete_cmd(name: str, yes: bool) -> None:
    """Delete a session directory and ALL its contents."""
    root = _sessions_root() / name
    if not root.exists():
        console.print(f"[yellow]Session {name!r} doesn't exist.[/yellow]")
        sys.exit(0)
    if name == "default" and not yes:
        console.print(f"[red]Refusing to delete 'default' without --yes.[/red]")
        sys.exit(1)
    if not yes:
        console.print(f"[red]This will permanently delete {root}[/red]")
        if not click.confirm("Proceed?", default=False):
            return
    import shutil
    shutil.rmtree(root)
    console.print(f"[green]Deleted[/green] {root}")


def session_main() -> None:
    cli()
