"""ctf-pull — pre-flight: validate CTFd access + optionally download challenges.

Designed for the moment before you commit to a full `ctf-solve` run:

  ctf-pull                    # auth check + list challenges, no downloads
  ctf-pull --download         # also fetch each challenge into the session
                              # (metadata.yml + distfiles)
  ctf-pull --filter rev       # only list/download challenges in a category
  ctf-pull --names foo,bar    # only those specific names

Reads CTFd credentials the same way ctf-solve does — the active session's
.env / session.yml plus --ctfd-url / --ctfd-token / --ctfd-session flags.

Exit code reflects success:
   0  auth OK + at least one challenge fetched
   1  auth or fetch error
   2  auth OK but no challenges visible (likely scoreboard hidden / wrong CTF)
"""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table

from backend.backends import make_backend
from backend.config import Settings
from backend.session import SessionContext

console = Console()


@click.command()
@click.option("--ctfd-url", default=None, help="Override CTFd URL")
@click.option("--ctfd-token", default=None, help="Override CTFd API token")
@click.option("--ctfd-session", default=None, help="Override CTFd session cookie")
@click.option("--ctfd-csrf", default=None, help="Override CTFd CSRF nonce")
@click.option("--session", "session_name", default=None,
              help="Active session (default: resolved from .ctf-session/$CTF_SESSION/'default')")
@click.option("--download/--no-download", default=False,
              help="If set, fetch each challenge's metadata.yml + distfiles into "
                   "sessions/<NAME>/challenges/. Otherwise just list and exit.")
@click.option("--filter", "category_filter", default=None,
              help="Only include challenges whose category matches this substring "
                   "(case-insensitive).")
@click.option("--names", default=None,
              help="Comma-separated list of exact challenge names to include.")
def pull(
    ctfd_url: str | None, ctfd_token: str | None,
    ctfd_session: str | None, ctfd_csrf: str | None,
    session_name: str | None, download: bool,
    category_filter: str | None, names: str | None,
) -> None:
    """Validate CTFd access and (optionally) pull challenges into the session."""
    asyncio.run(_pull(
        ctfd_url, ctfd_token, ctfd_session, ctfd_csrf,
        session_name, download, category_filter, names,
    ))


async def _pull(
    ctfd_url: str | None, ctfd_token: str | None,
    ctfd_session: str | None, ctfd_csrf: str | None,
    session_name: str | None, download: bool,
    category_filter: str | None, names_csv: str | None,
) -> None:
    # Resolve session first so we can layer its .env on top of the global one.
    session = SessionContext.resolve(explicit=session_name)
    session.ensure_dirs()
    env_chain = session.env_files_chain()
    settings = Settings(_env_file=env_chain) if env_chain else Settings()

    # Layer credentials: CLI > env > session.yml > class default.
    overlay = session.config or {}
    if ctfd_url:
        settings.ctfd_url = ctfd_url
    elif overlay.get("ctfd_url"):
        settings.ctfd_url = overlay["ctfd_url"]
    if ctfd_token:
        settings.ctfd_token = ctfd_token
    elif overlay.get("ctfd_token"):
        settings.ctfd_token = overlay["ctfd_token"]
    if ctfd_session:
        settings.ctfd_session_cookie = ctfd_session
    elif overlay.get("ctfd_session_cookie"):
        settings.ctfd_session_cookie = overlay["ctfd_session_cookie"]
    if ctfd_csrf:
        settings.ctfd_csrf_token = ctfd_csrf

    console.print(
        f"[bold]ctf-pull[/bold]  session=[magenta]{session.name}[/magenta]  "
        f"url=[cyan]{settings.ctfd_url}[/cyan]"
    )

    # Build backend WITHOUT AttemptLog or ManualConfirm — pull is read-only.
    backend = make_backend(
        base_url=settings.ctfd_url,
        token=settings.ctfd_token,
        username=settings.ctfd_user,
        password=settings.ctfd_pass,
        session_cookie=settings.ctfd_session_cookie,
        csrf_token=settings.ctfd_csrf_token,
        attempt_log_path=None,
        manual_confirm=False,
    )

    try:
        # 1. Auth check + lightweight list.
        try:
            stubs = await backend.fetch_challenge_stubs()
        except Exception as e:
            console.print(f"[red]Auth/connectivity failed:[/red] {e}")
            sys.exit(1)

        try:
            solved = await backend.fetch_solved_names()
        except Exception:
            # Not fatal — solved set just shows as unknown.
            solved = set()

        if not stubs:
            console.print(
                "[yellow]Auth succeeded but 0 challenges visible.[/yellow] "
                "Check the scoreboard isn't hidden, the team is registered, "
                "and the CTF is live."
            )
            sys.exit(2)

        # 2. Filter as requested.
        chosen = stubs
        if category_filter:
            cf = category_filter.lower()
            chosen = [c for c in chosen if cf in (c.get("category", "") or "").lower()]
        if names_csv:
            wanted = {n.strip() for n in names_csv.split(",") if n.strip()}
            chosen = [c for c in chosen if c.get("name") in wanted]

        # 3. Display summary.
        t = Table(title=f"{len(chosen)} of {len(stubs)} challenges "
                        f"({len(solved)} solved)",
                  show_header=True, header_style="bold")
        t.add_column("Name")
        t.add_column("Category")
        t.add_column("Pts", justify="right")
        t.add_column("Solves", justify="right")
        t.add_column("Status")
        for ch in sorted(chosen, key=lambda c: c.get("name", "")):
            status = "[green]solved[/green]" if ch.get("name") in solved else ""
            t.add_row(
                ch.get("name", ""),
                ch.get("category", ""),
                str(ch.get("value", 0)),
                str(ch.get("solves", 0) or 0),
                status,
            )
        console.print(t)

        if not download:
            console.print(
                f"\nTo pull metadata + distfiles into "
                f"[cyan]{session.challenges_dir}[/cyan], rerun with "
                f"[bold]--download[/bold]."
            )
            return

        # 4. Full fetch + pull each chosen challenge.
        console.print(
            f"\n[bold]Pulling {len(chosen)} challenge(s) into[/bold] "
            f"{session.challenges_dir}/"
        )
        # fetch_all_challenges hits one detail endpoint per stub; cap by names
        # we actually want to keep this from being slow on big CTFs.
        wanted_names = {c.get("name") for c in chosen}
        full = await backend.fetch_all_challenges()
        full = [c for c in full if c.get("name") in wanted_names]

        ok = 0
        for ch in full:
            try:
                ch_dir = await backend.pull_challenge(ch, str(session.challenges_dir))
                console.print(f"  [green]✓[/green] {ch.get('name'):40s}  → {ch_dir}")
                ok += 1
            except Exception as e:
                console.print(f"  [red]✗[/red] {ch.get('name'):40s}  {e}")

        console.print(f"\n[bold]Pulled {ok}/{len(full)} challenge(s).[/bold]")
        if ok == 0:
            sys.exit(1)
    finally:
        try:
            await backend.close()
        except Exception:
            pass
