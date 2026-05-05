"""Click CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings
from backend.models import DEFAULT_MODELS

console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiodocker").setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%X"))
    logging.basicConfig(level=level, handlers=[handler], force=True)


@click.command()
@click.option("--ctfd-url", default=None, help="CTFd URL (overrides .env)")
@click.option("--ctfd-token", default=None, help="CTFd API token (overrides .env)")
@click.option("--ctfd-session", default=None,
              help="CTFd session-cookie value (overrides .env CTFD_SESSION_COOKIE). "
                   "Use when API token is unavailable, e.g. behind an email-confirm gate.")
@click.option("--ctfd-csrf", default=None,
              help="Pre-extracted CTFd CSRF nonce (overrides .env CTFD_CSRF_TOKEN). "
                   "Optional — backend scrapes /challenges if omitted. Bound to the session cookie.")
@click.option("--image", default="ctf-sandbox", help="Docker sandbox image name")
@click.option("--models", multiple=True, help="Model specs (default: all configured)")
@click.option("--challenge", default=None, help="Solve a single challenge directory")
@click.option("--challenges-dir", default="challenges", help="Directory for challenge files")
@click.option("--no-submit", is_flag=True, help="Dry run — don't submit flags")
@click.option("--coordinator-model", default=None, help="Model for coordinator (default: gpt-5.5 for codex, claude-opus-4-7 for claude)")
@click.option("--coordinator", default="codex", type=click.Choice(["claude", "codex"]), help="Coordinator backend (default: codex)")
@click.option("--max-challenges", default=None, type=int,
              help="Max challenges solved concurrently. When omitted, the "
                   "session's MAX_CONCURRENT_CHALLENGES env var (or its "
                   "10-default) is used. Set this to 1 for platforms with "
                   "a per-account workspace lock (pwn.college).")
@click.option("--msg-port", default=13337, type=int,
              help="Dashboard / operator-message port. Default 13337 — falls "
                   "back to an auto-picked port if 13337 is already in use. "
                   "Pass 0 to force auto-pick.")
@click.option("--msg-host", default="0.0.0.0",
              help="Dashboard bind address (default 0.0.0.0 = reachable on "
                   "LAN/VPN). Use 127.0.0.1 for localhost-only — there is "
                   "no auth, anyone who can reach the port can kill swarms.")
@click.option("--no-writeup", is_flag=True, help="Skip the post-mortem writeup after each solve")
@click.option("--writeup-model", default="claude-opus-4-7", help="Model used to generate the post-mortem writeup")
@click.option("--session", "session_name", default=None,
              help="Active session name. Resolves to sessions/<NAME>/ for "
                   "challenges, writeups, logs, runs. Falls back to "
                   "$CTF_SESSION, then .ctf-session dotfile, then 'default'. "
                   "Use ctf-session create/use to manage sessions.")
@click.option("--attempt-log-path", default=None,
              help="SQLite file persisting flag attempts. Default: "
                   "sessions/<NAME>/logs/attempts.db (auto-derived from session).")
@click.option("--no-attempt-log", is_flag=True,
              help="Disable persistent attempt logging (default: enabled).")
@click.option("--confirm-flags", "confirm_flags", is_flag=True,
              help="Pause for stdin operator approval before each flag "
                   "submission. Useful when penalties are expensive or "
                   "you're vetting a new model. Denies fall straight back "
                   "to the solver as 'incorrect — operator-denied' without "
                   "burning a real attempt. Requires a TTY.")
@click.option("--context", "context_files", multiple=True, type=click.Path(),
              help="Attach a file to the solver as prior-chain context. "
                   "Mounted read-only at /challenge/context/<basename>; text-ish "
                   "files (UTF-8, <32 KB) are also embedded in the system prompt. "
                   "Repeatable. Used by an external orchestrator to chain "
                   "challenges (e.g. pass writeups + binaries from prior solves).")
@click.option("--preserve-workspace", "preserve_workspace", is_flag=True,
              help="Save each solver's /challenge/workspace to "
                   "runs/<RUN_ID>/<challenge_slug>/<model_spec>/workspace/ before "
                   "shutdown. Lets an orchestrator pull artifacts the solver "
                   "produced (unpacked binaries, decryption keys, intermediate "
                   "scripts) and feed them to the next challenge via --context.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(
    ctfd_url: str | None,
    ctfd_token: str | None,
    ctfd_session: str | None,
    ctfd_csrf: str | None,
    image: str,
    models: tuple[str, ...],
    challenge: str | None,
    challenges_dir: str,
    no_submit: bool,
    coordinator_model: str | None,
    coordinator: str,
    max_challenges: int,
    msg_port: int,
    msg_host: str,
    no_writeup: bool,
    writeup_model: str,
    session_name: str | None,
    attempt_log_path: str | None,
    no_attempt_log: bool,
    confirm_flags: bool,
    context_files: tuple[str, ...],
    preserve_workspace: bool,
    verbose: bool,
) -> None:
    """CTF Agent — multi-model solver swarm.

    Run without --challenge to start the full coordinator (Ctrl+C to stop).
    """
    _setup_logging(verbose)

    # Resolve the active session FIRST so we can layer the session's .env
    # on top of the global .env when constructing Settings.
    from backend.session import SessionContext
    session = SessionContext.resolve(explicit=session_name)
    session.ensure_dirs()

    env_chain = session.env_files_chain()
    if env_chain:
        settings = Settings(sandbox_image=image, _env_file=env_chain)
    else:
        settings = Settings(sandbox_image=image)
    settings.session_name = session.name

    if ctfd_url:
        settings.ctfd_url = ctfd_url
    if ctfd_token:
        settings.ctfd_token = ctfd_token
    if ctfd_session:
        settings.ctfd_session_cookie = ctfd_session
    if ctfd_csrf:
        settings.ctfd_csrf_token = ctfd_csrf

    # session.yml overlay — fills in any field that wasn't set by CLI/env.
    # Read order: CLI flag > env var > session.yml > class default.
    overlay = session.config or {}
    if not ctfd_url and overlay.get("ctfd_url"):
        settings.ctfd_url = overlay["ctfd_url"]
    if not ctfd_token and overlay.get("ctfd_token"):
        settings.ctfd_token = overlay["ctfd_token"]
    if not ctfd_session and overlay.get("ctfd_session_cookie"):
        settings.ctfd_session_cookie = overlay["ctfd_session_cookie"]

    # Only override the env-configured concurrency if the operator
    # explicitly passed --max-challenges. Otherwise keep what was loaded
    # from the session's .env (e.g. MAX_CONCURRENT_CHALLENGES=1 for
    # platforms with a per-account workspace lock like pwn.college).
    if max_challenges is not None:
        settings.max_concurrent_challenges = max_challenges
    # Resolve the effective value used downstream — banner, capacity caps.
    effective_max = settings.max_concurrent_challenges
    if no_attempt_log:
        settings.attempt_log_path = None
    elif attempt_log_path:
        settings.attempt_log_path = attempt_log_path
    else:
        settings.attempt_log_path = str(session.attempt_log_path)
    # Usage-log path is always session-scoped; no CLI override (yet).
    settings.usage_log_path = str(session.usage_log_path)
    # Quota: sourced from session.yml — None means no cap.
    settings.quota_usd = session.quota_usd
    settings.manual_confirm = confirm_flags

    # Orchestration: --context FILE (repeatable) and --preserve-workspace.
    # Workspace preserve root lives inside the session dir so artifacts
    # stay scoped to the engagement.
    settings.context_files = list(context_files)
    if preserve_workspace:
        from backend.sandbox import RUN_ID
        # Slug filled in per-challenge inside DockerSandbox.from_settings.
        settings.preserve_workspace_to = str(session.runs_dir / RUN_ID)

    # If --challenges-dir wasn't overridden (still the default 'challenges'),
    # use the session's challenges dir instead.
    if challenges_dir == "challenges":
        challenges_dir = str(session.challenges_dir)

    # `--models` is multiple=True; pass it once per model spec, e.g.
    # `--models codex/gpt-5.5 --models codex/gpt-5.4-mini`. Comma-
    # separated single value is rejected so a typo doesn't silently
    # become one malformed spec that the provider then rejects with
    # an unhelpful "model not supported" error.
    for m in models:
        if "," in m:
            console.print(
                f"[red]Invalid --models value {m!r}: pass --models once per "
                "spec instead of comma-separating.[/red]"
            )
            sys.exit(2)
    model_specs = list(models) if models else list(DEFAULT_MODELS)

    from backend.sandbox import RUN_ID
    console.print("[bold]CTF Agent v2[/bold]")
    console.print(f"  Session: [magenta]{session.name}[/magenta]   "
                  f"[dim]({session.root})[/dim]")
    console.print(f"  Run ID: [cyan]{RUN_ID}[/cyan]   "
                  f"[dim](docker ps --filter label=ctf-agent.run={RUN_ID})[/dim]")
    console.print(f"  CTFd: {settings.ctfd_url}")
    console.print(f"  Models: {', '.join(model_specs)}")
    console.print(f"  Image: {settings.sandbox_image}")
    console.print(f"  Max challenges: {effective_max}")
    console.print(f"  Attempt log: {settings.attempt_log_path or '(disabled)'}")
    console.print()

    if challenge:
        asyncio.run(_run_single(settings, challenge, model_specs, no_submit, effective_max, no_writeup, writeup_model))
    else:
        asyncio.run(_run_coordinator(settings, model_specs, challenges_dir, no_submit, coordinator_model, coordinator, effective_max, msg_port, msg_host, no_writeup, writeup_model))


async def _run_single(
    settings: Settings,
    challenge_dir: str,
    model_specs: list[str],
    no_submit: bool,
    max_challenges: int,
    no_writeup: bool = False,
    writeup_model: str = "claude-opus-4-7",
) -> None:
    """Run a single challenge with a swarm."""
    import time

    from backend.agents.swarm import ChallengeSwarm
    from backend.cost_tracker import CostTracker
    from backend.backends import make_backend
    from backend.prompts import ChallengeMeta
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore

    max_containers = max_challenges * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()

    challenge_path = Path(challenge_dir)
    meta_path = challenge_path / "metadata.yml"
    if not meta_path.exists():
        console.print(f"[red]No metadata.yml found in {challenge_dir}[/red]")
        sys.exit(1)

    meta = ChallengeMeta.from_yaml(meta_path)
    console.print(f"[bold]Challenge:[/bold] {meta.name} ({meta.category}, {meta.value} pts)")

    ctfd = make_backend(
        kind=getattr(settings, "backend_kind", None) or None,
        base_url=settings.ctfd_url,
        token=settings.ctfd_token,
        username=settings.ctfd_user,
        password=settings.ctfd_pass,
        session_cookie=getattr(settings, "ctfd_session_cookie", ""),
        csrf_token=getattr(settings, "ctfd_csrf_token", ""),
        attempt_log_path=getattr(settings, "attempt_log_path", None),
        manual_confirm=getattr(settings, "manual_confirm", False),
        pwncollege_dojos=getattr(settings, "pwncollege_dojos", []) or [],
    )
    cost_tracker = CostTracker.for_session(settings)

    # Build the multi-env registry. Same shape as the coordinator path —
    # registers `local` per-solver via fork(), shares remote envs (pwn.
    # college SSH master) here. For single-challenge runs the meta is
    # already loaded, so we can bind the active challenge eagerly.
    from backend.agents.coordinator_core import _bind_challenge_to_envs
    from backend.exec_envs.builder import build_env_registry
    from backend.session import SessionContext
    sess = SessionContext.resolve(
        explicit=getattr(settings, "session_name", None) or None
    )
    env_registry = build_env_registry(
        settings=settings, session=sess, backend=ctfd, sandbox=None,
    )
    if env_registry.names:
        _bind_challenge_to_envs(env_registry, meta)
    else:
        env_registry = None

    swarm = ChallengeSwarm(
        challenge_dir=str(challenge_path),
        meta=meta,
        ctfd=ctfd,
        cost_tracker=cost_tracker,
        settings=settings,
        model_specs=model_specs,
        no_submit=no_submit,
        env_registry=env_registry,
    )

    t0 = time.monotonic()
    try:
        result = await swarm.run()
        duration_s = time.monotonic() - t0
        from backend.solver_base import FLAG_FOUND
        if result and result.status == FLAG_FOUND:
            console.print(f"\n[bold green]FLAG FOUND:[/bold green] {result.flag}")
        else:
            console.print("\n[bold red]No flag found.[/bold red]")

        console.print("\n[bold]Cost Summary:[/bold]")
        for agent_name in cost_tracker.by_agent:
            console.print(f"  {agent_name}: {cost_tracker.format_usage(agent_name)}")
        console.print(f"  [bold]Total: ${cost_tracker.total_cost_usd:.2f}[/bold]")

        if not no_writeup and result and result.status == FLAG_FOUND:
            await _generate_writeup(
                swarm, result, cost_tracker, duration_s, writeup_model, ctfd, settings,
            )
        # Persist the preserved-workspace path so an orchestrator can find
        # the artifacts via the AttemptLog SQL query.
        if (
            getattr(settings, "preserve_workspace_to", "")
            and result and result.status == FLAG_FOUND
            and result.flag
        ):
            _record_workspace_path(ctfd, swarm, result, settings)
        # Persist token usage to the session's usage.db.
        from backend.sandbox import RUN_ID
        cost_tracker.flush_to_log(
            db_path=getattr(settings, "usage_log_path", None),
            run_id=RUN_ID,
            session_name=getattr(settings, "session_name", "default"),
        )
    finally:
        await ctfd.close()


def _record_workspace_path(ctfd, swarm, winner_result, settings) -> None:
    """If --preserve-workspace was on, attach the winner's preserved
    workspace path to the AttemptLog row for later orchestrator use."""
    if not hasattr(ctfd, "set_workspace_path"):
        return
    try:
        winner_spec = swarm.winner_spec or ""
        if not winner_spec:
            return
        # Mirror the path layout from DockerSandbox.from_settings:
        #   <preserve_root>/<challenge_slug>/<model_spec>/workspace
        from pathlib import Path
        slug = Path(swarm.challenge_dir).name or "challenge"
        path = Path(settings.preserve_workspace_to) / slug / winner_spec / "workspace"
        if path.exists():
            ctfd.set_workspace_path(swarm.meta.name, winner_result.flag, str(path))
    except Exception:
        # Persistence is best-effort — never let a logging failure break a solve.
        pass


async def _generate_writeup(swarm, winner_result, cost_tracker, duration_s, model: str, ctfd=None, settings=None) -> None:
    """Generate a post-mortem writeup for a finished swarm."""
    from pathlib import Path

    from backend.agents.postmortem import generate_writeup

    winner_spec = swarm.winner_spec or "unknown"
    sibling_traces: list[tuple[str, Path]] = []
    for spec, solver in swarm.solvers.items():
        if spec == winner_spec:
            continue
        tracer = getattr(solver, "tracer", None)
        path = Path(tracer.path) if tracer and getattr(tracer, "path", None) else None
        if path:
            sibling_traces.append((spec, path))

    # Pick a session-scoped output dir if available; this mirrors the
    # session resolution done in main(). The default arg in
    # generate_writeup is the legacy top-level "writeups/".
    from backend.session import SessionContext
    session_for_writeup = SessionContext.resolve()
    out_dir = session_for_writeup.writeups_dir

    console.print("\n[dim]Generating post-mortem writeup...[/dim]")
    out = await generate_writeup(
        meta=swarm.meta,
        winner_result=winner_result,
        winner_spec=winner_spec,
        sibling_traces=sibling_traces,
        cost_usd=cost_tracker.total_cost_usd,
        duration_s=duration_s,
        out_dir=out_dir,
        model=model,
        settings=settings,
    )
    if out:
        console.print(f"[green]Writeup:[/green] {out}")
        # Attach to the AttemptLog row so an orchestrator can locate the
        # writeup for chain-sibling --context attachments without
        # fs-walking writeups/.
        if ctfd is not None and hasattr(ctfd, "set_writeup_path") and winner_result.flag:
            try:
                ctfd.set_writeup_path(swarm.meta.name, winner_result.flag, str(out))
            except Exception:
                pass
    else:
        console.print("[yellow]Writeup generation skipped or failed (see logs).[/yellow]")


async def _run_coordinator(
    settings: Settings,
    model_specs: list[str],
    challenges_dir: str,
    no_submit: bool,
    coordinator_model: str | None,
    coordinator_backend: str,
    max_challenges: int,
    msg_port: int = 13337,
    msg_host: str = "0.0.0.0",
    no_writeup: bool = False,
    writeup_model: str = "claude-opus-4-7",
) -> None:
    """Run the full coordinator (continuous until Ctrl+C)."""
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore

    max_containers = max_challenges * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()
    console.print(f"[bold]Starting coordinator ({coordinator_backend}, Ctrl+C to stop)...[/bold]\n")

    if coordinator_backend == "codex":
        from backend.agents.codex_coordinator import run_codex_coordinator
        results = await run_codex_coordinator(
            settings=settings,
            model_specs=model_specs,
            challenges_root=challenges_dir,
            no_submit=no_submit,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
            msg_host=msg_host,
            no_writeup=no_writeup,
            writeup_model=writeup_model,
        )
    else:
        from backend.agents.claude_coordinator import run_claude_coordinator
        results = await run_claude_coordinator(
            settings=settings,
            model_specs=model_specs,
            challenges_root=challenges_dir,
            no_submit=no_submit,
            coordinator_model=coordinator_model,
            msg_port=msg_port,
            msg_host=msg_host,
            no_writeup=no_writeup,
            writeup_model=writeup_model,
        )

    console.print("\n[bold]Final Results:[/bold]")
    for challenge, data in results.get("results", {}).items():
        console.print(f"  {challenge}: {data.get('flag', 'no flag')}")
    console.print(f"\n[bold]Total cost: ${results.get('total_cost_usd', 0):.2f}[/bold]")


def _parse_age(s: str) -> float:
    """Parse a duration like '6h', '30m', '1d', '2.5h' into hours."""
    s = s.strip().lower()
    if not s:
        raise click.BadParameter("empty age")
    unit = s[-1]
    try:
        n = float(s[:-1] if unit in "hmds" else s)
    except ValueError as e:
        raise click.BadParameter(f"can't parse age {s!r}") from e
    if unit == "h" or unit not in "hmds":
        return n
    if unit == "m":
        return n / 60
    if unit == "d":
        return n * 24
    if unit == "s":
        return n / 3600
    raise click.BadParameter(f"unknown unit {unit!r}")


@click.command()
@click.option("--run", "run_id", default=None,
              help="Delete containers for a specific run-id (e.g. 'a3f4b1c2d5e6'). "
                   "Find it in the startup banner or via "
                   "`docker ps --filter label=ctf-agent.run`.")
@click.option("--age", "age", default=None,
              help="Delete containers older than this duration (e.g. '6h', '30m', '1d'). "
                   "Useful for mopping up SIGKILL-survivor containers without "
                   "disturbing concurrent runs.")
@click.option("--all", "all_", is_flag=True,
              help="Nuke every ctf-agent-labeled container regardless of run-id "
                   "or age. Replicates the pre-run-id startup behaviour. Use only "
                   "when no other ctf-agent processes are running.")
def cleanup(run_id: str | None, age: str | None, all_: bool) -> None:
    """Reap ctf-agent sandbox containers.

    Pass exactly one of --run / --age / --all. Without arguments, prints
    a summary of currently-tagged containers grouped by run-id.
    """
    import asyncio
    from backend.sandbox import (
        cleanup_all_containers,
        cleanup_run_containers,
        cleanup_stale_containers,
        CONTAINER_LABEL,
        RUN_LABEL,
    )

    chosen = sum(bool(x) for x in (run_id, age, all_))
    if chosen > 1:
        console.print("[red]Pick only one of --run / --age / --all.[/red]")
        sys.exit(2)

    if chosen == 0:
        # Default: list current containers grouped by run-id.
        async def _list() -> None:
            import aiodocker
            docker = aiodocker.Docker()
            try:
                containers = await docker.containers.list(
                    all=True, filters={"label": [CONTAINER_LABEL]}
                )
                if not containers:
                    console.print("No ctf-agent containers found.")
                    return
                by_run: dict[str, list[str]] = {}
                for c in containers:
                    info = await c.show()
                    rid = info.get("Config", {}).get("Labels", {}).get(RUN_LABEL, "(unlabeled)")
                    by_run.setdefault(rid, []).append(info["Id"][:12])
                for rid, ids in sorted(by_run.items()):
                    console.print(f"[cyan]{rid}[/cyan]: {len(ids)} container(s)")
                    for cid in ids[:5]:
                        console.print(f"    {cid}")
                    if len(ids) > 5:
                        console.print(f"    ... and {len(ids) - 5} more")
            finally:
                await docker.close()
        asyncio.run(_list())
        return

    if all_:
        n = asyncio.run(cleanup_all_containers())
        console.print(f"[green]Deleted {n} container(s).[/green]")
        return

    if run_id:
        n = asyncio.run(cleanup_run_containers(run_id))
        console.print(f"[green]Deleted {n} container(s) from run {run_id}.[/green]")
        return

    if age:
        hours = _parse_age(age)
        n = asyncio.run(cleanup_stale_containers(older_than_hours=hours))
        console.print(f"[green]Deleted {n} container(s) older than {age}.[/green]")
        return


@click.command()
@click.argument("message")
@click.option("--port", default=13337, type=int, help="Coordinator message port (matches ctf-solve --msg-port default)")
@click.option("--host", default="127.0.0.1", help="Coordinator host")
def msg(message: str, port: int, host: str) -> None:
    """Send a message to the running coordinator."""
    import json
    import urllib.request

    body = json.dumps({"message": message}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/msg",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            console.print(f"[green]Sent:[/green] {data.get('queued', message[:200])}")
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")
        console.print("Is the coordinator running?")
        sys.exit(1)


if __name__ == "__main__":
    main()
