"""Shared coordinator event loop — used by both Claude SDK and Codex coordinators."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

from backend.config import Settings
from backend.cost_tracker import CostTracker
from backend.backends import Backend, make_backend
from backend.deps import CoordinatorDeps
from backend.models import DEFAULT_MODELS
from backend.poller import CTFdPoller
from backend.prompts import ChallengeMeta

logger = logging.getLogger(__name__)

# Callable type for a coordinator turn: (message) -> None
TurnFn = Callable[[str], Coroutine[Any, Any, None]]


def build_deps(
    settings: Settings,
    model_specs: list[str] | None = None,
    challenges_root: str = "challenges",
    no_submit: bool = False,
    challenge_dirs: dict[str, str] | None = None,
    challenge_metas: dict[str, ChallengeMeta] | None = None,
    no_writeup: bool = False,
    writeup_model: str = "claude-opus-4-7",
) -> tuple[Backend, CostTracker, CoordinatorDeps]:
    """Create the backend, cost tracker, and coordinator deps."""
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
        pwnablekr_user_id=getattr(settings, "pwnablekr_user_id", ""),
    )
    cost_tracker = CostTracker.for_session(settings)
    specs = model_specs or list(DEFAULT_MODELS)
    Path(challenges_root).mkdir(parents=True, exist_ok=True)

    # Build the multi-env registry. Solvers consume this via
    # SolverDeps.env_registry. The local Docker env is registered per-
    # solver (so each solver gets its own container); only shared remote
    # envs (pwn.college SSH) live in the coordinator-level registry.
    from backend.exec_envs.builder import build_env_registry
    from backend.session import SessionContext
    sess = SessionContext.resolve(
        explicit=getattr(settings, "session_name", None) or None
    )
    env_registry = build_env_registry(
        settings=settings,
        session=sess,
        backend=ctfd,
        sandbox=None,  # solver-owned; no shared local sandbox here
    )

    deps = CoordinatorDeps(
        ctfd=ctfd,
        cost_tracker=cost_tracker,
        settings=settings,
        model_specs=specs,
        challenges_root=challenges_root,
        no_submit=no_submit,
        max_concurrent_challenges=getattr(settings, "max_concurrent_challenges", 10),
        challenge_dirs=challenge_dirs or {},
        challenge_metas=challenge_metas or {},
        no_writeup=no_writeup,
        writeup_model=writeup_model,
        env_registry=env_registry if env_registry.names else None,
    )

    # Pre-load already-pulled challenges
    for d in Path(challenges_root).iterdir():
        meta_path = d / "metadata.yml"
        if meta_path.exists():
            meta = ChallengeMeta.from_yaml(meta_path)
            if meta.name not in deps.challenge_dirs:
                deps.challenge_dirs[meta.name] = str(d)
                deps.challenge_metas[meta.name] = meta

    return ctfd, cost_tracker, deps


async def run_event_loop(
    deps: CoordinatorDeps,
    ctfd: Backend,
    cost_tracker: CostTracker,
    turn_fn: TurnFn,
    status_interval: int = 60,
) -> dict[str, Any]:
    """Run the shared coordinator event loop.

    Args:
        deps: Coordinator dependencies (shared state).
        ctfd: CTFd client (for poller).
        cost_tracker: Cost tracker.
        turn_fn: Async function that sends a message to the coordinator LLM.
        status_interval: Seconds between status updates.
    """
    poller = CTFdPoller(ctfd=ctfd, interval_s=5.0)
    await poller.start()
    # Expose to deps so the dashboard can read the full challenge list
    # (not just the spawned ones) for /api/status.
    deps.poller = poller

    # Live web dashboard. Replaces the previous hand-rolled HTTP server,
    # but keeps /msg backward compat so the existing ctf-msg CLI still works.
    from backend.sandbox import RUN_ID
    from backend.web import start_dashboard
    try:
        dash_runner, dash_port = await start_dashboard(
            deps, RUN_ID, port=deps.msg_port, host=deps.msg_host,
        )
        deps.event_hub = dash_runner.app["hub"]
    except OSError as e:
        logger.warning("Could not start dashboard: %s", e)
        dash_runner = None
        deps.event_hub = None

    logger.info(
        "Coordinator starting (run %s): %d models, %d challenges, %d solved",
        RUN_ID,
        len(deps.model_specs),
        len(poller.known_challenges),
        len(poller.known_solved),
    )
    if dash_runner is not None:
        logger.info("Dashboard:  http://%s:%d/", deps.msg_host, dash_port)
        if deps.msg_host == "0.0.0.0":
            logger.warning(
                "Dashboard bound to 0.0.0.0 — accessible to anyone on this "
                "machine's LAN/VPN with no auth. Bind 127.0.0.1 via --msg-host "
                "before exposing to untrusted networks."
            )

    from backend.agents.coordinator_core import _is_skipped
    unsolved = {
        n for n in (poller.known_challenges - poller.known_solved)
        if not _is_skipped(deps, n)
    }
    initial_msg = (
        f"CTF is LIVE. {len(poller.known_challenges)} challenges, "
        f"{len(poller.known_solved)} solved.\n"
        f"Unsolved: {sorted(unsolved) if unsolved else 'NONE'}\n"
        f"Spawn capacity: {deps.max_concurrent_challenges} concurrent "
        f"swarms max. Spawn at most that many at once — `spawn_swarm` "
        f"returns 'At capacity' once the cap is hit, so issuing more "
        f"parallel calls per turn just wastes them. As swarms finish "
        f"(`SOLVER FINISHED:` events) you'll get more capacity.\n"
        f"Fetch challenges and spawn swarms for the highest-priority "
        f"unsolved (start with the lowest-point / easiest)."
    )

    try:
        await turn_fn(initial_msg)

        # Auto-spawn swarms for unsolved challenges if coordinator LLM didn't
        await _auto_spawn_unsolved(deps, poller)

        last_status = asyncio.get_event_loop().time()

        while True:
            events = []
            evt = await poller.get_event(timeout=5.0)
            if evt:
                events.append(evt)
            events.extend(poller.drain_events())

            # Auto-kill swarms for solved challenges, BUT only when the
            # solve came from outside our own swarm. If swarm.confirmed_flag
            # is already set, our solver was the one that scored — let
            # swarm.run()'s natural FLAG_FOUND path return cleanly so
            # _run_and_cleanup() can fire the post-mortem. Killing in
            # that window races with the just-completed solver task and
            # cancels it before swarm.run() reads its FLAG_FOUND result,
            # which silently drops the writeup phase.
            for evt in events:
                if evt.kind != "challenge_solved":
                    continue
                if evt.challenge_name not in deps.swarms:
                    continue
                swarm = deps.swarms[evt.challenge_name]
                if swarm.cancel_event.is_set():
                    continue
                if swarm.confirmed_flag:
                    # Our solver got it. Don't interrupt — the natural
                    # completion path is already in flight.
                    logger.debug(
                        "Skipping auto-kill for %s: own solver confirmed flag",
                        evt.challenge_name,
                    )
                    continue
                swarm.kill()
                logger.info("Auto-killed swarm for: %s", evt.challenge_name)

            parts: list[str] = []
            for evt in events:
                if evt.kind == "new_challenge":
                    parts.append(f"NEW CHALLENGE: '{evt.challenge_name}' appeared. Spawn a swarm.")
                    if deps.event_hub:
                        deps.event_hub.broadcast(
                            "new_challenge", challenge=evt.challenge_name,
                            text=f"new challenge: {evt.challenge_name}",
                        )
                    # Auto-spawn for new challenges
                    await _auto_spawn_one(deps, evt.challenge_name)
                elif evt.kind == "challenge_solved":
                    parts.append(f"SOLVED: '{evt.challenge_name}' — swarm auto-killed.")
                    if deps.event_hub:
                        deps.event_hub.broadcast(
                            "challenge_correct", challenge=evt.challenge_name,
                            text=f"correct: {evt.challenge_name}",
                        )

            # Detect finished swarms
            for name, task in list(deps.swarm_tasks.items()):
                if task.done():
                    parts.append(f"SOLVER FINISHED: Swarm for '{name}' completed. Check results or retry.")
                    if deps.event_hub:
                        deps.event_hub.broadcast(
                            "swarm_finished", challenge=name,
                            text=f"swarm finished: {name}",
                        )
                    deps.swarm_tasks.pop(name, None)

            # Drain solver-to-coordinator messages
            while True:
                try:
                    solver_msg = deps.coordinator_inbox.get_nowait()
                    parts.append(f"SOLVER MESSAGE: {solver_msg}")
                except asyncio.QueueEmpty:
                    break

            # Drain operator messages
            while True:
                try:
                    op_msg = deps.operator_inbox.get_nowait()
                    parts.append(f"OPERATOR MESSAGE: {op_msg}")
                    logger.info("Operator message: %s", op_msg[:200])
                except asyncio.QueueEmpty:
                    break

            # Periodic status update — only when there are active swarms or other events
            now = asyncio.get_event_loop().time()
            if now - last_status >= status_interval:
                last_status = now
                # Persist any cost accrued since the previous tick. Lets
                # a coordinator restart resume with an accurate session
                # total instead of forgetting the in-flight bill.
                try:
                    from backend.sandbox import RUN_ID
                    cost_tracker.flush_to_log(
                        db_path=getattr(deps.settings, "usage_log_path", None),
                        run_id=RUN_ID,
                        session_name=getattr(deps.settings, "session_name", "default"),
                    )
                except Exception as e:
                    logger.warning("usage_log periodic flush failed: %s", e)
                from backend.agents.coordinator_core import _is_skipped
                active = [n for n, t in deps.swarm_tasks.items() if not t.done()]
                solved_set = poller.known_solved
                unsolved_set = {
                    n for n in (poller.known_challenges - solved_set)
                    if not _is_skipped(deps, n)
                }
                status_line = (
                    f"STATUS: {len(solved_set)} solved, {len(unsolved_set)} unsolved, "
                    f"{len(active)} active swarms. Cost: ${cost_tracker.total_cost_usd:.2f}"
                )
                # Send to coordinator if there's something happening OR if
                # the queue is idle with unsolved work — otherwise the LLM
                # has no nudge to spawn the next batch when all current
                # swarms have finished, and the run silently stalls.
                if active or parts or unsolved_set:
                    if not active and unsolved_set:
                        status_line += (
                            f"\nIDLE — no active swarms but {len(unsolved_set)} "
                            f"challenges remain. Spawn the next "
                            f"{deps.max_concurrent_challenges} highest-priority unsolved."
                        )
                    parts.append(status_line)
                else:
                    logger.info(f"Event -> coordinator: {status_line}")

            if parts:
                msg = "\n\n".join(parts)
                logger.info("Event -> coordinator: %s", msg[:200])
                await turn_fn(msg)

    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Coordinator shutting down...")
    except Exception as e:
        logger.error("Coordinator fatal: %s", e, exc_info=True)
    finally:
        if dash_runner is not None:
            with contextlib.suppress(Exception):
                await dash_runner.cleanup()
        await poller.stop()
        for swarm in deps.swarms.values():
            swarm.kill()
        for task in deps.swarm_tasks.values():
            task.cancel()
        if deps.swarm_tasks:
            await asyncio.gather(*deps.swarm_tasks.values(), return_exceptions=True)
        cost_tracker.log_summary()
        # Persist this run's per-agent usage to the session usage.db so
        # ctf-tokens reports / quota checks see it.
        try:
            from backend.sandbox import RUN_ID
            cost_tracker.flush_to_log(
                db_path=getattr(deps.settings, "usage_log_path", None),
                run_id=RUN_ID,
                session_name=getattr(deps.settings, "session_name", "default"),
            )
        except Exception as e:
            logger.warning("usage_log flush failed: %s", e)
        try:
            await ctfd.close()
        except Exception:
            pass

    return {
        "results": deps.results,
        "total_cost_usd": cost_tracker.total_cost_usd,
        "total_tokens": cost_tracker.total_tokens,
    }


async def _auto_spawn_one(deps: CoordinatorDeps, challenge_name: str) -> None:
    """Auto-spawn a swarm for a single challenge if not already running."""
    if challenge_name in deps.swarms:
        return
    active = sum(1 for t in deps.swarm_tasks.values() if not t.done())
    if active >= deps.max_concurrent_challenges:
        return
    try:
        from backend.agents.coordinator_core import do_spawn_swarm
        result = await do_spawn_swarm(deps, challenge_name)
        logger.info(f"Auto-spawn {challenge_name}: {result[:100]}")
    except Exception as e:
        logger.warning(f"Auto-spawn failed for {challenge_name}: {e}")


async def _auto_spawn_unsolved(deps: CoordinatorDeps, poller) -> None:
    """Auto-spawn swarms for all unsolved challenges that don't have active swarms."""
    from backend.agents.coordinator_core import _is_skipped
    unsolved = {
        n for n in (poller.known_challenges - poller.known_solved)
        if not _is_skipped(deps, n)
    }
    for name in sorted(unsolved):
        await _auto_spawn_one(deps, name)


