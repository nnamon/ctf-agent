"""Shared coordinator tool logic — called by both Claude SDK and Codex coordinators."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import time
from pathlib import Path

from backend.deps import CoordinatorDeps
from backend.exec_env import EnvRegistry
from backend.prompts import ChallengeMeta
from backend.solver_base import FLAG_FOUND

logger = logging.getLogger(__name__)


def _is_skipped(deps: CoordinatorDeps, challenge_name: str) -> bool:
    """True if `challenge_name` matches any glob in settings.skip_challenges.

    The skip-list filters out challenges the coordinator should never
    attempt — e.g. pwn.college's `linux-luminarium/destruction/*` slugs
    that deliberately wipe the workspace and are unrecoverable without
    a workspace-reset tool the solver doesn't have.
    """
    patterns = list(getattr(deps.settings, "skip_challenges", []) or [])
    if not patterns:
        return False
    return any(fnmatch.fnmatchcase(challenge_name, pat) for pat in patterns)


def _bind_challenge_to_envs(registry: EnvRegistry, meta: ChallengeMeta) -> None:
    """Tell envs which challenge they're now driving.

    For pwn.college: read meta.backend_meta["pwncollege"] = {dojo,module,
    challenge} and call set_active_challenge on the env. This is a no-op
    when the env doesn't know about the backend block. Safe to call before
    the env has been started — the actual workspace spawn defers to the
    env's pre-exec hook on first tool call.
    """
    pwn = meta.backend_meta.get("pwncollege")
    if pwn and registry.has("pwncollege"):
        try:
            env = registry.get_unstarted("pwncollege")
            if hasattr(env, "set_active_challenge"):
                env.set_active_challenge(  # type: ignore[attr-defined]
                    pwn.get("dojo", ""),
                    pwn.get("module", ""),
                    pwn.get("challenge", ""),
                )
        except Exception as e:
            logger.warning("Could not bind pwncollege env to %s: %s", meta.name, e)


async def do_fetch_challenges(deps: CoordinatorDeps) -> str:
    challenges = await deps.ctfd.fetch_all_challenges()
    solved = await deps.ctfd.fetch_solved_names()
    result = [
        {
            "name": ch.get("name", "?"),
            "category": ch.get("category", "?"),
            "value": ch.get("value", 0),
            "solves": ch.get("solves", 0),
            "status": "SOLVED" if ch.get("name") in solved else "unsolved",
            "description": (ch.get("description") or "")[:200],
        }
        for ch in challenges
        if not _is_skipped(deps, ch.get("name", ""))
    ]
    return json.dumps(result, indent=2)


async def do_get_solve_status(deps: CoordinatorDeps) -> str:
    solved = await deps.ctfd.fetch_solved_names()
    swarm_status = {}
    for name, swarm in deps.swarms.items():
        if _is_skipped(deps, name):
            continue
        status = swarm.get_status()
        # Annotate with run-loop liveness so the coordinator LLM can tell
        # finished swarms apart from running ones. A swarm whose task is
        # done is a zombie — bump_agent calls against it just stuff insights
        # into a trace nothing is consuming. Fresh spawn or move on.
        task = deps.swarm_tasks.get(name)
        status["task_done"] = task is None or task.done()
        swarm_status[name] = status
    return json.dumps({"solved": sorted(solved), "active_swarms": swarm_status}, indent=2)


async def do_spawn_swarm(deps: CoordinatorDeps, challenge_name: str) -> str:
    # Skip-list guard. Glob-matched names in settings.skip_challenges
    # (e.g. `*/destruction/*`) get rejected here so the coordinator
    # can't accidentally retry them after we've decided they're
    # unsolvable on this backend.
    if _is_skipped(deps, challenge_name):
        return (
            f"Skipped: {challenge_name!r} matches a skip_challenges "
            "pattern. Pick a different challenge."
        )

    # Usage-limit guard. When the upstream ChatGPT subscription is
    # rate-limited (deps.usage_limit["hit"]=True), every solver turn
    # fails with usageLimitExceeded — spawning new swarms only burns
    # docker containers and produces failed-turn noise. Refuse here
    # so the coord LLM gets a clear "wait for reset" message instead
    # of the previous behaviour (410 failed turns + 28 leaked
    # containers in 4 minutes during the 2026-05-07 incident).
    if (deps.usage_limit or {}).get("hit"):
        resets = deps.usage_limit.get("resets_at") or "(unknown)"
        return (
            f"Refused: ChatGPT subscription is rate-limited "
            f"(resets at {resets}). New spawns just burn containers — "
            f"wait for the reset before trying again."
        )

    # Atomic capacity admission. The Codex coordinator routinely
    # dispatches a flood of parallel spawn_swarm tool calls in one turn
    # ("spawn for all 30 unsolved at once") — without this lock the
    # active_count read races and every concurrent caller passes the
    # max_concurrent check at the initial value of 0, so all 30 swarms
    # register, 60+ solver threads start, and the codex MCP transport
    # collapses with "Connection lost". With the lock, admission is
    # strictly serial: the first N calls past the cap return "At
    # capacity" and the LLM either retries on the next turn or moves on.
    async with deps.spawn_lock:
        # Retire finished swarm_tasks (free their resources), but keep
        # the ChallengeSwarm objects in deps.swarms so the dashboard
        # can still display the solver list, flags, log paths, and
        # writeup link for completed challenges. The capacity check
        # below counts only swarms whose cancel_event is unset (i.e.
        # still actively solving).
        for name, task in list(deps.swarm_tasks.items()):
            if task.done():
                deps.swarm_tasks.pop(name, None)

        active_count = sum(
            1 for s in deps.swarms.values() if not s.cancel_event.is_set()
        )
        if active_count >= deps.max_concurrent_challenges:
            return (
                f"At capacity ({active_count}/{deps.max_concurrent_challenges} "
                f"challenges running). Wait for one to finish."
            )

        if challenge_name in deps.swarms and \
                not deps.swarms[challenge_name].cancel_event.is_set():
            return f"Swarm still running for {challenge_name}"

    # Per-session quota check. Block new spawns when the full session-
    # to-date cost (carryover from prior runs + this run's live cost,
    # both already folded into total_cost_usd) is over budget. Active
    # swarms continue to run — we don't kill mid-attempt, just refuse
    # to start more.
    quota = getattr(deps.settings, "quota_usd", None)
    if quota is not None:
        spent = deps.cost_tracker.total_cost_usd
        if spent >= quota:
            session = getattr(deps.settings, "session_name", "default")
            if deps.event_hub:
                deps.event_hub.broadcast(
                    "quota_exceeded", challenge=challenge_name,
                    text=f"refused {challenge_name}: spent ${spent:.2f} of ${quota:.2f}",
                )
            return (
                f"Session quota exceeded: spent ${spent:.2f} of "
                f"${quota:.2f}. Refusing to spawn new swarm. "
                f"Raise quota_usd in sessions/{session}/session.yml or "
                f"start a new session to continue."
            )

        # Stay inside the spawn_lock through swarm creation + registration.
        # The auto-pull is only slow on a cold cache (and fetch_all_challenges
        # populates challenge_dirs for every slug in one go, so subsequent
        # spawns hit the warm path); steady-state, the lock is held for a
        # few hundred ms, which is fine for serialising tool-call admission.
        if challenge_name not in deps.challenge_dirs:
            challenges = await deps.ctfd.fetch_all_challenges()
            ch_data = next((c for c in challenges if c.get("name") == challenge_name), None)
            if not ch_data:
                return f"Challenge '{challenge_name}' not found on CTFd"
            output_dir = str(Path(deps.challenges_root))
            ch_dir = await deps.ctfd.pull_challenge(ch_data, output_dir)
            deps.challenge_dirs[challenge_name] = ch_dir
            deps.challenge_metas[challenge_name] = ChallengeMeta.from_yaml(Path(ch_dir) / "metadata.yml")

        from backend.agents.swarm import ChallengeSwarm

        # Bind any per-challenge env settings to the shared registry. For
        # pwn.college this means telling the workspace env which (dojo,
        # module, challenge) to spawn on first SSH access. The registry +
        # envs themselves are owned by the coordinator and persist across
        # challenges; we just nudge the active challenge here so the next
        # tool call from the solver lands in the right container.
        meta = deps.challenge_metas[challenge_name]

        # Prerequisite gating. Backends like HtbMachinesBackend list
        # `<slug>-user` as a prereq on `<slug>-root` because root.txt
        # is unreachable without the user foothold. The check happens
        # here (not in the swarm) so the coord can fail fast and the
        # capacity slot stays free for something solvable.
        prereqs = list(getattr(meta, "prerequisites", []) or [])
        if prereqs:
            try:
                solved = await deps.ctfd.fetch_solved_names()
            except Exception as e:
                logger.warning("prereq check: fetch_solved_names failed: %s", e)
                solved = set()
            unmet = [p for p in prereqs if p not in solved]
            if unmet:
                return (
                    f"Refused: {challenge_name!r} blocked by unmet "
                    f"prerequisites {unmet!r}. Solve those first."
                )

        if deps.env_registry is not None:
            _bind_challenge_to_envs(deps.env_registry, meta)

        # Per-challenge instance lifecycle, coord-driven. Backends with
        # docker-instanced challenges (HTB Labs) or VPN-tunnelled VMs
        # (HTB Machines) spawn a per-user instance here; sibling solvers
        # in the resulting swarm share it. Static-distfile backends
        # inherit the no-op default and we leave meta alone.
        try:
            live_conn = await deps.ctfd.start_instance(challenge_name)
        except Exception as e:
            return (
                f"start_instance({challenge_name}) failed: {e} — "
                "swarm not spawned. Check backend / connectivity."
            )
        prev_netmode = getattr(deps.settings, "sandbox_network_mode", "") or ""
        netmode_was_set = False
        if live_conn:
            logger.info("[%s] live instance: %s", challenge_name, live_conn)
            meta.connection_info = live_conn
            # Propagate VPN sidecar netns to solver sandboxes if the
            # backend brought one up (HtbMachinesBackend exposes this
            # via a network_mode property; tier-2 docker-challenges leave
            # it empty).
            backend_netmode = getattr(deps.ctfd, "network_mode", "") or ""
            if backend_netmode:
                deps.settings.sandbox_network_mode = backend_netmode
                netmode_was_set = True
                logger.info(
                    "[%s] solver sandboxes will use network_mode=%r",
                    challenge_name, backend_netmode,
                )

        # Defensive: if anything between start_instance and task
        # creation fails (ChallengeSwarm ctor, asyncio.create_task in
        # rare resource pressure), the swarm's `finally` block never
        # runs. Without explicit cleanup the spawned instance leaks
        # AND sandbox_network_mode stays mutated, so the *next* swarm
        # spawned in this session inherits a stale VPN netns. Wrap the
        # tail of admission in try/except + roll back on failure.
        try:
            swarm = ChallengeSwarm(
                challenge_dir=deps.challenge_dirs[challenge_name],
                meta=meta,
                ctfd=deps.ctfd,
                cost_tracker=deps.cost_tracker,
                settings=deps.settings,
                model_specs=deps.model_specs,
                no_submit=deps.no_submit,
                coordinator_inbox=deps.coordinator_inbox,
                env_registry=deps.env_registry,
            )
            deps.swarms[challenge_name] = swarm

            async def _run_and_cleanup() -> None:
                t0 = time.monotonic()
                started_at_wall = int(time.time())
                result = await swarm.run()
                duration_s = time.monotonic() - t0
                finished_at_wall = int(time.time())
                # Flag already submitted/confirmed by solver's submit_fn — just record the result
                if result and result.status == FLAG_FOUND:
                    deps.results[challenge_name] = {
                        "flag": result.flag,
                        "submit": "DRY RUN" if deps.no_submit else "confirmed by solver",
                    }
                    if deps.event_hub:
                        # Truncated so a long flag doesn't blow up the event panel.
                        flag_short = (result.flag or "")[:60]
                        deps.event_hub.broadcast(
                            "flag_found", challenge=challenge_name,
                            model=swarm.winner_spec or "?",
                            text=f"{challenge_name}: {flag_short}",
                        )

                # Persist the per-challenge summary BEFORE the writeup. The
                # writeup can take 30s–15min (claude refusal → codex fallback,
                # rate-limit retries, etc.) and has previously hung the whole
                # swarm task. Writing the solve row first means the
                # challenge_solves table has the row even if writeup fails or
                # the coord crashes mid-postmortem; writeup_path is patched
                # onto the AttemptLog row separately on writeup success.
                # Logged for ALL outcomes (solved, gave_up, error, cancelled)
                # so we can compute solve-rate / time-to-solve / cost-per-
                # category aggregations after the competition.
                _persist_challenge_solve(
                    deps=deps, swarm=swarm, result=result, duration_s=duration_s,
                    started_at=started_at_wall, finished_at=finished_at_wall,
                )

                if result and result.status == FLAG_FOUND and not deps.no_writeup:
                    await _generate_writeup_for_swarm(swarm, result, deps, duration_s)

            task = asyncio.create_task(_run_and_cleanup(), name=f"swarm-{challenge_name}")
            deps.swarm_tasks[challenge_name] = task
        except Exception as e:
            # Roll back: release the per-user instance, restore the
            # network_mode setting, drop the half-registered swarm.
            logger.error(
                "[%s] swarm creation failed after start_instance: %s — "
                "rolling back instance + network_mode",
                challenge_name, e,
            )
            deps.swarms.pop(challenge_name, None)
            if netmode_was_set:
                deps.settings.sandbox_network_mode = prev_netmode
            try:
                await deps.ctfd.stop_instance(challenge_name)
            except Exception as cleanup_err:
                logger.warning(
                    "[%s] stop_instance during rollback failed: %s",
                    challenge_name, cleanup_err,
                )
            return f"Swarm setup failed for {challenge_name}: {e}"
        if deps.event_hub:
            deps.event_hub.broadcast(
                "swarm_spawned", challenge=challenge_name,
                text=f"spawned {challenge_name} ({len(deps.model_specs)} models)",
            )
        return f"Swarm spawned for {challenge_name} with {len(deps.model_specs)} models"


async def do_check_swarm_status(deps: CoordinatorDeps, challenge_name: str) -> str:
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm running for {challenge_name}"
    return json.dumps(swarm.get_status(), indent=2)


async def do_submit_flag(deps: CoordinatorDeps, challenge_name: str, flag: str) -> str:
    if deps.no_submit:
        return f'DRY RUN — would submit "{flag.strip()}" for {challenge_name}'
    try:
        result = await deps.ctfd.submit_flag(challenge_name, flag)
        return result.display
    except Exception as e:
        return f"submit_flag error: {e}"


async def do_kill_swarm(deps: CoordinatorDeps, challenge_name: str) -> str:
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm running for {challenge_name}"
    swarm.kill()
    return f"Swarm for {challenge_name} cancelled"


async def do_kill_solver(
    deps: CoordinatorDeps, challenge_name: str, model_spec: str,
) -> str:
    """Kill one specific solver in a swarm; siblings continue.

    Use when one model is stuck (idle_seconds >120 with no progress)
    but another is making real progress — kills only the dead weight,
    frees the slot, lets the productive solver finish + trigger
    writeup generation cleanly."""
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm running for {challenge_name}"
    if model_spec not in swarm.model_specs:
        return (
            f"No solver {model_spec!r} in swarm {challenge_name}. "
            f"Solvers: {swarm.model_specs}"
        )
    cancelled = swarm.kill_solver(model_spec)
    if cancelled:
        return f"Cancelled {model_spec} solver on {challenge_name}; siblings continue"
    return f"{model_spec} solver on {challenge_name} was already done — nothing to cancel"


async def do_bump_agent(deps: CoordinatorDeps, challenge_name: str, model_spec: str, insights: str) -> str:
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm running for {challenge_name}"
    # Refuse to bump a zombie. A swarm whose task has ended (consecutive
    # errors, terminal context overflow, sibling won) keeps its solver
    # objects around for the dashboard, but solver.bump() just buffers
    # insights nothing is going to read. Without this guard the coord LLM
    # spent ~25 min crafting recovery insights for a wedged hitcon-ftp
    # solver (2026-05-06), burning reasoning tokens on a no-op.
    task = deps.swarm_tasks.get(challenge_name)
    if task is None or task.done():
        return (
            f"Swarm for {challenge_name!r} has finished — bump_agent is a "
            f"no-op. Spawn a fresh swarm if you want another attempt, or "
            f"move on to a different challenge."
        )
    solver = swarm.solvers.get(model_spec)
    if not solver:
        return f"No solver for {model_spec} in {challenge_name}"
    solver.bump(insights)
    return f"Bumped {model_spec} on {challenge_name}"


async def do_read_solver_trace(deps: CoordinatorDeps, challenge_name: str, model_spec: str, last_n: int = 20) -> str:
    """Read the last N trace events from a solver's JSONL log."""
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm for {challenge_name}"
    solver = swarm.solvers.get(model_spec)
    if not solver:
        return f"No solver for {model_spec}"
    trace_path = getattr(solver, "tracer", None)
    if not trace_path:
        return "No tracer on solver"
    path = trace_path.path if hasattr(trace_path, "path") else str(trace_path)
    try:
        lines = Path(path).read_text().strip().split("\n")
        recent = lines[-last_n:]
        summary = []
        for line in recent:
            try:
                d = json.loads(line)
                t = d.get("type", "?")
                if t == "tool_call":
                    args_str = str(d.get("args", ""))[:100]
                    summary.append(f"step {d.get('step','?')} CALL {d.get('tool','?')}: {args_str}")
                elif t == "tool_result":
                    result_str = str(d.get("result", ""))[:100]
                    summary.append(f"step {d.get('step','?')} RESULT {d.get('tool','?')}: {result_str}")
                elif t in ("finish", "error", "bump", "turn_failed"):
                    summary.append(f"** {t}: {json.dumps({k:v for k,v in d.items() if k != 'ts'})}")
                elif t == "usage":
                    summary.append(f"usage: in={d.get('input_tokens',0)} out={d.get('output_tokens',0)} cost=${d.get('cost_usd',0):.4f}")
                elif t == "reasoning":
                    rtext = str(d.get("text", ""))[:1500]
                    summary.append(f"step {d.get('step','?')} REASONING: {rtext}")
                elif t == "reasoning_pulse":
                    summary.append(
                        f"step {d.get('step','?')} REASONING_PULSE: "
                        f"+{d.get('delta_tokens', 0)} tokens "
                        f"(total {d.get('total_tokens', 0)})"
                    )
                elif t == "codex_stderr":
                    summary.append(f"** codex_stderr: {str(d.get('text', d.get('line','')))[:600]}")
                elif t == "subprocess_exit":
                    summary.append(
                        f"** subprocess_exit: rc={d.get('returncode')} "
                        f"sig={d.get('signal','')} elapsed={d.get('elapsed_s')}s "
                        f"idle={d.get('last_event_idle_s')}s "
                        f"pending_rpcs={d.get('pending_rpcs')} step={d.get('step','?')}"
                    )
                else:
                    summary.append(f"{t}: {str(d)[:80]}")
            except Exception:
                summary.append(line[:100])
        return "\n".join(summary)
    except FileNotFoundError:
        return f"Trace file not found: {path}"
    except Exception as e:
        return f"Error reading trace: {e}"


async def do_broadcast(deps: CoordinatorDeps, challenge_name: str, message: str) -> str:
    """Broadcast a message to all solvers working on a challenge."""
    swarm = deps.swarms.get(challenge_name)
    if not swarm:
        return f"No swarm running for {challenge_name}"
    await swarm.message_bus.broadcast(message)
    return f"Broadcast to all solvers on {challenge_name}"


def _persist_challenge_solve(
    *,
    deps: CoordinatorDeps,
    swarm,
    result,
    duration_s: float,
    started_at: int,
    finished_at: int,
) -> None:
    """Insert a row into challenge_solves summarising this swarm run.

    Aggregates per-solver token / cost data from swarm.cost_tracker for
    every agent matching the swarm's `<challenge>/<spec>` naming. All
    swarm outcomes (solved, gave_up, error, cancelled) get a row so
    aggregations like solve-rate-by-category and cost-per-attempt
    work post-competition. Failures are swallowed — accounting must
    not break a successful solve.
    """
    try:
        from backend.sandbox import RUN_ID
        from backend.usage_log import (
            ChallengeSolveModelRow,
            ChallengeSolveRow,
            insert_solve,
        )

        usage_db = getattr(deps.settings, "usage_log_path", None)
        if not usage_db:
            return  # operator disabled usage logging

        challenge_name = swarm.meta.name
        session_name = getattr(deps.settings, "session_name", "default") or "default"
        # Sum tokens + cost across every solver in this swarm. Agents are
        # named "<challenge>/<spec>" so prefix-matching catches user/root
        # halves on htb-machines and any future per-attempt naming.
        # Also build per-model rows for the breakdown table.
        prefix = f"{challenge_name}/"
        in_t = out_t = cache_t = 0
        cost = 0.0
        per_model_rows: list[ChallengeSolveModelRow] = []
        winner_spec_raw = swarm.winner_spec or ""
        for agent_name, usage in swarm.cost_tracker.by_agent.items():
            if not agent_name.startswith(prefix):
                continue
            spec = agent_name[len(prefix):]
            agent_in = int(usage.usage.input_tokens or 0)
            agent_out = int(usage.usage.output_tokens or 0)
            agent_cache = int(usage.usage.cache_read_tokens or 0)
            agent_cost = float(usage.cost_usd or 0.0)
            in_t += agent_in
            out_t += agent_out
            cache_t += agent_cache
            cost += agent_cost
            # Pull per-solver step count off the live solver if available.
            solver = swarm.solvers.get(spec) if hasattr(swarm, "solvers") else None
            steps = int(getattr(solver, "_step_count", 0) or 0) if solver else 0
            per_model_rows.append(ChallengeSolveModelRow(
                run_id=RUN_ID,
                session_name=session_name,
                challenge_name=challenge_name,
                model_spec=spec,
                steps=steps,
                cost_usd=agent_cost,
                input_tokens=agent_in,
                output_tokens=agent_out,
                cache_read_tokens=agent_cache,
                won=(spec == winner_spec_raw),
            ))

        # Status normalisation. swarm.cancel_event is set on kill_swarm;
        # we record those as "cancelled" so they don't pollute the
        # solved-rate count. result is None when run() bailed early
        # (start_instance failure, etc.).
        if result is None:
            status = "cancelled" if swarm.cancel_event.is_set() else "error"
            flag = None
            confirmed = False
            winner_spec = None
            winner_steps = None
        else:
            status = result.status
            flag = result.flag
            confirmed = bool(getattr(result, "confirmed", False)) or status == "flag_found"
            winner_spec = swarm.winner_spec
            winner_steps = result.step_count if status == "flag_found" else None

        meta = swarm.meta
        row = ChallengeSolveRow(
            run_id=RUN_ID,
            session_name=session_name,
            challenge_name=challenge_name,
            category=getattr(meta, "category", "") or None,
            points=int(getattr(meta, "value", 0) or 0) or None,
            status=status,
            flag=flag,
            confirmed=confirmed,
            winner_spec=winner_spec,
            winner_steps=winner_steps,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=float(duration_s),
            cost_usd=cost,
            input_tokens=in_t,
            output_tokens=out_t,
            cache_read_tokens=cache_t,
            per_model=per_model_rows,
        )
        from pathlib import Path as _P
        insert_solve(_P(usage_db), row)
    except Exception as e:
        logger.warning("challenge_solves persistence failed: %s", e)


async def _generate_writeup_for_swarm(swarm, winner_result, deps: CoordinatorDeps, duration_s: float) -> None:
    """Build the post-mortem writeup for one finished swarm. Never raises."""
    try:
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

        # Session-scoped writeup output dir; falls back to the legacy
        # "writeups/" if no session is active.
        from backend.session import SessionContext
        session_for_writeup = SessionContext.resolve(
            explicit=getattr(deps.settings, "session_name", None)
        )

        if deps.event_hub:
            deps.event_hub.broadcast(
                "writeup_start", challenge=swarm.meta.name,
                model=deps.writeup_model,
                text=f"writeup start: {swarm.meta.name} ({deps.writeup_model})",
            )
        wstart = time.monotonic()

        out = await generate_writeup(
            meta=swarm.meta,
            winner_result=winner_result,
            winner_spec=winner_spec,
            sibling_traces=sibling_traces,
            cost_usd=deps.cost_tracker.total_cost_usd,
            duration_s=duration_s,
            out_dir=session_for_writeup.writeups_dir,
            model=deps.writeup_model,
            settings=deps.settings,
        )
        wdur = time.monotonic() - wstart
        if out:
            logger.info("Post-mortem writeup written: %s", out)
            if deps.event_hub:
                try:
                    size_kb = Path(out).stat().st_size / 1024.0
                except OSError:
                    size_kb = 0.0
                deps.event_hub.broadcast(
                    "writeup_done", challenge=swarm.meta.name,
                    model=deps.writeup_model, path=str(out),
                    text=f"writeup done: {swarm.meta.name} ({size_kb:.1f} KB, {wdur:.0f}s)",
                )
            # Attach to the AttemptLog row so an orchestrator can locate
            # the writeup for chain-sibling --context attachments without
            # fs-walking writeups/.
            if hasattr(deps.ctfd, "set_writeup_path") and winner_result.flag:
                try:
                    deps.ctfd.set_writeup_path(
                        swarm.meta.name, winner_result.flag, str(out)
                    )
                except Exception:
                    pass
        elif deps.event_hub:
            deps.event_hub.broadcast(
                "writeup_failed", challenge=swarm.meta.name,
                model=deps.writeup_model,
                text=f"writeup failed: {swarm.meta.name} (empty output)",
            )

        # Persist the preserved-workspace path (when --preserve-workspace is on)
        # for the same orchestrator-discoverability reason.
        preserve_root = getattr(deps.settings, "preserve_workspace_to", "") or ""
        if preserve_root and hasattr(deps.ctfd, "set_workspace_path") \
                and winner_result.flag and winner_spec:
            try:
                slug = Path(swarm.challenge_dir).name or "challenge"
                wpath = Path(preserve_root) / slug / winner_spec / "workspace"
                if wpath.exists():
                    deps.ctfd.set_workspace_path(
                        swarm.meta.name, winner_result.flag, str(wpath)
                    )
            except Exception:
                pass
    except Exception as e:
        logger.warning("Post-mortem failed for %s: %s", swarm.meta.name, e, exc_info=True)
        if deps.event_hub:
            deps.event_hub.broadcast(
                "writeup_failed", challenge=swarm.meta.name,
                model=getattr(deps, "writeup_model", "?"),
                text=f"writeup failed: {swarm.meta.name}: {type(e).__name__}: {str(e)[:120]}",
            )
