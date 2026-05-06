"""ChallengeSwarm — Parallel solvers racing on one challenge."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from backend.agents.solver import Solver
from backend.cost_tracker import CostTracker
from backend.backends import Backend
from backend.exec_env import EnvRegistry
from backend.message_bus import ChallengeMessageBus
from backend.models import DEFAULT_MODELS, provider_from_spec
from backend.prompts import ChallengeMeta
from backend.solver_base import (
    CANCELLED,
    ERROR,
    FLAG_FOUND,
    GAVE_UP,
    QUOTA_ERROR,
    SolverProtocol,
    SolverResult,
)

if TYPE_CHECKING:
    from backend.config import Settings

logger = logging.getLogger(__name__)


# Quota fallback: map subscription-backed providers to API-backed equivalents
QUOTA_FALLBACK: dict[str, str] = {
    "claude-sdk/claude-opus-4-7": "bedrock/us.anthropic.claude-opus-4-7-v1",
    "claude-sdk/claude-opus-4-6": "bedrock/us.anthropic.claude-opus-4-6-v1",
    "codex/gpt-5.5": "azure/gpt-5.5",
    "codex/gpt-5.5-mini": "azure/gpt-5.5-mini",
    "codex/gpt-5.4": "azure/gpt-5.4",
    "codex/gpt-5.4-mini": "azure/gpt-5.4-mini",
    "codex/gpt-5.3-codex-spark": "zen/gpt-5.3-codex-spark",
}


def _quota_fallback_spec(model_spec: str) -> str | None:
    return QUOTA_FALLBACK.get(model_spec)


@dataclass
class ChallengeSwarm:
    """Parallel solvers racing on one challenge."""

    challenge_dir: str
    meta: ChallengeMeta
    ctfd: Backend
    cost_tracker: CostTracker
    settings: Settings
    model_specs: list[str] = field(default_factory=lambda: list(DEFAULT_MODELS))
    no_submit: bool = False
    coordinator_inbox: asyncio.Queue | None = None

    # Optional multi-env registry. When set, solvers spawned by this
    # swarm receive it as `env_registry`, so their tool surface gains a
    # `target` arg. The local Docker env auto-registers per-solver. The
    # coordinator owns lifecycle for any shared remote envs (e.g.
    # pwn.college's workspace SSH master) — see coordinator_loop.
    env_registry: EnvRegistry | None = None

    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    solvers: dict[str, SolverProtocol] = field(default_factory=dict)
    findings: dict[str, str] = field(default_factory=dict)
    winner: SolverResult | None = None
    winner_spec: str | None = None
    confirmed_flag: str | None = None
    # Wall-clock solve timing (epoch seconds). Set by run() / its caller
    # so the dashboard can show "solved in 14m" etc. without re-deriving
    # from log timestamps.
    started_at: float | None = None
    finished_at: float | None = None
    # Set by kill() so the coordinator-side cleanup pass can drop killed
    # swarms from deps.swarms after a cooldown — without this the LLM
    # keeps "remembering" the kill in the active_swarms snapshot and
    # never gives a deprioritised challenge a second chance.
    killed_at: float | None = None
    _flag_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _submit_count: dict[str, int] = field(default_factory=dict)  # per-model wrong submission count
    _submitted_flags: set[str] = field(default_factory=set)  # dedup exact flags
    _last_submit_time: dict[str, float] = field(default_factory=dict)  # per-model last submit timestamp
    message_bus: ChallengeMessageBus = field(default_factory=ChallengeMessageBus)

    def _create_solver(self, model_spec: str):
        """Create the right solver type based on provider.

        - claude-sdk/* → ClaudeSolver (Claude Agent SDK, subscription-first)
        - codex/* → CodexSolver (Codex App Server, subscription-first)
        - bedrock/*, azure/*, zen/*, google/* → Pydantic AI Solver (API)
        """
        provider = provider_from_spec(model_spec)

        def _submit_fn(flag): return self.try_submit_flag(flag, model_spec)
        _notify = self._make_notify_fn(model_spec)

        if provider == "claude-sdk":
            from backend.agents.claude_solver import ClaudeSolver
            return ClaudeSolver(
                model_spec=model_spec,
                challenge_dir=self.challenge_dir,
                meta=self.meta,
                ctfd=self.ctfd,
                cost_tracker=self.cost_tracker,
                settings=self.settings,
                cancel_event=self.cancel_event,
                no_submit=self.no_submit,
                submit_fn=_submit_fn,
                message_bus=self.message_bus,
                notify_coordinator=_notify,
                env_registry=self.env_registry,
            )

        if provider == "codex":
            from backend.agents.codex_solver import CodexSolver
            return CodexSolver(
                model_spec=model_spec,
                challenge_dir=self.challenge_dir,
                meta=self.meta,
                ctfd=self.ctfd,
                cost_tracker=self.cost_tracker,
                settings=self.settings,
                cancel_event=self.cancel_event,
                no_submit=self.no_submit,
                submit_fn=_submit_fn,
                message_bus=self.message_bus,
                notify_coordinator=_notify,
                env_registry=self.env_registry,
            )

        return self._create_pydantic_solver(model_spec)

    def _make_notify_fn(self, model_spec: str):
        """Create a callback that pushes solver messages to the coordinator inbox."""
        async def _notify(message: str) -> None:
            if self.coordinator_inbox:
                self.coordinator_inbox.put_nowait(
                    f"[{self.meta.name}/{model_spec}] {message}"
                )
        return _notify

    def _create_pydantic_solver(self, model_spec: str, sandbox=None, owns_sandbox: bool | None = None) -> Solver:
        """Create a Pydantic AI solver. Pass sandbox to reuse an existing container (quota fallback)."""
        solver = Solver(
            model_spec=model_spec,
            challenge_dir=self.challenge_dir,
            meta=self.meta,
            ctfd=self.ctfd,
            cost_tracker=self.cost_tracker,
            settings=self.settings,
            cancel_event=self.cancel_event,
            sandbox=sandbox,
            owns_sandbox=owns_sandbox,
            env_registry=self.env_registry,
        )
        solver.deps.message_bus = self.message_bus
        solver.deps.model_spec = model_spec
        solver.deps.no_submit = self.no_submit
        solver.deps.submit_fn = lambda flag: self.try_submit_flag(flag, model_spec)
        solver.deps.notify_coordinator = self._make_notify_fn(model_spec)
        return solver

    def _gather_sibling_insights(self, exclude_model: str) -> str:
        parts: list[str] = []
        for model, finding in self.findings.items():
            if model != exclude_model and finding:
                parts.append(f"[{model}]: {finding}")
        return "\n\n".join(parts) if parts else "No sibling insights available yet."

    # Escalating cooldowns after incorrect submissions (per model)
    SUBMISSION_COOLDOWNS = [0, 30, 120, 300, 600]  # 0s, 30s, 2min, 5min, 10min

    async def try_submit_flag(self, flag: str, model_spec: str) -> tuple[str, bool]:
        """Cooldown-gated, deduplicated flag submission. Returns (display, is_confirmed)."""
        async with self._flag_lock:
            if self.confirmed_flag:
                return f"ALREADY SOLVED — flag already confirmed: {self.confirmed_flag}", True

            normalized = flag.strip()

            # Dedup exact flags across all models
            if normalized in self._submitted_flags:
                return "INCORRECT — already tried this exact flag.", False

            # Escalating cooldown after incorrect submissions
            wrong_count = self._submit_count.get(model_spec, 0)
            cooldown_idx = min(wrong_count, len(self.SUBMISSION_COOLDOWNS) - 1)
            cooldown = self.SUBMISSION_COOLDOWNS[cooldown_idx]
            if cooldown > 0:
                last_time = self._last_submit_time.get(model_spec, 0)
                elapsed = time.monotonic() - last_time
                if elapsed < cooldown:
                    remaining = int(cooldown - elapsed)
                    return (
                        f"COOLDOWN — wait {remaining}s before submitting again. "
                        f"You have {wrong_count} incorrect submissions. "
                        "Use this time to do deeper analysis and verify your flag.",
                        False,
                    )

            self._submitted_flags.add(normalized)

            from backend.tools.core import do_submit_flag
            display, is_confirmed = await do_submit_flag(self.ctfd, self.meta.name, flag)
            if is_confirmed:
                self.confirmed_flag = normalized
            else:
                self._submit_count[model_spec] = wrong_count + 1
                self._last_submit_time[model_spec] = time.monotonic()
            return display, is_confirmed

    async def _run_solver(self, model_spec: str) -> SolverResult | None:
        # Codex MCP transport occasionally drops with ConnectionResetError
        # during solver.start() ("Connection lost") — typically a brief
        # backend hiccup that resolves within seconds. Retry up to 2x
        # with exponential backoff before giving up. We rebuild the
        # solver each retry because the underlying transport is dead.
        last_err: BaseException | None = None
        for attempt in range(3):
            if self.cancel_event.is_set():
                return None
            solver = self._create_solver(model_spec)
            self.solvers[model_spec] = solver
            try:
                result, final_solver = await self._run_solver_loop(solver, model_spec)
                solver = final_solver
                return result
            except (ConnectionResetError, ConnectionError) as e:
                last_err = e
                logger.warning(
                    "[%s/%s] codex transport dropped (attempt %d/3): %s",
                    self.meta.name, model_spec, attempt + 1, e,
                )
                with contextlib.suppress(Exception):
                    await solver.stop()
                if attempt < 2:
                    # Codex app-server outages observed today have run
                    # 3-5 minutes per window. Old 5s/10s backoff was
                    # nowhere near enough — every spawn during the
                    # outage burned all 3 retries in 15s and gave up.
                    # 60s/180s gives the backend room to recover before
                    # the second + third attempts.
                    await asyncio.sleep([60, 180][attempt])
                continue
            except Exception as e:
                logger.error(f"[{self.meta.name}/{model_spec}] Fatal: {e}", exc_info=True)
                with contextlib.suppress(Exception):
                    await solver.stop()
                return None
            finally:
                # `solver.stop()` for the success path. The retry-loop
                # branches above stop manually before continuing so that
                # we don't double-stop on retry. Catch the case where
                # the loop returned without going through except/retry.
                pass
        logger.error(
            "[%s/%s] codex transport gave up after 3 attempts: %s",
            self.meta.name, model_spec, last_err,
        )
        return None

    async def _run_solver_loop(self, solver, model_spec: str) -> tuple[SolverResult, SolverProtocol]:
        """Inner loop: start → run → bump → run → ..."""
        bump_count = 0
        consecutive_errors = 0
        result = SolverResult(
            flag=None, status=CANCELLED, findings_summary="",
            step_count=0, cost_usd=0.0, log_path="",
        )
        await solver.start()

        while not self.cancel_event.is_set():
            result = await solver.run_until_done_or_gave_up()

            # Only broadcast useful findings — skip errors and broken solvers
            if (result.status not in (ERROR, QUOTA_ERROR)
                    and not (result.step_count == 0 and result.cost_usd == 0)
                    and result.findings_summary
                    and not result.findings_summary.startswith(("Error:", "Turn failed:"))):
                self.findings[model_spec] = result.findings_summary
                await self.message_bus.post(model_spec, result.findings_summary[:500])

            if result.status == FLAG_FOUND:
                self.cancel_event.set()
                self.winner = result
                self.winner_spec = model_spec
                logger.info(
                    f"[{self.meta.name}] Flag found by {model_spec}: {result.flag}"
                )
                return result, solver

            if result.status == CANCELLED:
                break

            # Quota exhaustion: fall back to API-backed Pydantic AI solver
            if result.status == QUOTA_ERROR:
                fallback_spec = _quota_fallback_spec(model_spec)
                if fallback_spec:
                    logger.warning(
                        f"[{self.meta.name}/{model_spec}] Quota exhausted — falling back to {fallback_spec}"
                    )
                    existing_sandbox = solver.sandbox
                    # Detach sandbox from old solver so stop() doesn't destroy it
                    solver.sandbox = None  # type: ignore[assignment]
                    await solver.stop()
                    solver = self._create_pydantic_solver(fallback_spec, sandbox=existing_sandbox, owns_sandbox=True)
                    self.solvers[model_spec] = solver
                    await solver.start()
                    continue
                # No fallback available, treat as error
                break

            if result.status in (GAVE_UP, ERROR):
                if result.step_count == 0 and result.cost_usd == 0:
                    if self.cancel_event.is_set():
                        logger.info(
                            f"[{self.meta.name}/{model_spec}] Cancelled before first step (race won by sibling)"
                        )
                    else:
                        logger.warning(
                            f"[{self.meta.name}/{model_spec}] Broken (0 steps, $0) — not bumping"
                        )
                    break

                # Terminal failures (e.g. context_length_exceeded after codex
                # remote-compaction overflow) won't recover on retry — the
                # next turn hits the same wall. Skip the 3-strike counter.
                if result.terminal:
                    logger.warning(
                        f"[{self.meta.name}/{model_spec}] Terminal failure — giving up immediately"
                    )
                    break

                # Track consecutive errors — stop after 3 in a row
                if result.status == ERROR:
                    consecutive_errors += 1
                    if consecutive_errors >= 3:
                        logger.warning(
                            f"[{self.meta.name}/{model_spec}] {consecutive_errors} consecutive errors — giving up"
                        )
                        break
                else:
                    consecutive_errors = 0

                bump_count += 1
                # Cooldown between bumps — check cancellation during wait
                try:
                    await asyncio.wait_for(
                        self.cancel_event.wait(),
                        timeout=min(bump_count * 30, 300),
                    )
                    break  # cancelled during cooldown
                except TimeoutError:
                    pass  # cooldown elapsed, proceed with bump
                insights = self._gather_sibling_insights(model_spec)
                solver.bump(insights)
                logger.info(
                    f"[{self.meta.name}/{model_spec}] Bumped ({bump_count}), resuming"
                )
                continue

        return result, solver

    async def run(self) -> SolverResult | None:
        """Run all solvers in parallel. Returns the winner's result or None.

        Per-challenge instance lifecycle (start) is owned by the
        coordinator (see do_spawn_swarm) — meta.connection_info and
        settings.sandbox_network_mode are already populated by the time
        we get here. We only handle teardown (stop_instance + reset
        the network_mode setting) in the `finally` block.
        """
        self.started_at = time.time()

        # Stash the per-solver tasks on the swarm so kill() can cancel
        # them later — without this, kill() only flips cancel_event and
        # the solvers' codex-MCP loops keep ticking until they
        # voluntarily check the event (which they typically don't until
        # the next tool-call boundary, sometimes minutes apart).
        self._solver_tasks = [
            asyncio.create_task(self._run_solver(spec), name=f"solver-{spec}")
            for spec in self.model_specs
        ]
        tasks = list(self._solver_tasks)

        try:
            while tasks:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    try:
                        result = task.result()
                    except Exception:
                        continue
                    if result and result.status == FLAG_FOUND:
                        self.cancel_event.set()
                        for p in pending:
                            p.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                        return result

                tasks = list(pending)

            self.cancel_event.set()
            return self.winner
        except Exception as e:
            logger.error(f"[{self.meta.name}] Swarm error: {e}", exc_info=True)
            self.cancel_event.set()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return None
        finally:
            self.finished_at = time.time()
            # Tear down any per-user docker instance we spawned. Default
            # backend impl is a no-op so this is safe regardless of
            # whether start_instance actually did anything.
            try:
                await self.ctfd.stop_instance(self.meta.name)
            except Exception as e:
                logger.warning(
                    f"[{self.meta.name}] stop_instance failed: {e}"
                )
            # Always reset sandbox_network_mode so the next swarm starts
            # from bridge default. (Mutated above only if backend reported
            # a VPN sidecar; safe to clear unconditionally.)
            if getattr(self.settings, "sandbox_network_mode", ""):
                self.settings.sandbox_network_mode = ""

    def kill(self) -> None:
        """Cancel all agents for this challenge.

        Sets cancel_event AND directly cancels the per-solver asyncio
        tasks. Setting the event alone leaves the codex-MCP loops
        running (they only check the event between tool-call boundaries,
        which can be minutes apart on a long reasoning turn). The
        explicit task.cancel() raises CancelledError into the coroutine
        immediately, freeing the swarm slot for the next spawn."""
        self.cancel_event.set()
        if self.killed_at is None:
            self.killed_at = time.time()
        for t in getattr(self, "_solver_tasks", []):
            if not t.done():
                t.cancel()

    def get_status(self) -> dict:
        """Get per-agent progress, findings, and stuck-detection data.

        Adds per-solver liveness signals so the coordinator can spot
        hung solvers (no trace activity for >120s while the swarm
        thinks they're 'running'). The trace JSONL's mtime is a cheap
        proxy — every tool_call / tool_result / note event triggers a
        write, so a stale mtime means the codex transport is hung."""
        import os
        import time
        now = time.time()

        agents = {}
        for spec in self.model_specs:
            solver = self.solvers.get(spec)
            step_count = getattr(solver, "_step_count", 0) if solver else 0
            confirmed = getattr(solver, "_confirmed", False) if solver else False
            cost_usd = 0.0
            if solver and self.cost_tracker:
                agent_name = getattr(solver, "agent_name", f"{self.meta.name}/{spec}")
                if agent_name in self.cost_tracker.by_agent:
                    cost_usd = self.cost_tracker.by_agent[agent_name].cost_usd

            # Liveness signals:
            #   idle_seconds       — trace mtime; ANY event resets this
            #                        (incl. coord bumps that don't reflect
            #                        solver progress)
            #   tool_call_idle_s   — seconds since last tool_call. Only
            #                        the model emitting a tool advances
            #                        this. Wedges where the model thinks
            #                        forever post-startup show up here
            #                        even when step_count > 0.
            idle_seconds = None
            tool_call_idle_s: float | None = None
            stuck = False
            tracer = getattr(solver, "tracer", None) if solver else None
            trace_path = getattr(tracer, "path", None) if tracer else None
            if trace_path and os.path.exists(trace_path):
                idle_seconds = round(now - os.path.getmtime(trace_path), 1)
            last_call = getattr(solver, "_last_tool_call_at", None) if solver else None
            if last_call is not None:
                tool_call_idle_s = round(now - last_call, 1)

            swarm_age = (now - self.started_at) if self.started_at else 0
            # Three distinct stuck patterns we can detect:
            #   (a) step_count == 0 after >60s         → never advanced
            #       past the initial codex turn (transport hang or
            #       model reasoning without producing any tool call)
            #   (b) step_count > 0 but no tool_call    → model wedged in
            #       in >180s and not confirmed             a reasoning loop after some progress.
            #   (c) trace mtime stale >180s            → no events at all
            #       (catches non-tool-call wedges, e.g. transport dead)
            stuck = (
                not self.cancel_event.is_set()
                and not confirmed
                and (
                    (swarm_age > 60 and step_count == 0)
                    or (step_count > 0 and tool_call_idle_s is not None
                        and tool_call_idle_s > 180)
                    or (idle_seconds is not None and idle_seconds > 180)
                )
            )

            status = (
                "running" if spec in self.solvers and not self.cancel_event.is_set()
                else ("won" if self.winner and self.winner.flag else "finished")
            )
            agents[spec] = {
                "findings": self.findings.get(spec, "")[:300],
                "status": status,
                "step_count": step_count,
                "cost_usd": round(cost_usd, 4),
                "confirmed": confirmed,
                "idle_seconds": idle_seconds,
                "tool_call_idle_s": tool_call_idle_s,
                "suspected_stuck": stuck,
            }

        return {
            "challenge": self.meta.name,
            "cancelled": self.cancel_event.is_set(),
            "winner": self.winner.flag if self.winner else None,
            "winner_spec": self.winner_spec,
            "agents": agents,
        }

    def kill_solver(self, model_spec: str) -> bool:
        """Cancel one specific solver in this swarm; siblings continue.

        Returns True if a matching solver task was cancelled. Used by
        the coordinator's `kill_solver` tool to terminate hung solvers
        without taking down the whole swarm — e.g. when codex/gpt-5.5
        is stuck at step=0 but codex/gpt-5.4-mini is making progress."""
        # Per-solver tasks are stashed in the same order as model_specs
        # by run() (one per spec), so we can locate the matching task
        # by index.
        try:
            idx = self.model_specs.index(model_spec)
        except ValueError:
            return False
        tasks = getattr(self, "_solver_tasks", [])
        if idx >= len(tasks):
            return False
        t = tasks[idx]
        if t.done():
            return False
        t.cancel()
        return True
