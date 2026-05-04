"""Shared dependency types — avoids circular imports between agents and tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from backend.backends import Backend
from backend.cost_tracker import CostTracker
from backend.sandbox import DockerSandbox

if TYPE_CHECKING:
    from backend.message_bus import ChallengeMessageBus

# Type for the deduped submit callback: (flag) -> (display, is_confirmed)
SubmitFn = Callable[[str], Coroutine[Any, Any, tuple[str, bool]]]


@dataclass
class SolverDeps:
    sandbox: DockerSandbox
    ctfd: Backend
    challenge_dir: str
    challenge_name: str
    workspace_dir: str
    use_vision: bool
    cost_tracker: CostTracker | None = None
    confirmed_flag: str | None = None
    message_bus: ChallengeMessageBus | None = None
    model_spec: str = ""
    submit_fn: SubmitFn | None = None  # Deduped flag submission via swarm
    no_submit: bool = False
    notify_coordinator: Callable[[str], Coroutine[Any, Any, None]] | None = None
    # Writes a free-form note into the solver's trace for post-mortem use.
    note_fn: Callable[[str], None] | None = None


@dataclass
class CoordinatorDeps:
    ctfd: Backend
    cost_tracker: CostTracker
    settings: Any
    model_specs: list[str] = field(default_factory=list)
    challenges_root: str = "challenges"
    no_submit: bool = False
    max_concurrent_challenges: int = 10

    msg_port: int = 0  # 0 = auto-pick free port
    msg_host: str = "0.0.0.0"  # default: reachable on LAN/VPN; flip to 127.0.0.1 to lock down

    # Post-mortem writeup config
    no_writeup: bool = False
    writeup_model: str = "claude-opus-4-6"

    # Runtime state
    coordinator_inbox: asyncio.Queue = field(default_factory=asyncio.Queue)
    operator_inbox: asyncio.Queue = field(default_factory=asyncio.Queue)
    swarms: dict[str, Any] = field(default_factory=dict)
    swarm_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    results: dict[str, dict] = field(default_factory=dict)
    challenge_dirs: dict[str, str] = field(default_factory=dict)
    # Web dashboard EventHub — populated by coordinator_loop.run_event_loop
    # when the dashboard server starts. None when the dashboard is not
    # running (port bind failure, or the single-challenge cli path that
    # doesn't run a coordinator). Use deps.event_hub.broadcast(kind, ...)
    # to push live events into the SSE stream.
    event_hub: Any = None
    challenge_metas: dict[str, Any] = field(default_factory=dict)
