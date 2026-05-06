"""Solver result type, status constants, and solver protocol — shared across all backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# Status constants
FLAG_FOUND = "flag_found"
GAVE_UP = "gave_up"
CANCELLED = "cancelled"
ERROR = "error"
QUOTA_ERROR = "quota_error"

# Flag confirmation markers from CTFd
CORRECT_MARKERS = ("CORRECT", "ALREADY SOLVED")


@dataclass
class SolverResult:
    flag: str | None
    status: str
    findings_summary: str
    step_count: int
    cost_usd: float
    log_path: str
    # Set when the failure cannot be recovered by another turn (e.g. codex
    # remote-compaction overflowed the model window — the next turn will hit
    # the same wall). Tells swarm.py to break the run loop immediately
    # instead of bumping and retrying 3× before the consecutive-error cap.
    terminal: bool = False


class SolverProtocol(Protocol):
    """Common interface for all solver backends (Pydantic AI, Claude SDK, Codex)."""

    model_spec: str
    agent_name: str
    sandbox: object

    async def start(self) -> None: ...
    async def run_until_done_or_gave_up(self) -> SolverResult: ...
    def bump(self, insights: str) -> None: ...
    async def stop(self) -> None: ...
