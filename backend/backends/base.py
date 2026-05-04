"""Abstract Backend interface.

Every CTF integration (CTFd, rCTF, local-files-only, custom HTTP service,
etc.) implements this surface. Solvers and the coordinator depend ONLY on
this ABC, not on any concrete implementation.

The `dict[str, Any]` shape returned by the fetch_* methods follows the
CTFd JSON conventions for now (keys: `id`, `name`, `category`, `value`,
`description`, `files`, `tags`, `hints`, `connection_info`, `solves`,
`type`). New backends should map their native shape into this dict.
A future refactor may promote it to a structured dataclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class SubmitResult:
    status: str   # "correct" | "already_solved" | "incorrect" | "unknown"
    message: str
    display: str  # human-readable summary suitable for log output


@dataclass
class Attempt:
    """A historical flag-submission attempt, persisted by AttemptLogBackend."""
    challenge_name: str
    flag: str
    status: str
    message: str
    ts: int  # unix epoch seconds


class Backend(ABC):
    """Generic backend protocol for flag submission, listing, and fetch."""

    # ---- submission (used by every solver) ----
    @abstractmethod
    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        ...

    # ---- attempt history (optional; default = no history) ----
    def previous_attempts(self, challenge_name: str) -> list[Attempt]:
        """Return prior submission attempts for this challenge. Default
        implementation returns []; AttemptLogBackend overrides this to
        query its persistent store."""
        return []

    # ---- listing / poll (used by coordinator + poller) ----
    @abstractmethod
    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        """Return a lightweight list of challenge dicts (no per-challenge detail)."""

    @abstractmethod
    async def fetch_solved_names(self) -> set[str]:
        """Return the set of challenge names already solved by the current
        user/team. Used by the poller to skip them."""

    # ---- detailed fetch + sync (used by `pull_challenges.py`) ----
    @abstractmethod
    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        """Return full challenge dicts including descriptions, hints, files."""

    @abstractmethod
    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Materialise a challenge to disk: distfiles + metadata.yml.

        Returns the on-disk challenge directory path.
        """

    # ---- lifecycle ----
    @abstractmethod
    async def close(self) -> None:
        """Release any open connections / resources."""
