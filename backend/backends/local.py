"""Local / no-op backend.

Used when there's no real CTF server in the loop — pure local-file
challenges, dry-run grading, or `--no-submit` workflows where flag
acceptance is verified out-of-band by the operator.

`submit_flag` logs and returns `SubmitResult("unknown", ..., ...)` so
solvers don't crash when the harness is wired to call it.

`fetch_*` methods return empty containers so coordinator-mode loops
no-op cleanly without having to special-case the absence of a server.

`pull_challenge` raises NotImplementedError because there's nothing to
pull from. Use the manual `metadata.yml` + `distfiles/` workflow
instead — see the project README.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from backend.backends.base import Backend, SubmitResult

logger = logging.getLogger(__name__)


@dataclass
class LocalBackend(Backend):
    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        msg = f'LocalBackend (no remote): would submit {flag!r} for "{challenge_name}"'
        logger.info(msg)
        return SubmitResult(status="unknown", message="no backend configured", display=msg)

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        return []

    async def fetch_solved_names(self) -> set[str]:
        return set()

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        return []

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        raise NotImplementedError(
            "LocalBackend has no remote source. Author challenge dirs by hand "
            "(metadata.yml + distfiles/) under your --challenges-dir."
        )

    async def close(self) -> None:
        return None
