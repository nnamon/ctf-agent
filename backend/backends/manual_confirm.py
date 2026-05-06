"""Manual-confirm decorator backend.

Wraps any concrete backend and gates each `submit_flag` call on operator
approval. Used when:

  - You want a human in the loop for every submission (e.g. you're
    paying attempt penalties and don't fully trust the swarm).
  - You're running a long autonomous session but want to review each
    candidate flag before it lands.
  - You're testing a new model and want to vet what it proposes
    before committing.

The decorator is transparent: every other Backend method is forwarded
unchanged to the inner backend.

Approval is read from stdin by default (assumes an interactive operator).
For headless / multi-operator setups, swap in a different `prompt_fn` —
the constructor takes a callable so the integration is easy to test and
to retarget at the existing operator-message HTTP endpoint if you want.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from backend.backends.base import Attempt, Backend, SubmitResult

logger = logging.getLogger(__name__)


# A prompt_fn takes (challenge_name, flag) and returns True to approve.
PromptFn = Callable[[str, str], bool]


def _stdin_prompt(challenge_name: str, flag: str) -> bool:
    """Default approval prompt: blocking y/N on stdin.

    Returns False (deny) if stdin isn't a TTY — we'd hang otherwise. The
    operator gets a clear message in that case so they know to either
    re-run with --no-confirm-flags or wire up a different prompt_fn.
    """
    if not sys.stdin.isatty():
        sys.stderr.write(
            f"\n[ManualConfirmBackend] stdin is not a TTY — auto-denying flag "
            f"{flag!r} for {challenge_name!r}. Re-run without --confirm-flags "
            f"or hook a non-stdin prompt_fn.\n"
        )
        sys.stderr.flush()
        return False

    sys.stderr.write(
        f"\n[ManualConfirmBackend] Submit flag for '{challenge_name}'?\n"
        f"  flag: {flag!r}\n"
        f"  [y]es / [N]o / [s]how-only (deny but don't return error)\n"
        f"> "
    )
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


@dataclass
class ManualConfirmBackend(Backend):
    """Decorator that pauses for operator approval before each submit."""

    inner: Backend
    prompt_fn: PromptFn = field(default=_stdin_prompt)

    # ---- public Backend API ----

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        # Run the (potentially blocking) prompt off the event loop so we
        # don't stall other async work. Default _stdin_prompt blocks on
        # readline() which would freeze the loop if invoked directly.
        approved = await asyncio.to_thread(self.prompt_fn, challenge_name, flag)
        if not approved:
            logger.info(
                "ManualConfirmBackend: operator denied %r for %r",
                flag, challenge_name,
            )
            return SubmitResult(
                status="incorrect",
                message="operator-denied",
                display=f"DENIED — {flag!r} not submitted (operator declined)",
            )
        return await self.inner.submit_flag(challenge_name, flag)

    def previous_attempts(self, challenge_name: str) -> list[Attempt]:
        return self.inner.previous_attempts(challenge_name)

    # ---- delegated Backend methods ----

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        return await self.inner.fetch_challenge_stubs()

    async def fetch_solved_names(self) -> set[str]:
        return await self.inner.fetch_solved_names()

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        return await self.inner.fetch_all_challenges()

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        return await self.inner.pull_challenge(challenge, output_dir)

    async def start_instance(self, challenge_name: str) -> str | None:
        return await self.inner.start_instance(challenge_name)

    async def stop_instance(self, challenge_name: str) -> None:
        await self.inner.stop_instance(challenge_name)

    async def close(self) -> None:
        await self.inner.close()
