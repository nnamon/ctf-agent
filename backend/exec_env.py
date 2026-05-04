"""Execution environment abstraction.

A solver agent's tool calls (bash, read_file, write_file) ultimately have to
run *somewhere*. Historically that was always a local Docker sandbox, but
some CTF platforms (pwn.college, HTB, your-own-VPS) ship their own remote
shell that's the actual execution surface for a challenge — solving "happens
inside" their box, and our sandbox is just the orchestrator.

`ExecEnv` is the smallest stable interface a solver depends on. Concrete
implementations:

  - `LocalDockerEnv` (alias for the existing `DockerSandbox`): per-solver
    container on the host, full toolchain from `Dockerfile.sandbox`.
  - `SSHEnv` (Phase 2): persistent shell on a remote host via key-auth SSH
    with ControlMaster. First customer is pwn.college.
  - `WinSSHEnv` (future): OpenSSH-on-Windows defaulting to PowerShell.

Multiple envs can be registered simultaneously and the agent picks one per
tool call via a `target` argument. `EnvRegistry` lazily starts envs on first
use so an unused Windows VM doesn't pay boot cost.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


class ExecEnv(ABC):
    """Abstract execution environment for solver tool calls.

    Implementations must provide `start`, `stop`, `exec`, `read_file`, and
    `write_file`. `read_file_bytes` has a default implementation derived
    from `read_file`; subclasses may override for efficiency.

    Concurrency contract: `exec`, `read_file`, `write_file` may be called
    from multiple coroutines on the same instance; implementations are
    responsible for any internal serialization needed (the local Docker
    impl uses a per-instance `asyncio.Lock`; the SSH impl will use a
    ControlMaster + per-channel sequencing).

    Class-level metadata (`name`, `description`, `scratch_dir`) is surfaced
    to the agent via the `list_envs` tool and tool-result framing. Override
    these as `ClassVar` declarations on each subclass.
    """

    # Stable identifier the agent uses to address this env: "local",
    # "pwncollege", "win-lab". Must be a short, identifier-ish string.
    name: ClassVar[str] = "default"

    # One-line description shown in the agent's system prompt and the
    # `list_envs` tool. Tell the agent when to pick this env over others.
    description: ClassVar[str] = ""

    # Per-env path the agent should treat as a writable scratch dir.
    # Surfaced in the prompt. Empty if there's no canonical scratch dir.
    scratch_dir: ClassVar[str] = ""

    @abstractmethod
    async def start(self) -> None:
        """Bring the environment up. Idempotent — calling twice is a no-op."""

    @abstractmethod
    async def stop(self) -> None:
        """Tear the environment down. Idempotent."""

    @abstractmethod
    async def exec(self, command: str, timeout_s: int = 300) -> ExecResult:
        """Run a shell command. Implementations MUST enforce timeout."""

    @abstractmethod
    async def read_file(self, path: str) -> str | bytes:
        """Read a file. Returns str for UTF-8 text, bytes otherwise."""

    @abstractmethod
    async def write_file(self, path: str, content: str | bytes) -> None:
        """Write a file. Parent dirs must already exist."""

    async def read_file_bytes(self, path: str) -> bytes:
        """Convenience: read a file as raw bytes regardless of encoding."""
        result = await self.read_file(path)
        if isinstance(result, str):
            return result.encode("utf-8")
        return result


class EnvRegistry:
    """Holds the exec envs available to a single solver / coordinator.

    Lifecycle:
      registry.register(LocalDockerEnv(...))
      registry.register(SSHEnv(...))
      env = await registry.get("pwncollege")   # lazy-starts on first get
      ...
      await registry.stop_all()                # clean shutdown

    Lazy-start matters because expensive envs (Windows VM, pwn.college
    workspace pre-flight) shouldn't pay startup cost if the agent never
    actually targets them. A per-name `asyncio.Lock` prevents double-init
    when concurrent tool calls race for the same env.
    """

    def __init__(self) -> None:
        self._envs: dict[str, ExecEnv] = {}
        self._started: set[str] = set()
        self._locks: dict[str, asyncio.Lock] = {}

    def register(self, env: ExecEnv) -> None:
        if not env.name:
            raise ValueError("ExecEnv.name must be set on the subclass")
        self._envs[env.name] = env
        self._locks.setdefault(env.name, asyncio.Lock())

    def has(self, name: str) -> bool:
        return name in self._envs

    @property
    def names(self) -> list[str]:
        return list(self._envs.keys())

    def describe(self) -> list[dict[str, str]]:
        """Return [{name, description, scratch_dir}] for every registered env.

        Surfaced verbatim to the agent via the `list_envs` tool.
        """
        return [
            {
                "name": e.name,
                "description": e.description,
                "scratch_dir": e.scratch_dir,
            }
            for e in self._envs.values()
        ]

    async def get(self, name: str) -> ExecEnv:
        """Return a started env. Calls `.start()` on first access."""
        if name not in self._envs:
            raise KeyError(
                f"No exec env named {name!r}. Available: {sorted(self._envs)}"
            )
        async with self._locks[name]:
            if name not in self._started:
                logger.info("Starting exec env: %s", name)
                await self._envs[name].start()
                self._started.add(name)
        return self._envs[name]

    def get_unstarted(self, name: str) -> ExecEnv:
        """Return the env without starting it. For introspection only —
        callers who plan to actually exec must use `await get(name)`."""
        if name not in self._envs:
            raise KeyError(name)
        return self._envs[name]

    async def stop_all(self) -> None:
        """Stop every started env, swallowing per-env failures."""
        for name in list(self._started):
            try:
                await self._envs[name].stop()
            except Exception as e:
                logger.warning("Stop failed for env %r: %s", name, e)
        self._started.clear()

    def fork(self) -> "EnvRegistry":
        """Return a child registry that shares all currently-registered envs.

        The child can `register()` additional envs (e.g. a per-solver local
        Docker container) without affecting the parent. Started-state is
        also forked: envs already started in the parent remain marked
        started in the child, so the child won't double-start them.
        Lifecycle of the parent's envs stays the parent's responsibility —
        the child's `stop_all()` only stops envs it registered itself.
        """
        child = EnvRegistry()
        for name, env in self._envs.items():
            child._envs[name] = env
            child._locks[name] = self._locks[name]
            if name in self._started:
                child._started.add(name)
        # Track which envs the child registered itself (for scoped stop).
        child._parent_envs = set(self._envs.keys())
        return child

    async def stop_all_owned(self) -> None:
        """Like stop_all, but only stops envs not inherited from a parent.

        Parents register their own remote envs (pwn.college, …) and own
        their lifecycle; a forked child just borrows them. The child's
        own additions (e.g. a per-solver Docker sandbox) are stopped here.
        """
        parent = getattr(self, "_parent_envs", set())
        for name in list(self._started):
            if name in parent:
                continue
            try:
                await self._envs[name].stop()
            except Exception as e:
                logger.warning("Stop failed for env %r: %s", name, e)
            self._started.discard(name)
