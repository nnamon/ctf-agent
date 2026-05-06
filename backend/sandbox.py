"""Docker sandbox for CTF challenge solving — native async via aiodocker.

This module hosts the canonical `LocalDockerEnv` (aliased as `DockerSandbox`
for legacy callers): one isolated Docker container per solver, mounted with
the challenge's distfiles read-only and a tempdir scratch read-write. It
formally implements the `ExecEnv` ABC from `backend.exec_env`, so any code
that needs to swap in an SSH-backed or Windows-backed env later can do so
without changing the solver tool surface.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import shlex
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

import aiodocker

from backend.exec_env import ExecEnv, ExecResult  # re-exported for back-compat

logger = logging.getLogger(__name__)

CONTAINER_LABEL = "ctf-agent"
RUN_LABEL = "ctf-agent.run"
# PID of the coord/CLI process that spawned this container. Used by
# `cleanup_dead_run_containers` at startup to detect leftovers from a
# crashed prior process and reclaim them — without it the only
# correlator we had was age (cleanup_stale_containers, default 6h),
# which lets a SIGKILL'd coord leak ~100 containers for hours.
COORD_PID_LABEL = "ctf-agent.coord_pid"
# Per-process run-id. Containers are tagged with this so concurrent
# ctf-agent invocations don't trample each other's sandboxes during cleanup.
# Operators can `docker ps --filter label=ctf-agent.run=<RUN_ID>` to inspect
# one run's containers from any other shell.
RUN_ID = uuid.uuid4().hex[:12]
COORD_PID = str(os.getpid())


def _pid_alive(pid: int) -> bool:
    """True iff a process with this PID is currently running.

    Uses kill(pid, 0) which delivers no signal but performs the standard
    permission/existence checks. ProcessLookupError → process is gone;
    PermissionError → process exists but isn't ours (treat as alive,
    we don't want to nuke another user's containers).
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

# Concurrency control
_start_semaphore: asyncio.Semaphore | None = None
_active_count: int = 0
_count_lock = asyncio.Lock()

_WARN_THRESHOLDS = {100, 200, 500}


def configure_semaphore(max_concurrent: int = 50) -> None:
    """Set the max concurrent container starts. Call once at startup."""
    global _start_semaphore
    _start_semaphore = asyncio.Semaphore(max_concurrent)


async def _track_start() -> None:
    global _active_count
    async with _count_lock:
        _active_count += 1
        if _active_count in _WARN_THRESHOLDS:
            logger.warning("Active containers: %d", _active_count)


async def _track_stop() -> None:
    global _active_count
    async with _count_lock:
        _active_count = max(0, _active_count - 1)


async def _delete_matching(filters: dict[str, list[str]]) -> int:
    """Delete every container matching the given Docker label filters.

    Returns the count actually deleted. Errors per-container are swallowed —
    individual delete failures shouldn't tank the whole sweep.
    """
    deleted = 0
    try:
        docker = aiodocker.Docker()
        try:
            containers = await docker.containers.list(all=True, filters=filters)
            for c in containers:
                try:
                    await c.delete(force=True)
                    deleted += 1
                except Exception:
                    pass
        finally:
            await docker.close()
    except Exception as e:
        logger.warning("Container cleanup failed (filters=%s): %s", filters, e)
    return deleted


async def cleanup_orphan_containers() -> None:
    """Kill leftover containers from THIS run only.

    Scoped via RUN_LABEL=RUN_ID so concurrent ctf-agent invocations don't
    delete each other's sandboxes. Genuine orphans from crashed-but-no-longer
    running processes are NOT cleaned up here — use cleanup_stale_containers
    or `ctf-agent cleanup --age N` for that.
    """
    deleted = await _delete_matching(
        {"label": [CONTAINER_LABEL, f"{RUN_LABEL}={RUN_ID}"]},
    )
    if deleted:
        logger.info("Cleaned up %d container(s) from this run", deleted)


async def cleanup_run_containers(run_id: str) -> int:
    """Kill all ctf-agent containers belonging to a given run-id."""
    deleted = await _delete_matching(
        {"label": [CONTAINER_LABEL, f"{RUN_LABEL}={run_id}"]},
    )
    if deleted:
        logger.info("Cleaned up %d container(s) from run %s", deleted, run_id)
    return deleted


async def cleanup_stale_containers(older_than_hours: float = 6.0) -> int:
    """Kill ctf-agent containers older than the cutoff, regardless of run-id.

    Use this to mop up SIGKILL-survivor containers from crashed processes,
    without disturbing containers from active concurrent runs. Younger
    containers are presumed to belong to a still-running ctf-agent.
    """
    cutoff = time.time() - (older_than_hours * 3600)
    deleted = 0
    try:
        docker = aiodocker.Docker()
        try:
            containers = await docker.containers.list(
                all=True,
                filters={"label": [CONTAINER_LABEL]},
            )
            for c in containers:
                try:
                    info = await c.show()
                    # "Created" looks like "2024-01-15T10:30:00.123456789Z"
                    raw = info.get("Created", "").rstrip("Z").split(".")[0]
                    if not raw:
                        continue
                    ts = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc).timestamp()
                    if ts < cutoff:
                        await c.delete(force=True)
                        deleted += 1
                except Exception:
                    pass
        finally:
            await docker.close()
    except Exception as e:
        logger.warning("Stale cleanup failed: %s", e)
    if deleted:
        logger.info("Cleaned up %d stale container(s) (>%sh old)", deleted, older_than_hours)
    return deleted


async def cleanup_all_containers() -> int:
    """Nuke every ctf-agent-labeled container, regardless of run-id or age.

    Replicates the pre-RUN_ID startup behaviour. Use only when no other
    ctf-agent processes are running — otherwise prefer cleanup_stale_containers
    or cleanup_run_containers.
    """
    deleted = await _delete_matching({"label": [CONTAINER_LABEL]})
    if deleted:
        logger.info("Cleaned up %d ctf-agent container(s)", deleted)
    return deleted


async def cleanup_dead_run_containers() -> int:
    """Kill ctf-agent containers whose owning coord PID is no longer alive.

    Called at CLI startup to reclaim leftovers from a SIGKILL'd prior
    process — the canonical "I killed the coord and now have 100 zombie
    sandboxes" case. Concurrent live ctf-agent processes are preserved:
    we only kill containers whose `ctf-agent.coord_pid` label points
    at a dead PID (or, for legacy containers without the label, that
    have aged past 30 min — younger ones might belong to a brand-new
    sibling coord that hasn't tagged yet).
    """
    deleted = 0
    legacy_cutoff = time.time() - (30 * 60)
    try:
        docker = aiodocker.Docker()
        try:
            containers = await docker.containers.list(
                all=True,
                filters={"label": [CONTAINER_LABEL]},
            )
            for c in containers:
                try:
                    info = await c.show()
                    labels = (info.get("Config") or {}).get("Labels") or {}
                    pid_label = labels.get(COORD_PID_LABEL, "")
                    if pid_label:
                        try:
                            pid = int(pid_label)
                        except ValueError:
                            continue
                        if pid == int(COORD_PID):
                            continue  # ours — never reclaim
                        if _pid_alive(pid):
                            continue  # another live coord — leave alone
                    else:
                        # Legacy container with no PID label: fall back
                        # to age. Anything <30 min old we leave alone
                        # to avoid racing a freshly-started sibling.
                        raw = info.get("Created", "").rstrip("Z").split(".")[0]
                        if not raw:
                            continue
                        ts = datetime.fromisoformat(raw).replace(
                            tzinfo=timezone.utc).timestamp()
                        if ts > legacy_cutoff:
                            continue
                    await c.delete(force=True)
                    deleted += 1
                except Exception:
                    pass
        finally:
            await docker.close()
    except Exception as e:
        logger.warning("Dead-run cleanup failed: %s", e)
    if deleted:
        logger.info(
            "Reclaimed %d container(s) from dead/legacy ctf-agent runs",
            deleted,
        )
    return deleted


@dataclass
class DockerSandbox(ExecEnv):
    """Isolated Docker container for a single solver agent.

    Implements `ExecEnv`. Registered under name "local" by default; multiple
    instances coexist (one per solver) so the registry-level name is shared
    but each solver's deps holds its own DockerSandbox instance.
    """

    # ExecEnv class-level metadata. Surfaced to the agent via `list_envs`.
    name: ClassVar[str] = "local"
    description: ClassVar[str] = (
        "Local Linux Docker sandbox with the full RE/pwn/forensics/web "
        "toolchain (gdb, ghidra, pwntools, ffuf, …). Default for any work "
        "that doesn't require a specific remote target."
    )
    scratch_dir: ClassVar[str] = "/challenge/workspace"

    image: str
    challenge_dir: str
    memory_limit: str = "16g"
    workspace_dir: str = ""
    # Files to bind-mount read-only at /challenge/context/<basename>. Used
    # by an external orchestrator to pass artifacts (writeups, unpacked
    # binaries, decryption keys) from prior chain-siblings to this solver.
    context_files: list[str] = field(default_factory=list)
    # If set, on stop() the workspace is copied here before rmtree. Lets
    # an orchestrator collect artifacts the solver wrote during its run.
    preserve_workspace_to: str = ""
    # Docker network mode override. Default "" → bridge (Docker's default).
    # Set to "container:<vpn-sidecar-name>" to share another container's
    # network namespace — used by HtbMachinesBackend so solver containers
    # route through the VPN sidecar's tun0 to reach 10.10.x.x targets.
    network_mode: str = ""
    _container: Any = field(default=None, repr=False)
    _docker: Any = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def container_id(self) -> str:
        """The Docker container ID, available after start()."""
        if not self._container:
            raise RuntimeError("Sandbox not started")
        return self._container.id

    @classmethod
    def from_settings(
        cls,
        *,
        challenge_dir: str,
        settings: Any,
        model_spec: str = "",
    ) -> DockerSandbox:
        """Build a sandbox from a Settings object, applying orchestration flags.

        Picks up `context_files` and `preserve_workspace_to` from the settings
        if present. The preserve path is composed as:
            <preserve_root>/<challenge_slug>/<model_spec>/workspace
        — challenge slug derives from the directory basename of challenge_dir,
        and model_spec is appended so concurrent solvers don't trample each
        other's workspace dumps.
        """
        preserve_root = getattr(settings, "preserve_workspace_to", "") or ""
        preserve = ""
        if preserve_root:
            slug = Path(challenge_dir).name or "challenge"
            parts = [preserve_root, slug]
            if model_spec:
                parts.append(model_spec)
            parts.append("workspace")
            preserve = str(Path(*parts))
        return cls(
            image=getattr(settings, "sandbox_image", "ctf-sandbox"),
            challenge_dir=challenge_dir,
            memory_limit=getattr(settings, "container_memory_limit", "4g"),
            context_files=list(getattr(settings, "context_files", []) or []),
            preserve_workspace_to=preserve,
            network_mode=getattr(settings, "sandbox_network_mode", "") or "",
        )

    def _parse_memory_limit(self) -> int:
        s = self.memory_limit.strip().lower()
        try:
            if s.endswith("g"):
                return int(s[:-1]) * 1024 * 1024 * 1024
            if s.endswith("m"):
                return int(s[:-1]) * 1024 * 1024
            return int(s)
        except (ValueError, IndexError):
            logger.warning("Invalid memory_limit %r, defaulting to 4GB", self.memory_limit)
            return 4 * 1024 * 1024 * 1024

    async def start(self) -> None:
        sem = _start_semaphore or asyncio.Semaphore(50)
        async with sem:
            self._docker = aiodocker.Docker()

            self.workspace_dir = tempfile.mkdtemp(prefix="ctf-workspace-")

            challenge_root = Path(self.challenge_dir).resolve()
            distfiles = str(challenge_root / "distfiles")
            meta_yml = str(challenge_root / "metadata.yml")

            binds: list[str] = [f"{self.workspace_dir}:/challenge/workspace:rw"]
            if Path(distfiles).exists():
                binds.append(f"{distfiles}:/challenge/distfiles:ro")
            if Path(meta_yml).exists():
                binds.append(f"{meta_yml}:/challenge/metadata.yml:ro")
            # Context files from prior siblings (orchestrator-supplied).
            # Mounted read-only at /challenge/context/<basename>. Source paths
            # are resolved to absolute so the bind doesn't depend on cwd.
            for src in self.context_files:
                src_abs = str(Path(src).resolve())
                if Path(src_abs).exists():
                    name = Path(src_abs).name
                    binds.append(f"{src_abs}:/challenge/context/{name}:ro")
                else:
                    logger.warning("Context file missing, skipping: %s", src)

            host_config = {
                "Binds": binds,
                "ExtraHosts": ["host.docker.internal:host-gateway"],
                "CapAdd": ["SYS_ADMIN", "SYS_PTRACE"],
                "SecurityOpt": ["seccomp=unconfined"],
                "Devices": [{"PathOnHost": "/dev/loop-control", "PathInContainer": "/dev/loop-control", "CgroupPermissions": "rwm"}],
                "Memory": self._parse_memory_limit(),
                "NanoCpus": int(2 * 1e9),
            }
            if self.network_mode:
                # When attaching to another container's network namespace
                # (VPN sidecar) ExtraHosts is invalid — Docker rejects the
                # create call. Drop it; the sidecar's namespace controls
                # routing entirely.
                host_config["NetworkMode"] = self.network_mode
                host_config.pop("ExtraHosts", None)
            config = {
                "Image": self.image,
                "Cmd": ["sleep", "infinity"],
                "WorkingDir": "/challenge",
                "Tty": False,
                "Labels": {
                    CONTAINER_LABEL: "true",
                    RUN_LABEL: RUN_ID,
                    COORD_PID_LABEL: COORD_PID,
                },
                "HostConfig": host_config,
            }

            self._container = await self._docker.containers.create(config)
            await self._container.start()
            await _track_start()

            info = await self._container.show()
            short_id = info["Id"][:12]
            logger.info("Sandbox started: %s", short_id)

    async def exec(self, command: str, timeout_s: int = 300) -> ExecResult:
        if not self._container:
            raise RuntimeError("Sandbox not started")

        async with self._lock:
            try:
                return await self._exec_inner(command, timeout_s)
            except aiodocker.exceptions.DockerError as e:
                # Container was deleted (e.g., sibling solver found the flag)
                return ExecResult(exit_code=-1, stdout="", stderr=f"Container gone: {e}")

    async def _exec_inner(self, command: str, timeout_s: int) -> ExecResult:
        # Wrap command with `timeout` so the container kills the process on expiry.
        # --signal=KILL ensures hard kill; --kill-after=5 is a safety net.
        wrapped = f"timeout --signal=KILL --kill-after=5 {timeout_s} bash -c {shlex.quote(command)}"
        exec_instance = await self._container.exec(
            cmd=["bash", "-c", wrapped],
            stdout=True,
            stderr=True,
            tty=False,
        )

        stream = exec_instance.start(detach=False)
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        async def _collect() -> None:
            while True:
                msg = await stream.read_out()
                if msg is None:
                    break
                if msg.stream == 1:
                    stdout_chunks.append(msg.data)
                else:
                    stderr_chunks.append(msg.data)

        try:
            # Give extra margin beyond the container-side timeout
            await asyncio.wait_for(_collect(), timeout=timeout_s + 30)
        except TimeoutError:
            try:
                await stream.close()
            except Exception:
                pass
            return ExecResult(
                exit_code=-1,
                stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
                stderr="Command timed out",
            )

        inspect = await exec_instance.inspect()
        exit_code = inspect.get("ExitCode", 0)

        return ExecResult(
            exit_code=exit_code,
            stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        )

    async def read_file(self, path: str) -> str | bytes:
        """Read a file from the container. Returns str for text, bytes for binary."""
        if not self._container:
            raise RuntimeError("Sandbox not started")

        try:
            tar = await asyncio.wait_for(
                self._container.get_archive(path),
                timeout=30,
            )
        except TimeoutError as e:
            raise TimeoutError(f"Timed out reading {path}") from e

        # aiodocker 0.26.0 returns tarfile.TarFile directly
        with tar:
            for member in tar:
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        data = f.read()
                        try:
                            return data.decode("utf-8")
                        except UnicodeDecodeError:
                            return data
        raise FileNotFoundError(f"No file found at {path}")

    async def read_file_bytes(self, path: str) -> bytes:
        """Read a file from the container as raw bytes."""
        result = await self.read_file(path)
        if isinstance(result, str):
            return result.encode("utf-8")
        return result

    async def write_file(self, path: str, content: str | bytes) -> None:
        """Write a file into the container via tar archive."""
        if not self._container:
            raise RuntimeError("Sandbox not started")

        if isinstance(content, str):
            content = content.encode("utf-8")

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=Path(path).name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)

        try:
            await asyncio.wait_for(
                self._container.put_archive(str(Path(path).parent), buf.getvalue()),
                timeout=30,
            )
        except TimeoutError as e:
            raise TimeoutError(f"Timed out writing {path}") from e

    async def copy_from(self, container_path: str, host_path: str) -> None:
        """Copy a file from the container to the host."""
        data = await self.read_file_bytes(container_path)
        Path(host_path).parent.mkdir(parents=True, exist_ok=True)
        Path(host_path).write_bytes(data)

    async def stop(self) -> None:
        if self._container:
            try:
                await self._container.delete(force=True)
            except Exception:
                pass
            self._container = None
            await _track_stop()

        if self._docker:
            try:
                await self._docker.close()
            except Exception:
                pass
            self._docker = None

        if self.workspace_dir:
            import shutil
            # Optionally copy the workspace to an external location before
            # discarding it — the orchestrator uses this to pass artifacts
            # (unpacked binaries, decrypted blobs, scripts the solver wrote)
            # between chained challenges.
            if self.preserve_workspace_to:
                try:
                    dest = Path(self.preserve_workspace_to)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if dest.exists():
                        shutil.rmtree(dest, ignore_errors=True)
                    shutil.copytree(self.workspace_dir, dest, dirs_exist_ok=True)
                    logger.info("Workspace preserved to %s", dest)
                except Exception as e:
                    logger.warning("Workspace preservation failed: %s", e)
            try:
                shutil.rmtree(self.workspace_dir, ignore_errors=True)
            except Exception:
                pass
            self.workspace_dir = ""
        logger.info("Sandbox stopped")
