"""Generic SSH-based execution environment.

`SSHEnv` opens a single OpenSSH ControlMaster connection at `start()` and
multiplexes every subsequent `exec` / `read_file` / `write_file` over that
shared socket. New connections do *not* re-handshake — the marginal cost
per tool call is one extra `ssh` invocation that hands off to the master.

This is the right shape for any "the agent SSHes into a remote box" CTF
target: pwn.college dojos, HTB labs you've already VPN-attached to, your
own VPS, or a Windows host with OpenSSH-Server enabled.

Auth model:
  - Public-key only. Path to the private key is supplied at construction.
  - Host key is pinned via a known_hosts file written by the caller (or a
    private one created on first start when accept-new is allowed).

Concurrency:
  - A single `asyncio.Lock` serializes commands on this env. The model
    issues tool calls sequentially anyway, but the lock guards against
    accidental interleaving (e.g., a coordinator-driven trace read racing
    with the solver's bash call).

What this class explicitly does NOT do:
  - Manage the *remote target's lifecycle*. If the remote is a pwn.college
    workspace that needs to be spawned via an HTTP API before SSH lands,
    that's the wrapping subclass's job (see `exec_envs.pwncollege`). Pass a
    `pre_exec_hook` if you want this class to invoke a callback before
    every command — useful when the target may have idled out.
  - Re-establish the connection if the master dies mid-run. Failure
    bubbles up as a non-zero exit code; the caller (or the agent) decides
    what to do next.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import shlex
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import ClassVar

from backend.exec_env import ExecEnv, ExecResult

logger = logging.getLogger(__name__)


@dataclass
class SSHEnv(ExecEnv):
    """SSH-multiplexed remote shell as an `ExecEnv`.

    Intended to be subclassed for platform-specific behavior (e.g.
    pwn.college's workspace pre-flight); pure SSHEnv is also usable
    directly for any "I have a key and a host" target.
    """

    name: ClassVar[str] = "ssh"
    description: ClassVar[str] = (
        "Remote Linux shell over SSH. Use for work that must happen on the "
        "remote target itself (e.g. reading a flag, exploiting a service "
        "running there). Local tools are NOT available on this side; use "
        "`local` for scratch work and transfer artifacts over with `scp`/"
        "`transfer`."
    )
    scratch_dir: ClassVar[str] = "/tmp"

    # --- connection params ---
    host: str = ""
    user: str = "root"
    port: int = 22
    identity_file: str = ""
    known_hosts_file: str = ""

    # Extra `-o key=value` options. Caller-supplied entries win over our
    # defaults — useful for `StrictHostKeyChecking=accept-new` on first
    # contact with a fresh target.
    ssh_options: dict[str, str] = field(default_factory=dict)

    # Called before every exec/read_file/write_file. Use this for "make
    # sure the remote target exists" logic (e.g. POST /api/v1/docker for
    # pwn.college). Failures abort the call. Reentrant — must tolerate
    # being called rapidly without doing redundant work.
    pre_exec_hook: Callable[[], Awaitable[None]] | None = None

    # --- internal state ---
    _ctl_dir: str = field(default="", repr=False)
    _ctl_path: str = field(default="", repr=False)
    _started: bool = field(default=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    # ---------- lifecycle ----------

    async def start(self) -> None:
        if self._started:
            return
        if not self.host:
            raise ValueError("SSHEnv.host must be set")
        if not self.identity_file:
            raise ValueError("SSHEnv.identity_file must be set")
        if not os.path.isfile(self.identity_file):
            raise FileNotFoundError(f"SSH identity file not found: {self.identity_file}")
        # OpenSSH will refuse keys with permissive perms. Lock down to 0600
        # in case the caller wrote them with the umask default.
        try:
            os.chmod(self.identity_file, 0o600)
        except OSError as e:
            logger.warning("Could not chmod identity %s: %s", self.identity_file, e)

        self._ctl_dir = tempfile.mkdtemp(prefix="sshenv-")
        # %C expands to a hash of (l@h:p, user) so multiple masters can coexist
        self._ctl_path = os.path.join(self._ctl_dir, "ctl-%C")

        master_cmd = [
            "ssh",
            *self._common_opts(),
            "-M",            # become a master
            "-N",            # no remote command — just hold the connection
            "-f",            # background once the connection is up
            f"{self.user}@{self.host}",
        ]
        logger.debug("SSHEnv master cmd: %s", " ".join(master_cmd))
        proc = await asyncio.create_subprocess_exec(
            *master_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except TimeoutError:
            proc.kill()
            raise RuntimeError(f"SSH master to {self.user}@{self.host} timed out")
        if proc.returncode != 0:
            err = (stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"SSH master to {self.user}@{self.host} failed (rc={proc.returncode}): {err}"
            )

        # Quick sanity exec — if the master succeeded but the shell can't
        # start (e.g. the remote container is dead), surface that now.
        probe = await self._raw_exec("echo __sshenv_ok__", timeout_s=10)
        if probe.exit_code != 0 or "__sshenv_ok__" not in probe.stdout:
            raise RuntimeError(
                f"SSH master is up but probe failed: rc={probe.exit_code} "
                f"stderr={probe.stderr!r}"
            )

        self._started = True
        logger.info("SSHEnv started: %s@%s:%s", self.user, self.host, self.port)

    async def stop(self) -> None:
        if not self._started:
            return
        # Ask the master to exit cleanly.
        try:
            proc = await asyncio.create_subprocess_exec(
                "ssh",
                *self._common_opts(),
                "-O", "exit",
                f"{self.user}@{self.host}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (TimeoutError, OSError):
            pass

        if self._ctl_dir and os.path.isdir(self._ctl_dir):
            import shutil
            shutil.rmtree(self._ctl_dir, ignore_errors=True)

        self._started = False
        self._ctl_dir = ""
        self._ctl_path = ""
        logger.info("SSHEnv stopped: %s@%s", self.user, self.host)

    # ---------- ExecEnv surface ----------

    async def exec(self, command: str, timeout_s: int = 300) -> ExecResult:
        await self._ensure_ready()
        async with self._lock:
            return await self._raw_exec(command, timeout_s=timeout_s)

    async def read_file(self, path: str) -> str | bytes:
        await self._ensure_ready()
        async with self._lock:
            # `base64 -w0` survives shells with weird LANG settings and
            # protects against newline mangling. -w0 gives one long line
            # which we decode after.
            r = await self._raw_exec(
                f"base64 -w0 < {shlex.quote(path)}", timeout_s=60
            )
            if r.exit_code != 0:
                # Mirror DockerSandbox semantics: propagate as exception so
                # tools.core can format it.
                raise FileNotFoundError(
                    f"read_file({path}) failed: rc={r.exit_code} stderr={r.stderr.strip()!r}"
                )
            data = base64.b64decode(r.stdout.strip() or b"")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data

    async def write_file(self, path: str, content: str | bytes) -> None:
        await self._ensure_ready()
        if isinstance(content, str):
            content = content.encode("utf-8")
        encoded = base64.b64encode(content).decode("ascii")
        # `base64 -d` reads stdin and writes the decoded bytes to `path`.
        # We pass the b64 payload via stdin to dodge ARG_MAX limits on
        # large uploads (default 128 KiB on macOS).
        async with self._lock:
            r = await self._raw_exec(
                f"base64 -d > {shlex.quote(path)}",
                timeout_s=60,
                stdin=encoded.encode("ascii"),
            )
            if r.exit_code != 0:
                raise OSError(
                    f"write_file({path}) failed: rc={r.exit_code} stderr={r.stderr.strip()!r}"
                )

    # ---------- internals ----------

    def _common_opts(self) -> list[str]:
        """SSH options shared by master and child invocations.

        Order matters when callers add to `ssh_options`: their entries are
        emitted last so they override our defaults.
        """
        opts: dict[str, str] = {
            "ControlMaster": "auto",
            "ControlPath": self._ctl_path or os.path.join(tempfile.gettempdir(), "ctl-%C"),
            "ControlPersist": "10m",
            "BatchMode": "yes",                # never prompt for password
            "PasswordAuthentication": "no",
            "ServerAliveInterval": "30",
            "ServerAliveCountMax": "3",
            "ConnectTimeout": "10",
            "Port": str(self.port),
            "IdentityFile": self.identity_file,
            "IdentitiesOnly": "yes",           # don't try every key in the agent
            "LogLevel": "ERROR",
        }
        if self.known_hosts_file:
            opts["UserKnownHostsFile"] = self.known_hosts_file
            opts["StrictHostKeyChecking"] = "yes"
        else:
            # If the caller hasn't pinned, default to TOFU. This is fine
            # for personal CTF targets but the pwncollege wrapper SHOULD
            # always supply a known_hosts_file with the dojo's pinned key.
            opts.setdefault("StrictHostKeyChecking", "accept-new")

        # Caller overrides win
        opts.update(self.ssh_options)

        result: list[str] = []
        for k, v in opts.items():
            result.extend(["-o", f"{k}={v}"])
        return result

    async def _ensure_ready(self) -> None:
        if not self._started:
            raise RuntimeError(f"SSHEnv {self.name!r} not started")
        if self.pre_exec_hook is not None:
            await self.pre_exec_hook()

    async def _raw_exec(
        self,
        command: str,
        timeout_s: int = 300,
        stdin: bytes | None = None,
    ) -> ExecResult:
        """Run a command via the established master. No lock, no hook —
        the caller has already covered both."""
        wrapped = (
            f"timeout --signal=KILL --kill-after=5 {timeout_s} "
            f"bash -c {shlex.quote(command)}"
        )
        cmd = [
            "ssh",
            *self._common_opts(),
            f"{self.user}@{self.host}",
            wrapped,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin),
                timeout=timeout_s + 30,
            )
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout_s}s",
            )
        return ExecResult(
            exit_code=proc.returncode or 0,
            stdout=(stdout_b or b"").decode("utf-8", errors="replace"),
            stderr=(stderr_b or b"").decode("utf-8", errors="replace"),
        )
