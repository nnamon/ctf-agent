"""pwn.college workspace as an `ExecEnv`.

Wraps `SSHEnv` with the platform-specific pre-flight that pwn.college
needs:

  - Make sure the user has a public key registered (POST /api/v1/keys).
  - Make sure a workspace container is running for the *current* challenge
    (POST /api/v1/docker {dojo,module,challenge}). The server-side
    docker_locked decorator means this also tears down any previous
    workspace, so we set the active challenge once per challenge attempt
    rather than per command.
  - Pin `dojo.pwn.college`'s host key in a private known_hosts file.

Solvers run inside our local Docker sandbox as before. They reach into
this env via `target="pwncollege"` on bash/read_file/write_file tool calls
(see Phase 2d). Inside the workspace they're the `hacker` user (UID 1000),
with `/flag` only readable by root and the platform's full `/nix` toolchain
mounted at `/run/dojo/bin/`.

Key material: a per-session ed25519 keypair is auto-generated in the
session's `secrets/` dir on first start. The public half is uploaded to
pwn.college (idempotent) so SSH lands in the user's container.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from backend.exec_envs.ssh import SSHEnv

logger = logging.getLogger(__name__)


@dataclass
class PwnCollegeEnv(SSHEnv):
    """SSH-into-pwn.college-workspace exec environment.

    The challenge to attempt is set via `set_active_challenge()` BEFORE the
    first tool call targets this env. Once set, every exec/read_file/
    write_file ensures the workspace is running for that challenge — if
    the user navigated to a different challenge in their browser, we
    silently re-spawn the original.
    """

    name: ClassVar[str] = "pwncollege"
    description: ClassVar[str] = (
        "pwn.college workspace (remote Linux container at dojo.pwn.college). "
        "This is the ONLY place the real `/flag` for this challenge lives — "
        "you must read it from here (you run as the `hacker` user; /flag is "
        "root-readable, so you'll need to interact with the challenge program "
        "to capture it). The platform's full toolchain is at /run/dojo/bin/."
    )
    scratch_dir: ClassVar[str] = "/home/hacker"

    # The pwn.college backend with workspace API methods (upload_ssh_key,
    # start_workspace, reset_workspace_home). Required.
    backend: object | None = None

    # Active challenge triple. set_active_challenge() updates this; the
    # pre-exec hook ensures the workspace matches.
    active_dojo: str = ""
    active_module: str = ""
    active_challenge: str = ""

    # If True, reset_home() is invoked when set_active_challenge changes
    # to a different challenge. Useful for hygiene between solver runs;
    # disable when chaining challenges that depend on prior artifacts.
    reset_home_on_switch: bool = True

    # Tracks the challenge the workspace was last spawned for. If
    # active_* is updated to point elsewhere, the next pre-exec hook
    # re-spawns. Populated lazily.
    _spawned_for: tuple[str, str, str] | None = field(default=None, repr=False)
    _spawn_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    # Public key text awaiting upload to pwn.college. Set by the env
    # builder before start(); cleared after the upload succeeds.
    _pending_pubkey: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        # Wire SSHEnv's per-exec hook to our spawn-ensurer.
        self.pre_exec_hook = self._ensure_workspace_for_active

    async def start(self) -> None:
        """Upload the pubkey, spawn the active workspace, then open SSH.

        Order matters: `super().start()` opens the SSH ControlMaster and
        probes with `echo __sshenv_ok__`, which requires both (a) the
        public key registered server-side, and (b) a running workspace
        container for sshd to `docker exec` into. The orchestrator must
        therefore call `set_active_challenge()` BEFORE the first tool
        call targets this env (which triggers `registry.get("pwncollege")`
        which calls this `start`).
        """
        if self._started:
            return
        if self.backend is None:
            raise RuntimeError("PwnCollegeEnv.backend is required")
        if not self.active_challenge:
            raise RuntimeError(
                "PwnCollegeEnv.start: no active challenge. The orchestrator "
                "must call set_active_challenge(dojo, module, challenge) "
                "before the first tool call targets this env."
            )

        # 1. Idempotent pubkey upload. Failures here are not fatal — the
        #    operator may have uploaded the key out-of-band, in which
        #    case the SSH probe still succeeds.
        if self._pending_pubkey:
            try:
                await self.backend.upload_ssh_key(self._pending_pubkey)  # type: ignore[attr-defined]
            except Exception as e:
                logger.warning("pwn.college upload_ssh_key failed (continuing): %s", e)
            self._pending_pubkey = ""

        # 2. Spawn workspace for the active challenge.
        async with self._spawn_lock:
            await self.backend.start_workspace(  # type: ignore[attr-defined]
                self.active_dojo, self.active_module, self.active_challenge
            )
            self._spawned_for = (
                self.active_dojo, self.active_module, self.active_challenge,
            )

        # 3. SSH master + sanity probe.
        await super().start()

    def set_active_challenge(self, dojo: str, module: str, challenge: str) -> None:
        """Declare which (dojo, module, challenge) the next tool calls target.

        The actual `/api/v1/docker` POST is deferred to the first tool call
        so we don't spend a workspace boot if the agent never targets this
        env."""
        new = (dojo, module, challenge)
        if new == (self.active_dojo, self.active_module, self.active_challenge):
            return
        self.active_dojo, self.active_module, self.active_challenge = new
        # Force re-spawn on next exec.
        self._spawned_for = None
        logger.info("PwnCollegeEnv active challenge -> %s/%s/%s", *new)

    async def _ensure_workspace_for_active(self) -> None:
        if not self.active_challenge:
            raise RuntimeError(
                "PwnCollegeEnv used without set_active_challenge(); call it "
                "before the solver starts issuing tool calls."
            )
        target = (self.active_dojo, self.active_module, self.active_challenge)
        if self._spawned_for == target:
            return
        async with self._spawn_lock:
            if self._spawned_for == target:
                return
            if self.backend is None:
                raise RuntimeError("PwnCollegeEnv.backend is not set")
            # Optional home reset between challenges
            if self.reset_home_on_switch and self._spawned_for is not None:
                try:
                    await self.backend.reset_workspace_home()  # type: ignore[attr-defined]
                except Exception as e:
                    logger.warning("reset_home failed (non-fatal): %s", e)
            await self.backend.start_workspace(  # type: ignore[attr-defined]
                self.active_dojo, self.active_module, self.active_challenge
            )
            self._spawned_for = target


# ---------- key + known_hosts management ----------

def ensure_keypair(private_path: Path) -> tuple[str, str]:
    """Create an ed25519 keypair if missing. Returns (private_path, public_key_text).

    Files are written 0600/0644 under the parent dir (which must already
    exist). Idempotent — existing keypair is returned as-is.
    """
    private_path = Path(private_path)
    public_path = Path(str(private_path) + ".pub")
    private_path.parent.mkdir(parents=True, exist_ok=True)

    if private_path.exists() and public_path.exists():
        return str(private_path), public_path.read_text(encoding="utf-8").strip()

    # Use ssh-keygen — it's portable and handles the openssh format
    # correctly. `-N ''` for no passphrase; `-q` for quiet; `-C` comment
    # so the key is identifiable in the user's authorized_keys.
    cmd = [
        "ssh-keygen",
        "-t", "ed25519",
        "-N", "",
        "-q",
        "-f", str(private_path),
        "-C", f"ctf-agent@{os.uname().nodename}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh-keygen failed (rc={result.returncode}): {result.stderr.strip()}"
        )

    private_path.chmod(0o600)
    public_path.chmod(0o644)
    pub = public_path.read_text(encoding="utf-8").strip()
    logger.info("Generated ed25519 keypair at %s", private_path)
    return str(private_path), pub


def pin_known_host(host: str, port: int, known_hosts_path: Path) -> None:
    """Use ssh-keyscan to fetch host keys for `host:port` and write them
    to `known_hosts_path` if absent.

    Idempotent: existing entries are preserved. Fails loudly on keyscan
    error so the caller can decide whether to fall back to TOFU mode."""
    known_hosts_path = Path(known_hosts_path)
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True)

    if known_hosts_path.exists():
        existing = known_hosts_path.read_text(encoding="utf-8")
        if host in existing:
            return  # already pinned; trust the caller picked the right key

    # ssh-keyscan -p <port> -t ed25519,rsa <host>
    cmd = ["ssh-keyscan", "-p", str(port), "-t", "ed25519,rsa", host]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh-keyscan {host}:{port} failed: {result.stderr.strip()}"
        )
    if not result.stdout.strip():
        raise RuntimeError(f"ssh-keyscan {host}:{port} returned no keys")

    with known_hosts_path.open("a", encoding="utf-8") as fh:
        fh.write(result.stdout)
    known_hosts_path.chmod(0o644)
    logger.info("Pinned host keys for %s:%s -> %s", host, port, known_hosts_path)
