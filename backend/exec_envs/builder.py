"""Build an `EnvRegistry` from session settings.

Reads `Settings.exec_envs` (and per-env config: `pwncollege_*`) plus the
session's filesystem layout (for SSH key + known_hosts placement) and
returns a fully configured registry. The local Docker env is always
registered under `name="local"`. Other envs are added when the session
has been told to provision them.

The builder is intentionally tolerant: if pwn.college is requested but
not yet usable (no session cookie set, can't pin host keys), it logs a
warning and skips that env rather than failing the whole solver run. The
agent will simply not see `pwncollege` in `list_envs` and any `target=
"pwncollege"` call will return a clear "unknown env" error — much easier
to recover from than a hard exit at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from backend.exec_env import EnvRegistry

if TYPE_CHECKING:
    from backend.backends import Backend
    from backend.config import Settings
    from backend.sandbox import DockerSandbox
    from backend.session import SessionContext

logger = logging.getLogger(__name__)


def build_env_registry(
    *,
    settings: "Settings",
    session: "SessionContext | None" = None,
    backend: "Backend | None" = None,
    sandbox: "DockerSandbox | None" = None,
) -> EnvRegistry:
    """Construct an EnvRegistry for one solver / coordinator session.

    `sandbox` is registered as the `local` env if supplied — pass the
    instance you already constructed for a solver so the registry shares
    it (same container, no double-init).

    `backend` is consulted only when registering platform-specific envs
    that need API calls (pwn.college's workspace pre-flight, key upload).
    Passing `None` means "no platform env, just local."
    """
    registry = EnvRegistry()

    if sandbox is not None:
        registry.register(sandbox)

    requested = list(settings.exec_envs or [])
    # If the backend is pwn.college, auto-include the matching env even
    # when the operator hasn't listed it explicitly — that's the obvious
    # default and surprising to leave off.
    if (
        getattr(settings, "backend_kind", "").lower() in ("pwncollege", "pwn.college", "dojo")
        and "pwncollege" not in requested
    ):
        requested.append("pwncollege")

    for env_name in requested:
        env_name = env_name.strip().lower()
        if env_name == "pwncollege":
            env = _build_pwncollege_env(settings, session, backend)
            if env is not None:
                registry.register(env)
        elif env_name in ("", "local"):
            # local is always present; ignore explicit listings.
            pass
        else:
            logger.warning("Unknown exec_envs entry %r — skipped", env_name)

    return registry


def _unwrap_backend(backend):
    """Peel decorator layers (AttemptLogBackend, ManualConfirmBackend) to
    reach the concrete backend. Returns `backend` unchanged if it has no
    `inner`."""
    seen = set()
    cur = backend
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        inner = getattr(cur, "inner", None)
        if inner is None:
            return cur
        cur = inner
    return backend


def _build_pwncollege_env(
    settings: "Settings",
    session: "SessionContext | None",
    backend: "Backend | None",
):
    """Provision the pwn.college env. Returns None if prerequisites aren't met."""
    # Avoid forcing pwn.college imports on operators who never use it.
    from backend.backends.pwncollege import PwnCollegeBackend
    from backend.exec_envs.pwncollege import (
        PwnCollegeEnv,
        ensure_keypair,
        pin_known_host,
    )

    # The backend may be wrapped in AttemptLogBackend / ManualConfirmBackend
    # decorators — peel them off so we can reach the actual PwnCollegeBackend
    # for the workspace API calls. The decorator chain handles flag-submit
    # paths; the env needs the concrete backend.
    pwn_backend = _unwrap_backend(backend)

    if not isinstance(pwn_backend, PwnCollegeBackend):
        # The env only makes sense paired with the matching backend (it
        # calls into backend.start_workspace etc.). If the operator
        # selected the env but a different backend, refuse to register.
        logger.warning(
            "exec_envs includes 'pwncollege' but backend_kind is %r — "
            "skipping; set backend_kind=pwncollege to enable.",
            getattr(settings, "backend_kind", "?"),
        )
        return None

    # Resolve where the SSH key + known_hosts files live. Per-session
    # secrets/ keeps them out of the sessions/<name>/.env (which is
    # already in version control's ignore list).
    if settings.pwncollege_ssh_key:
        key_path = Path(settings.pwncollege_ssh_key).expanduser()
    elif session is not None:
        key_path = session.root / "secrets" / "pwncollege_id"
    else:
        logger.warning(
            "pwncollege env: no SSH key path and no session — cannot place keypair"
        )
        return None

    try:
        priv, pub = ensure_keypair(key_path)
    except Exception as e:
        logger.warning("pwncollege env: ensure_keypair failed: %s", e)
        return None

    known_hosts_path = key_path.parent / "known_hosts"
    try:
        pin_known_host(
            settings.pwncollege_ssh_host, settings.pwncollege_ssh_port, known_hosts_path
        )
    except Exception as e:
        logger.warning(
            "pwncollege env: pin_known_host failed (will fall back to TOFU): %s", e
        )
        known_hosts_path = Path("")  # empty -> SSHEnv uses accept-new

    env = PwnCollegeEnv(
        host=settings.pwncollege_ssh_host,
        port=settings.pwncollege_ssh_port,
        user=settings.pwncollege_ssh_user,
        identity_file=str(priv),
        known_hosts_file=str(known_hosts_path) if known_hosts_path else "",
        backend=pwn_backend,
        reset_home_on_switch=settings.pwncollege_reset_home_on_switch,
    )

    # The public key needs to be registered with pwn.college before SSH
    # can land. Defer the actual upload to start() so we don't make HTTP
    # calls in the constructor — but stash the pubkey on the env so
    # start() can find it.
    env._pending_pubkey = pub  # type: ignore[attr-defined]
    return env
