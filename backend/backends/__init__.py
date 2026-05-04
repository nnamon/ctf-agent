"""Pluggable backends for CTF integrations.

Solvers, the coordinator, and the poller all consume the `Backend` ABC
defined in `base.py`. Concrete backends live in their own modules:

  - `ctfd.CTFdBackend`  : standard CTFd HTTP API (token or session auth)
  - `local.LocalBackend`: no-op for offline runs without a real CTF server

To add a new backend, subclass `Backend` and implement the seven methods,
then either pass an instance directly to the swarm/solvers or extend
`make_backend()` so it can be selected via the CLI.
"""

from pathlib import Path

from backend.backends.attempt_log import AttemptLogBackend
from backend.backends.base import Attempt, Backend, SubmitResult
from backend.backends.ctfd import CTFdBackend
from backend.backends.local import LocalBackend


def make_backend(
    *,
    kind: str | None = None,
    base_url: str = "",
    token: str = "",
    username: str = "admin",
    password: str = "admin",
    attempt_log_path: str | Path | None = None,
) -> Backend:
    """Construct a backend by kind, optionally wrapped with attempt-logging.

    `kind` overrides URL-based detection. If unset, falls back to:
      - "local" when base_url is empty / "local" / "none" / "http://unused.invalid"
      - "ctfd"  otherwise

    If `attempt_log_path` is set, the chosen backend is wrapped in an
    AttemptLogBackend that persists every flag submission to that SQLite
    file and short-circuits known-incorrect flags. Pass None to disable.
    """
    if kind is None:
        u = (base_url or "").strip().lower()
        if not u or u in {"local", "none"} or u.startswith("http://unused"):
            kind = "local"
        else:
            kind = "ctfd"

    kind = kind.lower()
    if kind == "ctfd":
        inner: Backend = CTFdBackend(
            base_url=base_url, token=token, username=username, password=password
        )
    elif kind == "local":
        inner = LocalBackend()
    else:
        raise ValueError(f"unknown backend kind: {kind!r}")

    if attempt_log_path is not None:
        return AttemptLogBackend(inner=inner, db_path=Path(attempt_log_path))
    return inner


__all__ = [
    "Attempt", "Backend", "SubmitResult",
    "CTFdBackend", "LocalBackend", "AttemptLogBackend",
    "make_backend",
]
