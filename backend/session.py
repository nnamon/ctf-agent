"""Sessions: per-CTF / per-engagement state isolation.

A session is a directory under `sessions/<NAME>/` that holds everything
specific to one CTF or engagement: pulled challenges, writeups,
attempt log, usage log, preserved workspaces, plus a per-session
`session.yml` overlay for credentials and quotas.

Why: running two CTFs simultaneously, or wanting to compare the cost
of one CTF vs another, or wanting to set a budget cap on a particular
engagement. Without sessions, all state piles up in one shared tree.

Resolution order for the active session name:
  1. explicit `--session NAME` CLI flag
  2. `CTF_SESSION` environment variable
  3. `.ctf-session` dotfile in the current working directory
  4. literal "default"

Layout:
  sessions/<NAME>/
    session.yml      optional config overlay (ctfd_url, quota_usd, ...)
    challenges/      pulled challenge directories
    writeups/        post-mortem writeups (one per solve)
    runs/            preserved workspaces from --preserve-workspace
    logs/
      attempts.db    AttemptLogBackend persistence
      usage.db       token / cost log

Backwards compatibility: when `--session` is omitted and there's no
.ctf-session dotfile, the session resolves to "default" and the
sessions/default/ tree is used. Existing top-level `challenges/`,
`writeups/`, `logs/` directories from pre-sessions installs are
NOT auto-migrated — operators run `ctf-session migrate` to move them.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


SESSION_DIR = "sessions"
SESSION_DOTFILE = ".ctf-session"
SESSION_YAML = "session.yml"


def resolve_session_name(
    explicit: str | None = None,
    cwd: Path | None = None,
) -> str:
    """Resolve the active session name from flag → env → dotfile → default."""
    if explicit:
        return explicit
    env_val = os.environ.get("CTF_SESSION", "").strip()
    if env_val:
        return env_val
    cwd = cwd or Path.cwd()
    dotfile = cwd / SESSION_DOTFILE
    if dotfile.exists():
        try:
            value = dotfile.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
    return "default"


@dataclass
class SessionContext:
    """Filesystem layout + config overlay for one session.

    Construct via `SessionContext.resolve(...)`. The constructor itself
    just packages a name + root path; resolve() does the lookup work.
    """

    name: str
    root: Path

    # Config overlay loaded from session.yml (None if no file).
    config: dict[str, Any] | None = None

    @classmethod
    def resolve(
        cls,
        explicit: str | None = None,
        cwd: Path | None = None,
        repo_root: Path | None = None,
    ) -> SessionContext:
        """Resolve and construct a SessionContext.

        repo_root: where the `sessions/` parent dir lives. Defaults to
        the current working directory, which matches how the rest of
        the codebase resolves relative paths.
        """
        name = resolve_session_name(explicit=explicit, cwd=cwd)
        repo_root = repo_root or Path.cwd()
        root = repo_root / SESSION_DIR / name
        ctx = cls(name=name, root=root)
        ctx._load_overlay()
        return ctx

    def _load_overlay(self) -> None:
        path = self.root / SESSION_YAML
        if not path.exists():
            self.config = None
            return
        try:
            import yaml
            self.config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as e:
            logger.warning("Failed to parse %s: %s", path, e)
            self.config = None

    def ensure_dirs(self) -> None:
        """Create the session's filesystem layout. Safe to call repeatedly."""
        for sub in ("challenges", "writeups", "runs", "logs"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    # ── Path accessors — keep the layout decisions in one place ──

    @property
    def challenges_dir(self) -> Path:
        return self.root / "challenges"

    @property
    def writeups_dir(self) -> Path:
        return self.root / "writeups"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def db_path(self) -> Path:
        """Single SQLite file holding the session's `attempts`, `usage`,
        `challenge_solves`, and `challenge_solve_models` tables (schema
        v2). Older sessions split this across `attempts.db` + `usage.db`
        — see `ctf-migrate` for the v1→v2 unification."""
        return self.root / "logs" / "session.db"

    # Compat: legacy callers and config defaults reference these names.
    # Both now resolve to the unified session.db.
    @property
    def attempt_log_path(self) -> Path:
        return self.db_path

    @property
    def usage_log_path(self) -> Path:
        return self.db_path

    @property
    def session_yml(self) -> Path:
        return self.root / SESSION_YAML

    @property
    def env_file(self) -> Path:
        return self.root / ".env"

    def env_files_chain(self, *, include_global: bool = True) -> tuple[str, ...]:
        """Return the .env file chain to feed to pydantic-settings _env_file.

        Pydantic loads files in order, with later files overriding earlier
        ones. We put the cwd's global .env first (defaults — API keys,
        Bedrock creds, sandbox image name) and the session-local .env
        last so per-CTF overrides win.
        """
        chain: list[str] = []
        if include_global and Path(".env").exists():
            chain.append(".env")
        if self.env_file.exists():
            chain.append(str(self.env_file))
        return tuple(chain)

    # ── Config overlay accessors ──

    def get(self, key: str, default: Any = None) -> Any:
        """Read a value from the session.yml overlay (if any)."""
        if not self.config:
            return default
        return self.config.get(key, default)

    @property
    def quota_usd(self) -> float | None:
        v = self.get("quota_usd")
        return float(v) if v is not None else None

    @property
    def quota_tokens(self) -> int | None:
        v = self.get("quota_tokens")
        return int(v) if v is not None else None
