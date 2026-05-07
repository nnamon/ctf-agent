"""Attempt-logging backend decorator.

Wraps any concrete backend, persisting every flag submission to a small
SQLite file. Two operator-facing wins:

  1. The harness automatically refuses to re-submit a flag that's already
     been submitted and rejected — saves wrong-answer penalties.
  2. The prompt builder pulls `previous_attempts(name)` and inlines a
     "ALREADY-REJECTED — do not re-propose" section into each new
     solver run, so the LLM stops re-suggesting things you've already
     burned attempts on.

The decorator is transparent: every other Backend method is forwarded
unchanged to the inner backend.

Schema (SQLite):

    CREATE TABLE attempts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        backend_id      TEXT NOT NULL,
        challenge_name  TEXT NOT NULL,
        flag            TEXT NOT NULL,
        status          TEXT NOT NULL,
        message         TEXT,
        ts              INTEGER NOT NULL
    );
    CREATE INDEX idx_lookup ON attempts(backend_id, challenge_name);

The `backend_id` column scopes attempts to a particular CTF/instance so
multiple events sharing one DB don't cross-contaminate. It's derived
from the inner backend's `base_url` if available, else its class name.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.backends.base import Attempt, Backend, SubmitResult

logger = logging.getLogger(__name__)


_SCHEMA = """
-- Schema v2: this file is the unified per-session DB. Sister tables
-- (usage, challenge_solves, challenge_solve_models) are created by
-- usage_log._connect on its first invocation against the same file.
CREATE TABLE IF NOT EXISTS attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    backend_id      TEXT NOT NULL,
    challenge_name  TEXT NOT NULL,
    flag            TEXT NOT NULL,
    status          TEXT NOT NULL,
    message         TEXT,
    ts              INTEGER NOT NULL,
    writeup_path    TEXT,
    workspace_path  TEXT
);
CREATE INDEX IF NOT EXISTS idx_lookup ON attempts(backend_id, challenge_name);
"""

# Forward-compat: when an existing DB pre-dates the writeup/workspace columns,
# add them in place so older logs keep working without manual migration.
_MIGRATIONS = (
    "ALTER TABLE attempts ADD COLUMN writeup_path TEXT",
    "ALTER TABLE attempts ADD COLUMN workspace_path TEXT",
)

ATTEMPTS_DB_SCHEMA_VERSION = 2


@dataclass
class AttemptLogBackend(Backend):
    """Decorator that logs flag submissions and short-circuits known-incorrect ones."""

    inner: Backend
    db_path: Path
    backend_id: str = ""  # auto-derived in __post_init__ if not set

    def __post_init__(self) -> None:
        self.db_path = Path(self.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.backend_id:
            # Prefer base_url for stable scoping across runs; fall back
            # to the class name for in-memory / no-URL backends.
            base_url = getattr(self.inner, "base_url", "")
            self.backend_id = base_url or type(self.inner).__name__
        self._init_db()

    # ---- DB plumbing ----

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            # Apply forward-compat ALTERs for older DBs. Each may fail with
            # "duplicate column name" if the column already exists — that's
            # the expected no-op path on fresh DBs and on already-migrated DBs.
            for stmt in _MIGRATIONS:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass
            # PRAGMA user_version: schema-version slot.
            #   v1: every row's `status` reflects backend acceptance
            #       (no `incorrect`-but-Correct-flag! mis-classifications
            #        from 3b561ca / b297c90).
            #   v2: this file IS the unified session DB — same physical
            #       file holds challenge_solves + challenge_solve_models
            #       + usage tables (managed by usage_log._connect's own
            #       CREATE TABLE IF NOT EXISTS calls).
            # Stamp the current target on fresh DBs only; older DBs are
            # advanced by `ctf-migrate` after merging stale state.
            cur_ver = conn.execute("PRAGMA user_version").fetchone()[0]
            if cur_ver == 0:
                conn.execute(f"PRAGMA user_version = {ATTEMPTS_DB_SCHEMA_VERSION}")

    def _log(self, name: str, flag: str, result: SubmitResult) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO attempts(backend_id, challenge_name, flag, status, message, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (self.backend_id, name, flag, result.status, result.message, int(time.time())),
            )

    def set_writeup_path(self, name: str, flag: str, path: str) -> None:
        """Attach a writeup path to the most recent successful attempt.

        Called by the postmortem step after the writeup file is generated.
        Matches on (backend_id, challenge_name, flag, status='correct')
        and updates the latest such row.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE attempts SET writeup_path = ? "
                " WHERE id = (SELECT id FROM attempts "
                "             WHERE backend_id = ? AND challenge_name = ? "
                "               AND flag = ? AND status IN ('correct','already_solved') "
                "             ORDER BY ts DESC LIMIT 1)",
                (path, self.backend_id, name, flag),
            )

    def set_workspace_path(self, name: str, flag: str, path: str) -> None:
        """Attach a preserved-workspace path to the most recent successful attempt."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE attempts SET workspace_path = ? "
                " WHERE id = (SELECT id FROM attempts "
                "             WHERE backend_id = ? AND challenge_name = ? "
                "               AND flag = ? AND status IN ('correct','already_solved') "
                "             ORDER BY ts DESC LIMIT 1)",
                (path, self.backend_id, name, flag),
            )

    # ---- public Backend API ----

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        # Short-circuit known-incorrect flags so we don't burn another attempt.
        # Don't short-circuit "unknown" (LocalBackend, network errors) — those
        # weren't real rejections. Don't short-circuit "correct" / "already_solved"
        # because re-submitting those is harmless and might be intentional.
        for prev in self.previous_attempts(challenge_name):
            if prev.flag == flag and prev.status == "incorrect":
                msg = (f"Flag {flag!r} already submitted and rejected at "
                       f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(prev.ts))}; "
                       f"not resubmitting (cached by AttemptLogBackend)")
                logger.info(msg)
                return SubmitResult(
                    status="incorrect",
                    message="duplicate-rejected",
                    display=f"INCORRECT — {flag!r} (cached: previously rejected)",
                )

        result = await self.inner.submit_flag(challenge_name, flag)
        self._log(challenge_name, flag, result)
        return result

    def previous_attempts(self, challenge_name: str) -> list[Attempt]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT challenge_name, flag, status, message, ts FROM attempts"
                " WHERE backend_id = ? AND challenge_name = ?"
                " ORDER BY ts ASC",
                (self.backend_id, challenge_name),
            ).fetchall()
        return [
            Attempt(
                challenge_name=r["challenge_name"],
                flag=r["flag"],
                status=r["status"],
                message=r["message"] or "",
                ts=int(r["ts"]),
            )
            for r in rows
        ]

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

    def instance_lifetime_remaining_s(self, challenge_name: str) -> float | None:
        return self.inner.instance_lifetime_remaining_s(challenge_name)

    async def close(self) -> None:
        await self.inner.close()
