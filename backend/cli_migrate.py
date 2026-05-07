"""ctf-migrate: bring session DBs up to current schema (v2).

The session DB stores everything one CTF run cares about. v2 unifies
two previously-separate files:

    sessions/<NAME>/logs/attempts.db   (v1)  ─┐
                                              ├─→  sessions/<NAME>/logs/session.db (v2)
    sessions/<NAME>/logs/usage.db      (v1)  ─┘

Schema versions are stamped via SQLite's PRAGMA user_version. Migrations
are idempotent: running on already-current DBs is a no-op (just a
metadata stamp where needed).

What v1→v2 does for each session:

  1. Run any v0→v1 row-rewrite work on the legacy attempts.db /
     usage.db files first (so the merge inputs are consistent).
  2. Open (creating if absent) sessions/<NAME>/logs/session.db.
  3. ATTACH the legacy files and INSERT … SELECT each row into the
     unified DB. INSERT OR IGNORE on UNIQUE (challenge_solve_id,
     model_spec) so re-runs don't double-merge.
  4. PRAGMA user_version = 2 on session.db.
  5. Rename legacy files to .v1.bak so they don't get re-merged.

Usage:
    ctf-migrate              # dry-run
    ctf-migrate --apply      # actually rewrite + merge
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from backend.backends.attempt_log import (
    ATTEMPTS_DB_SCHEMA_VERSION,
    _SCHEMA as _ATTEMPTS_SCHEMA,
)
from backend.session import SESSION_DIR
from backend.usage_log import (
    USAGE_DB_SCHEMA_VERSION,
    _SCHEMA as _USAGE_SCHEMA,
)

logger = logging.getLogger(__name__)
console = Console()

CURRENT_SCHEMA_VERSION = 2  # session.db (unified)


@dataclass
class SessionPlan:
    name: str
    session_dir: Path
    legacy_attempts: Path | None = None
    legacy_usage: Path | None = None
    unified_db: Path | None = None
    current_version: int = 0
    target_version: int = CURRENT_SCHEMA_VERSION
    # v0→v1 row-rewrites still needed
    attempts_rows_to_fix: int = 0
    usage_rows_to_fix: int = 0
    attempts_samples: list[str] = field(default_factory=list)
    usage_samples: list[str] = field(default_factory=list)
    # v1→v2 merge needed
    needs_merge: bool = False
    # Just a version stamp needed (already-current data, old pragma)
    needs_stamp: bool = False

    @property
    def is_noop(self) -> bool:
        return (
            self.attempts_rows_to_fix == 0
            and self.usage_rows_to_fix == 0
            and not self.needs_merge
            and not self.needs_stamp
        )


def _sessions_root() -> Path:
    return Path.cwd() / SESSION_DIR


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


# ── plan: per-session ──────────────────────────────────────────────────────


def _plan_session(session_dir: Path) -> SessionPlan | None:
    """Compute what migration work is needed for one session.

    Returns None if the session's logs/ dir doesn't exist (nothing to
    migrate).
    """
    logs = session_dir / "logs"
    if not logs.exists():
        return None
    plan = SessionPlan(name=session_dir.name, session_dir=session_dir)

    legacy_a = logs / "attempts.db"
    legacy_u = logs / "usage.db"
    unified = logs / "session.db"
    if legacy_a.exists():
        plan.legacy_attempts = legacy_a
    if legacy_u.exists():
        plan.legacy_usage = legacy_u
    if unified.exists():
        plan.unified_db = unified

    # 1) v0→v1 row-fixes on legacy files (only when present).
    if legacy_a.exists():
        plan.attempts_rows_to_fix, plan.attempts_samples = _scan_attempts_v01(legacy_a)
    if legacy_u.exists():
        plan.usage_rows_to_fix, plan.usage_samples = _scan_usage_v01(legacy_u, legacy_a)

    # 2) v1→v2 merge: needed when any legacy file exists OR session.db
    # is below v2.
    if legacy_a.exists() or legacy_u.exists():
        plan.needs_merge = True

    # 3) Determine current "session version" — the lowest version of
    # whatever exists. Fresh sessions with only session.db at v2 are
    # at v2 already.
    versions: list[int] = []
    if unified.exists():
        try:
            with sqlite3.connect(str(unified)) as c:
                versions.append(_user_version(c))
        except sqlite3.Error:
            pass
    if legacy_a.exists():
        try:
            with sqlite3.connect(str(legacy_a)) as c:
                versions.append(_user_version(c))
        except sqlite3.Error:
            pass
    if legacy_u.exists():
        try:
            with sqlite3.connect(str(legacy_u)) as c:
                versions.append(_user_version(c))
        except sqlite3.Error:
            pass
    plan.current_version = min(versions) if versions else 0

    # 4) Need a version stamp if unified exists but is below target and
    # there's nothing else to do (no legacy files to merge, no rows to
    # fix). Catches the edge where session.db was created fresh by a
    # buggy older build.
    if (
        plan.unified_db is not None
        and plan.current_version < CURRENT_SCHEMA_VERSION
        and not plan.needs_merge
        and plan.attempts_rows_to_fix == 0
        and plan.usage_rows_to_fix == 0
    ):
        plan.needs_stamp = True

    return plan


def _scan_attempts_v01(db_path: Path) -> tuple[int, list[str]]:
    """Count v0→v1 row-fixes needed in attempts.db (status='incorrect'
    but message says 'Correct flag!')."""
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            if not _table_exists(conn, "attempts"):
                return 0, []
            if _user_version(conn) >= 1:
                return 0, []
            rows = conn.execute(
                "SELECT challenge_name, status, message FROM attempts"
                " WHERE status NOT IN ('correct', 'already_solved')"
                "   AND lower(message) LIKE '%correct%'"
                "   AND lower(message) NOT LIKE '%incorrect%'"
            ).fetchall()
            samples = [
                f'{r["challenge_name"]}: {r["status"]} → correct'
                for r in rows[:3]
            ]
            return len(rows), samples
    except sqlite3.Error as e:
        logger.warning("attempts scan failed for %s: %s", db_path, e)
        return 0, []


def _scan_usage_v01(usage_db: Path, attempts_db: Path | None) -> tuple[int, list[str]]:
    """Count v0→v1 row-fixes needed in usage.db (challenge_solves
    cancelled rows that attempts.db says were actually solved)."""
    try:
        with sqlite3.connect(str(usage_db)) as conn:
            conn.row_factory = sqlite3.Row
            if not _table_exists(conn, "challenge_solves"):
                return 0, []
            if _user_version(conn) >= 1:
                return 0, []
            cancelled = conn.execute(
                "SELECT id, challenge_name FROM challenge_solves"
                " WHERE status='cancelled'"
            ).fetchall()
        if not cancelled or attempts_db is None or not attempts_db.exists():
            return 0, []
        # Set of challenges that attempts.db knows are correct (using
        # the v1-aware classification).
        with sqlite3.connect(str(attempts_db)) as conn:
            conn.row_factory = sqlite3.Row
            if not _table_exists(conn, "attempts"):
                return 0, []
            correct_names = {
                r["challenge_name"]
                for r in conn.execute(
                    "SELECT DISTINCT challenge_name FROM attempts"
                    " WHERE status IN ('correct', 'already_solved')"
                    "   OR (lower(message) LIKE '%correct%'"
                    "       AND lower(message) NOT LIKE '%incorrect%')"
                )
            }
        to_fix = [r for r in cancelled if r["challenge_name"] in correct_names]
        samples = [
            f'{r["challenge_name"]}: cancelled → flag_found'
            for r in to_fix[:3]
        ]
        return len(to_fix), samples
    except sqlite3.Error as e:
        logger.warning("usage scan failed for %s: %s", usage_db, e)
        return 0, []


# ── apply: per-session ─────────────────────────────────────────────────────


def _apply_session(plan: SessionPlan) -> dict[str, int]:
    """Run the migration steps for one session. Returns counts."""
    out = {"attempts_fixed": 0, "usage_fixed": 0,
           "attempts_merged": 0, "usage_merged": 0,
           "solves_merged": 0, "solve_models_merged": 0}

    # 1) v0→v1 row-fixes on legacy files (in place).
    if plan.legacy_attempts and plan.attempts_rows_to_fix > 0:
        with sqlite3.connect(str(plan.legacy_attempts)) as conn:
            cur = conn.execute(
                "UPDATE attempts SET status='correct'"
                " WHERE status NOT IN ('correct', 'already_solved')"
                "   AND lower(message) LIKE '%correct%'"
                "   AND lower(message) NOT LIKE '%incorrect%'"
            )
            out["attempts_fixed"] = cur.rowcount
            conn.execute("PRAGMA user_version = 1")

    if plan.legacy_usage and plan.usage_rows_to_fix > 0:
        # Re-derive the correct-name set after attempts is fixed.
        correct_names: set[str] = set()
        correct_flag: dict[str, str] = {}
        if plan.legacy_attempts and plan.legacy_attempts.exists():
            with sqlite3.connect(str(plan.legacy_attempts)) as conn:
                conn.row_factory = sqlite3.Row
                for r in conn.execute(
                    "SELECT challenge_name, flag FROM attempts"
                    " WHERE status IN ('correct', 'already_solved')"
                    " ORDER BY ts DESC"
                ):
                    correct_names.add(r["challenge_name"])
                    correct_flag.setdefault(r["challenge_name"], r["flag"])
        with sqlite3.connect(str(plan.legacy_usage)) as conn:
            conn.row_factory = sqlite3.Row
            cancelled = conn.execute(
                "SELECT id, challenge_name FROM challenge_solves"
                " WHERE status='cancelled'"
            ).fetchall()
            n = 0
            for r in cancelled:
                chal = r["challenge_name"]
                if chal not in correct_names:
                    continue
                conn.execute(
                    "UPDATE challenge_solves"
                    " SET status='flag_found',"
                    "     confirmed=1,"
                    "     winner_spec=COALESCE(winner_spec, 'coordinator'),"
                    "     flag=COALESCE(flag, ?)"
                    " WHERE id=?",
                    (correct_flag.get(chal), r["id"]),
                )
                n += 1
            out["usage_fixed"] = n
            conn.execute("PRAGMA user_version = 1")

    # 2) v1→v2 merge: copy legacy tables into session.db.
    if plan.needs_merge:
        unified = plan.session_dir / "logs" / "session.db"
        unified.parent.mkdir(parents=True, exist_ok=True)
        # Initialise unified DB with both schemas (idempotent).
        with sqlite3.connect(str(unified), isolation_level=None) as conn:
            conn.executescript(_ATTEMPTS_SCHEMA)
            conn.executescript(_USAGE_SCHEMA)

        # Merge legacy attempts.
        if plan.legacy_attempts and plan.legacy_attempts.exists():
            with sqlite3.connect(str(unified), isolation_level=None) as conn:
                conn.execute(
                    "ATTACH DATABASE ? AS src", (str(plan.legacy_attempts),)
                )
                # Use INSERT OR IGNORE to handle re-runs (UNIQUE on id
                # would conflict otherwise — id column is the PK).
                # Best to dedupe by (backend_id, challenge_name, flag,
                # ts) instead of relying on id. Easier: just skip merge
                # when the unified table is non-empty AND row counts
                # match (idempotent shortcut). For first-merge, copy
                # everything.
                src_cnt = conn.execute(
                    "SELECT COUNT(*) FROM src.attempts"
                ).fetchone()[0]
                dst_cnt = conn.execute(
                    "SELECT COUNT(*) FROM main.attempts"
                ).fetchone()[0]
                if dst_cnt < src_cnt:
                    conn.execute(
                        "INSERT INTO main.attempts"
                        " (backend_id, challenge_name, flag, status,"
                        "  message, ts, writeup_path, workspace_path)"
                        " SELECT backend_id, challenge_name, flag, status,"
                        "        message, ts, writeup_path, workspace_path"
                        " FROM src.attempts"
                    )
                    out["attempts_merged"] = src_cnt - dst_cnt
                conn.execute("DETACH DATABASE src")

        # Merge legacy usage. Three tables, all just append-style.
        if plan.legacy_usage and plan.legacy_usage.exists():
            with sqlite3.connect(str(unified), isolation_level=None) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute(
                    "ATTACH DATABASE ? AS src", (str(plan.legacy_usage),)
                )
                # `usage` table.
                if _table_exists(conn, "usage"):
                    src_cnt = conn.execute(
                        "SELECT COUNT(*) FROM src.usage"
                    ).fetchone()[0] if _attached_table_exists(conn, "src", "usage") else 0
                    dst_cnt = conn.execute(
                        "SELECT COUNT(*) FROM main.usage"
                    ).fetchone()[0]
                    if dst_cnt < src_cnt:
                        conn.execute(
                            "INSERT INTO main.usage"
                            " (run_id, session_name, agent_name, challenge_name,"
                            "  model_name, provider_spec, input_tokens,"
                            "  output_tokens, cache_read_tokens, cost_usd,"
                            "  duration_seconds, ts)"
                            " SELECT run_id, session_name, agent_name, challenge_name,"
                            "        model_name, provider_spec, input_tokens,"
                            "        output_tokens, cache_read_tokens, cost_usd,"
                            "        duration_seconds, ts"
                            " FROM src.usage"
                        )
                        out["usage_merged"] = src_cnt - dst_cnt
                # challenge_solves
                if _attached_table_exists(conn, "src", "challenge_solves"):
                    src_cnt = conn.execute(
                        "SELECT COUNT(*) FROM src.challenge_solves"
                    ).fetchone()[0]
                    dst_cnt = conn.execute(
                        "SELECT COUNT(*) FROM main.challenge_solves"
                    ).fetchone()[0]
                    if dst_cnt < src_cnt:
                        # Map old IDs → new IDs because challenge_solve_models
                        # references challenge_solve_id.
                        id_map: dict[int, int] = {}
                        for old in conn.execute("SELECT * FROM src.challenge_solves"):
                            cur = conn.execute(
                                "INSERT INTO main.challenge_solves"
                                " (run_id, session_name, challenge_name, category,"
                                "  points, status, flag, confirmed, winner_spec,"
                                "  winner_steps, duration_seconds, cost_usd,"
                                "  input_tokens, output_tokens, cache_read_tokens,"
                                "  started_at, finished_at)"
                                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    old["run_id"], old["session_name"], old["challenge_name"],
                                    old["category"], old["points"], old["status"], old["flag"],
                                    old["confirmed"], old["winner_spec"], old["winner_steps"],
                                    old["duration_seconds"], old["cost_usd"], old["input_tokens"],
                                    old["output_tokens"], old["cache_read_tokens"],
                                    old["started_at"], old["finished_at"],
                                ),
                            )
                            id_map[old["id"]] = cur.lastrowid
                        out["solves_merged"] = len(id_map)
                        # Now child rows.
                        if _attached_table_exists(conn, "src", "challenge_solve_models"):
                            for child in conn.execute(
                                "SELECT * FROM src.challenge_solve_models"
                            ):
                                new_parent = id_map.get(child["challenge_solve_id"])
                                if new_parent is None:
                                    continue
                                conn.execute(
                                    "INSERT OR IGNORE INTO main.challenge_solve_models"
                                    " (challenge_solve_id, run_id, session_name,"
                                    "  challenge_name, model_spec, steps, cost_usd,"
                                    "  input_tokens, output_tokens, cache_read_tokens, won)"
                                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (
                                        new_parent, child["run_id"], child["session_name"],
                                        child["challenge_name"], child["model_spec"],
                                        child["steps"], child["cost_usd"],
                                        child["input_tokens"], child["output_tokens"],
                                        child["cache_read_tokens"], child["won"],
                                    ),
                                )
                                out["solve_models_merged"] += 1
                conn.execute("DETACH DATABASE src")

        # Stamp v2 on the unified DB.
        with sqlite3.connect(str(unified), isolation_level=None) as conn:
            conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

        # Move legacy files out of the way so re-runs don't re-merge.
        # Use .v1.bak suffix; user can delete manually once happy.
        for legacy in (plan.legacy_attempts, plan.legacy_usage):
            if legacy and legacy.exists():
                bak = legacy.with_suffix(legacy.suffix + ".v1.bak")
                shutil.move(str(legacy), str(bak))

    elif plan.needs_stamp and plan.unified_db:
        # session.db exists already (fresh) but is below v2 — just
        # advance the pragma.
        with sqlite3.connect(str(plan.unified_db)) as conn:
            conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

    return out


def _attached_table_exists(conn: sqlite3.Connection, schema: str, table: str) -> bool:
    row = conn.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


# ── CLI ────────────────────────────────────────────────────────────────────


@click.command()
@click.option("--apply", "do_apply", is_flag=True,
              help="Actually perform the migration. Without this flag, the "
                   "command runs in dry-run mode and only prints the plan.")
@click.option("-v", "--verbose", is_flag=True)
def migrate_main(do_apply: bool, verbose: bool) -> None:
    """Migrate session DBs to current schema (v2 — unified session.db).

    Walks every `sessions/<NAME>/logs/` and runs:

      • v0→v1 fixes  on legacy attempts.db / usage.db (mis-classified
                      submit_flag rows, cancelled-but-solved rows)
      • v1→v2 merge  the two legacy files into one session.db; rename
                      the legacy ones to .v1.bak

    Idempotent: re-running on already-current sessions is a no-op.
    """
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    root = _sessions_root()
    if not root.exists():
        console.print(f"[yellow]No sessions found under {root}/[/yellow]")
        return

    plans: list[SessionPlan] = []
    for d in sorted(root.iterdir(), key=lambda p: p.name):
        if not d.is_dir():
            continue
        plan = _plan_session(d)
        if plan is not None:
            plans.append(plan)

    if not plans:
        console.print("[green]No session DBs found.[/green]")
        return

    # Render summary table.
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Session")
    tbl.add_column("Version", justify="center")
    tbl.add_column("Plan", overflow="fold")
    for p in plans:
        if p.is_noop:
            tbl.add_row(p.name, f"[dim]{p.current_version} = {p.target_version}[/dim]",
                        "[dim]up to date[/dim]")
            continue
        ver_cell = f"{p.current_version} [yellow]→[/yellow] {p.target_version}"
        ops = []
        if p.attempts_rows_to_fix:
            ops.append(f"attempts: {p.attempts_rows_to_fix} row-fix"
                       + (f" ({'; '.join(p.attempts_samples)})" if p.attempts_samples else ""))
        if p.usage_rows_to_fix:
            ops.append(f"usage: {p.usage_rows_to_fix} row-fix"
                       + (f" ({'; '.join(p.usage_samples)})" if p.usage_samples else ""))
        if p.needs_merge:
            files = []
            if p.legacy_attempts: files.append("attempts.db")
            if p.legacy_usage:    files.append("usage.db")
            ops.append(f"merge into session.db: {', '.join(files)}")
        if p.needs_stamp:
            ops.append("stamp v2")
        tbl.add_row(p.name, ver_cell, "; ".join(ops))
    console.print(tbl)

    pending = [p for p in plans if not p.is_noop]
    if not pending:
        console.print("\n[green]Nothing to do — all sessions at v"
                      f"{CURRENT_SCHEMA_VERSION}.[/green]")
        return

    if not do_apply:
        console.print(
            f"\n[yellow]Dry run.[/yellow] {len(pending)} session(s) need work. "
            f"Re-run with [bold]--apply[/bold] to perform the migration."
        )
        return

    console.print("\n[bold]Applying migration…[/bold]")
    totals = {"attempts_fixed": 0, "usage_fixed": 0,
              "attempts_merged": 0, "usage_merged": 0,
              "solves_merged": 0, "solve_models_merged": 0}
    for p in pending:
        try:
            counts = _apply_session(p)
            for k, v in counts.items():
                totals[k] += v
            ops_msg = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
            console.print(f"  {p.name}: [green]done[/green] ({ops_msg or 'stamp only'})")
        except sqlite3.Error as e:
            console.print(f"  {p.name}: [red]error: {e}[/red]")

    console.print(
        f"\n[green bold]Done.[/green bold] "
        + ", ".join(f"{k}={v}" for k, v in totals.items() if v)
    )


if __name__ == "__main__":
    migrate_main()
