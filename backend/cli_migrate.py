"""ctf-migrate: bring pre-v1 session DBs up to current schema.

Walks `sessions/*/logs/{attempts,usage}.db` and rewrites stale rows
that pre-date the submit_flag classification fixes (3b561ca for
htb-ctf-mcp, b297c90 for htb-ctf-creds) and the coord-submit-routing
fix (d5e6272). After rewrite, stamps `PRAGMA user_version = 1` so
subsequent runs skip them.

Two correctness fixes:

  1. attempts.db rows that say `status='incorrect'` but the backend
     message reads "Correct flag!" — these were correct submissions
     mis-classified. Status flipped to 'correct'.

  2. usage.db `challenge_solves` rows that say `status='cancelled'`
     for challenges that attempts.db confirms were solved. The swarm
     was auto-killed by the poller after a coord-routed submit, but
     the per-challenge summary persisted as cancelled with no
     winner_spec. Status flipped to 'flag_found' and winner_spec set
     to 'coordinator' (since these only happen on the coord-submit
     path; solver-submit rows have proper winner_spec already).

Defaults to dry-run; pass --apply to actually rewrite. Each DB is
inspected independently — if attempts.db is at v1 already, it's
skipped without touching usage.db.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from backend.backends.attempt_log import ATTEMPTS_DB_SCHEMA_VERSION
from backend.session import SESSION_DIR
from backend.usage_log import USAGE_DB_SCHEMA_VERSION
from backend.usage_log import _connect as _usage_connect  # type: ignore[attr-defined]

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class MigrationDiff:
    db_path: Path
    db_kind: str  # "attempts" | "usage"
    current_version: int
    target_version: int
    rows_changed: int
    samples: list[str]


def _sessions_root() -> Path:
    return Path.cwd() / SESSION_DIR


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _find_dbs() -> list[tuple[Path, str]]:
    """Return [(db_path, 'attempts'|'usage'), …] from every session."""
    out: list[tuple[Path, str]] = []
    root = _sessions_root()
    if not root.exists():
        return out
    for session_dir in sorted(root.iterdir(), key=lambda p: p.name):
        if not session_dir.is_dir():
            continue
        logs = session_dir / "logs"
        if not logs.exists():
            continue
        att = logs / "attempts.db"
        if att.exists():
            out.append((att, "attempts"))
        usg = logs / "usage.db"
        if usg.exists():
            out.append((usg, "usage"))
    return out


def _diff_attempts(db_path: Path) -> MigrationDiff:
    """Pre-v1 → v1: flip mis-classified rows where message says 'Correct flag!'."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cur_ver = _user_version(conn)
        if cur_ver >= ATTEMPTS_DB_SCHEMA_VERSION:
            return MigrationDiff(
                db_path=db_path, db_kind="attempts",
                current_version=cur_ver, target_version=cur_ver,
                rows_changed=0, samples=[],
            )

        rows = conn.execute(
            "SELECT id, challenge_name, flag, status, message FROM attempts"
            " WHERE status NOT IN ('correct', 'already_solved')"
            "   AND lower(message) LIKE '%correct%'"
            "   AND lower(message) NOT LIKE '%incorrect%'"
            " ORDER BY ts ASC"
        ).fetchall()

        samples = [
            f'{r["challenge_name"]}: {r["status"]} → correct  ({r["message"][:40]!r})'
            for r in rows[:5]
        ]
        return MigrationDiff(
            db_path=db_path, db_kind="attempts",
            current_version=cur_ver,
            target_version=ATTEMPTS_DB_SCHEMA_VERSION,
            rows_changed=len(rows), samples=samples,
        )


def _apply_attempts(db_path: Path) -> int:
    """Apply attempts.db migration. Returns number of rows updated."""
    with sqlite3.connect(str(db_path)) as conn:
        cur_ver = _user_version(conn)
        if cur_ver >= ATTEMPTS_DB_SCHEMA_VERSION:
            return 0
        cur = conn.execute(
            "UPDATE attempts SET status='correct'"
            " WHERE status NOT IN ('correct', 'already_solved')"
            "   AND lower(message) LIKE '%correct%'"
            "   AND lower(message) NOT LIKE '%incorrect%'"
        )
        n = cur.rowcount
        conn.execute(f"PRAGMA user_version = {ATTEMPTS_DB_SCHEMA_VERSION}")
        return n


def _attempts_correct_set(db_path: Path) -> dict[str, str]:
    """Return {challenge_name: latest_correct_flag} from a v1 attempts.db.

    Caller has already migrated attempts.db (or it's already at v1) so
    we trust `status='correct'` directly.
    """
    out: dict[str, str] = {}
    if not db_path.exists():
        return out
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            for r in conn.execute(
                "SELECT challenge_name, flag, ts FROM attempts"
                " WHERE status IN ('correct', 'already_solved')"
                " ORDER BY ts DESC"
            ):
                out.setdefault(r["challenge_name"], r["flag"])
    except sqlite3.Error as e:
        logger.warning("attempts.db read failed for %s: %s", db_path, e)
    return out


def _ensure_usage_schema(db_path: Path) -> None:
    """Run usage_log._connect's CREATE TABLE IF NOT EXISTS so older DBs
    that pre-date `challenge_solves` get the table materialised. The
    connect helper also stamps user_version=1 on fresh DBs, but that's
    harmless when we then run migration logic afterward."""
    # _usage_connect handles mkdir + executescript + version stamp on
    # fresh DBs. We only invoke it for its side effects.
    conn = _usage_connect(db_path)
    try:
        conn.close()
    except Exception:
        pass


def _diff_usage(db_path: Path) -> MigrationDiff:
    """Pre-v1 → v1: flip cancelled→flag_found where attempts proves it solved."""
    _ensure_usage_schema(db_path)
    sibling_attempts = db_path.parent / "attempts.db"
    correct = _attempts_correct_set(sibling_attempts)

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cur_ver = _user_version(conn)
        if cur_ver >= USAGE_DB_SCHEMA_VERSION:
            return MigrationDiff(
                db_path=db_path, db_kind="usage",
                current_version=cur_ver, target_version=cur_ver,
                rows_changed=0, samples=[],
            )

        rows = conn.execute(
            "SELECT id, challenge_name, status, flag, winner_spec"
            " FROM challenge_solves"
            " WHERE status='cancelled'"
            " ORDER BY started_at ASC"
        ).fetchall()

        to_fix = [r for r in rows if r["challenge_name"] in correct]
        samples = [
            f'{r["challenge_name"]}: cancelled → flag_found '
            f'(winner_spec={r["winner_spec"] or "—"} → coordinator)'
            for r in to_fix[:5]
        ]
        return MigrationDiff(
            db_path=db_path, db_kind="usage",
            current_version=cur_ver,
            target_version=USAGE_DB_SCHEMA_VERSION,
            rows_changed=len(to_fix), samples=samples,
        )


def _apply_usage(db_path: Path) -> int:
    _ensure_usage_schema(db_path)
    sibling_attempts = db_path.parent / "attempts.db"
    correct = _attempts_correct_set(sibling_attempts)

    n = 0
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cur_ver = _user_version(conn)
        if cur_ver >= USAGE_DB_SCHEMA_VERSION:
            return 0
        rows = conn.execute(
            "SELECT id, challenge_name FROM challenge_solves"
            " WHERE status='cancelled'"
        ).fetchall()
        for r in rows:
            chal = r["challenge_name"]
            if chal not in correct:
                continue
            # Set winner_spec to 'coordinator' only if it's currently
            # NULL — preserve any existing value (e.g. a future case
            # where the solver submitted but somehow ended up cancelled
            # with a populated winner_spec). The flag column gets
            # filled in too if NULL.
            conn.execute(
                "UPDATE challenge_solves"
                " SET status='flag_found',"
                "     confirmed=1,"
                "     winner_spec=COALESCE(winner_spec, 'coordinator'),"
                "     flag=COALESCE(flag, ?)"
                " WHERE id=?",
                (correct.get(chal), r["id"]),
            )
            n += 1
        conn.execute(f"PRAGMA user_version = {USAGE_DB_SCHEMA_VERSION}")
    return n


# ── CLI ────────────────────────────────────────────────────────────────────


@click.command()
@click.option("--apply", "do_apply", is_flag=True,
              help="Actually rewrite rows. Without this flag, the command "
                   "runs in dry-run mode and only prints what would change.")
@click.option("-v", "--verbose", is_flag=True)
def migrate_main(do_apply: bool, verbose: bool) -> None:
    """Migrate session DBs to current schema (v1).

    Walks every `sessions/*/logs/{attempts,usage}.db` and rewrites
    rows that pre-date the submit_flag-classification and
    coord-submit-routing fixes. Stamps `PRAGMA user_version = 1`
    after a successful rewrite so subsequent invocations are no-ops.

    Always do `ctf-migrate` first (dry-run), then `ctf-migrate --apply`
    once you've reviewed the planned changes.
    """
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    dbs = _find_dbs()
    if not dbs:
        console.print(f"[yellow]No session DBs found under {_sessions_root()}/[/yellow]")
        return

    diffs: list[MigrationDiff] = []
    for db_path, kind in dbs:
        try:
            if kind == "attempts":
                diffs.append(_diff_attempts(db_path))
            else:  # usage
                diffs.append(_diff_usage(db_path))
        except sqlite3.Error as e:
            console.print(f"[red]error reading {db_path}: {e}[/red]")

    # Render summary table.
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Session")
    tbl.add_column("DB")
    tbl.add_column("Version", justify="center")
    tbl.add_column("Rows", justify="right")
    tbl.add_column("Notes", overflow="fold")
    for d in diffs:
        sess = d.db_path.parent.parent.name
        if d.rows_changed > 0:
            ver_cell = f"{d.current_version} [yellow]→[/yellow] {d.target_version}"
            rows_cell = f"[yellow]{d.rows_changed}[/yellow]"
            sample_str = "; ".join(d.samples)
        else:
            ver_cell = f"[dim]{d.current_version} = {d.target_version}[/dim]"
            rows_cell = "[dim]0[/dim]"
            sample_str = "[dim]already at v" + str(d.target_version) + "[/dim]"
        tbl.add_row(sess, d.db_kind, ver_cell, rows_cell, sample_str)
    console.print(tbl)

    total_to_fix = sum(d.rows_changed for d in diffs)
    pending_stamp = sum(
        1 for d in diffs if d.current_version < d.target_version
    )

    if total_to_fix == 0 and pending_stamp == 0:
        console.print("[green]Nothing to migrate — all DBs are at current schema.[/green]")
        return

    if not do_apply:
        msg = []
        if total_to_fix:
            msg.append(
                f"{total_to_fix} row(s) across "
                f"{sum(1 for d in diffs if d.rows_changed)} DB(s) would be rewritten"
            )
        if pending_stamp:
            stamp_only = sum(
                1 for d in diffs
                if d.current_version < d.target_version and d.rows_changed == 0
            )
            if stamp_only:
                msg.append(f"{stamp_only} DB(s) only need a version stamp (no row changes)")
        console.print(
            f"\n[yellow]Dry run.[/yellow] {'; '.join(msg)}. "
            f"Re-run with [bold]--apply[/bold] to actually update."
        )
        return

    # Apply phase. Order: attempts first so usage migration sees the
    # post-fix attempts.db state via _attempts_correct_set. Even DBs
    # with rows_changed=0 still need apply called so the user_version
    # pragma gets stamped forward — without that, the next ctf-migrate
    # invocation would re-scan them every time.
    console.print("\n[bold]Applying migration…[/bold]")
    applied_attempts = applied_usage = 0
    stamped = 0
    for d in diffs:
        if d.current_version >= d.target_version:
            continue
        try:
            if d.db_kind == "attempts":
                n = _apply_attempts(d.db_path)
                applied_attempts += n
                if n:
                    console.print(f"  attempts: {d.db_path}  [green]{n} row(s) updated[/green]")
                else:
                    stamped += 1
            elif d.db_kind == "usage":
                n = _apply_usage(d.db_path)
                applied_usage += n
                if n:
                    console.print(f"  usage:    {d.db_path}  [green]{n} row(s) updated[/green]")
                else:
                    stamped += 1
        except sqlite3.Error as e:
            console.print(f"  [red]error on {d.db_path}: {e}[/red]")

    summary = (
        f"\n[green bold]Done.[/green bold] "
        f"attempts: {applied_attempts}  usage: {applied_usage}"
    )
    if stamped:
        summary += f"  ({stamped} DB(s) stamped to v1 with no row changes)"
    console.print(summary)


if __name__ == "__main__":
    migrate_main()
